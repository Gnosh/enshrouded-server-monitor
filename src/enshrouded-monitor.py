#!/usr/bin/env python3
import html, math, subprocess, os, sys, json, re, urllib.request, xml.etree.ElementTree as ET
from datetime import datetime, timezone

# ── Configuration ─────────────────────────────────────────────────────────────
# All settings come from a TOML config file found outside the repo; see
# config.example.toml and enshrouded_monitor_config.py for the lookup order.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import enshrouded_monitor_config as _cfgmod  # noqa: E402

_CFG        = _cfgmod.load_config()
CONTAINER   = _CFG["general"]["container"]
DATA_DIR    = _CFG["general"]["data_dir"]
SERVER_NAME = html.escape(str(_CFG["general"]["server_name"]))
STEAM_NAMES_FILE = _CFG["general"]["steam_names_file"]
PLAYER_DISPLAY = _CFG["general"]["player_display"]   # "anonymous" | "names"
STEAM_LOOKUP = _CFG["general"]["steam_lookup"]  # opt-in network lookup of public Steam names
STEAM_CACHE_FILE = _CFG["general"]["steam_cache_file"] or os.path.join(_CFG["general"]["data_dir"], "steam_names.json")
STEAM_LOOKUP_BUDGET = 3   # max new profile fetches per run (each has a 5s timeout)
CPU_CORES   = _CFG["general"]["cpu_cores"]
STALE_AFTER_S = _CFG["general"]["stale_after_seconds"]
MAX_CSV_ROWS = _CFG["general"]["max_csv_rows"]
REBOOT_MARKER_TIME  = _CFG["general"]["reboot_marker_time"]   # "" = no marker, else "HH:MM"
REBOOT_MARKER_LABEL = str(_CFG["general"]["reboot_marker_label"])
# ──────────────────────────────────────────────────────────────────────────────
CSV_FILE   = os.path.join(DATA_DIR, "metrics.csv")
HTML_FILE  = os.path.join(DATA_DIR, "index.html")
LIVE_FILE  = os.path.join(DATA_DIR, "live.json")
CSV_HEADER = "timestamp,cpu_pct,mem_mb,players,bad_perf_count,entity_count,avg_tick_ms,save_kb,water_kb\n"

def run(*cmd, timeout=10):
    # A hard timeout here is load-bearing: if `docker` ever hangs again (e.g.
    # the daemon is wedged or unreachable), we must still finish this cycle
    # and report the server as offline — not freeze and leave the last good
    # reading on screen looking live forever. Treat a timeout as "no output",
    # which downstream state checks (`state == "true"`) naturally read as down.
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return ""
    except OSError:     # docker binary missing / not executable
        return ""


def _load_steam_overrides():
    """Optional user-maintained {steamid: display name} file (outside the repo)."""
    if STEAM_NAMES_FILE:
        try:
            with open(STEAM_NAMES_FILE) as f:
                d = json.load(f)
            return {str(k): str(v) for k, v in d.items()}
        except Exception:
            pass
    return {}

def _load_steam_cache():
    try:
        with open(STEAM_CACHE_FILE) as f:
            d = json.load(f)
        return {str(k): str(v) for k, v in d.items()}
    except Exception:
        return {}

def _save_steam_cache(cache):
    try:
        # private: the cache maps Steam IDs to names (0600, atomic, no symlinks)
        _cfgmod.atomic_write(STEAM_CACHE_FILE, json.dumps(cache), mode=0o600)
    except Exception:
        pass

def _fetch_steam_name(steam_id):
    """Fetch the public Steam display name from the profile XML (5s timeout).
    Returns None on any failure; never raises."""
    try:
        url = f"https://steamcommunity.com/profiles/{steam_id}/?xml=1"
        req = urllib.request.Request(url, headers={"User-Agent": "enshrouded-monitor/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            xml_data = r.read(1_000_000)
        return ET.fromstring(xml_data).findtext("steamID")
    except Exception:
        return None

def resolve_names(steam_ids, mode=None, lookup=None):
    """{steamid: name} for the given IDs. Only in "names" mode: overrides file
    first, then (only if steam_lookup is on) cached/fetched Steam names."""
    mode   = PLAYER_DISPLAY if mode is None else mode
    lookup = STEAM_LOOKUP if lookup is None else lookup
    if mode != "names":
        return {}
    names = _load_steam_overrides()
    if lookup:
        cache, fetched, budget = _load_steam_cache(), False, STEAM_LOOKUP_BUDGET
        for sid in sorted(set(steam_ids)):
            if sid in names:
                continue
            if sid not in cache and budget > 0:
                budget -= 1
                n = _fetch_steam_name(sid)
                if n:
                    cache[sid], fetched = n, True
            if sid in cache:
                names[sid] = cache[sid]
        if fetched:
            _save_steam_cache(cache)
    return names

def build_player_entries(slot_pings, steam_map, mode=None, names=None):
    """Public player list: {"ping", "name"} only - Steam IDs never leave this
    function. anonymous mode: "Player 1..N" in slot order. names mode: the
    name from the external mapping file, else the generic label."""
    mode  = PLAYER_DISPLAY if mode is None else mode
    names = resolve_names(steam_map.values(), mode) if names is None else names
    out = []
    for i, slot in enumerate(sorted(slot_pings), 1):
        name = names.get(steam_map.get(slot)) if mode == "names" else None
        out.append({"ping": slot_pings[slot], "name": name or f"Player {i}"})
    return out

def collect():
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    state = run("docker", "inspect", "-f", "{{.State.Running}}", CONTAINER)
    # "online" | "offline" | "unknown" (docker hung / gave no usable answer)
    online = _cfgmod.classify_status(state)
    if online != "online":
        return ts, 0, 0, 0, 0, 0, 0.0, 0, 0, [], online

    # CPU + memory (single call)
    stats = run("docker", "stats", CONTAINER, "--no-stream",
                "--format", "{{.CPUPerc}}\t{{.MemUsage}}").strip().split("\t")
    cpu_pct, mem_mb = 0.0, 0
    if len(stats) >= 2:
        try:
            cpu_val = float(stats[0].strip("%"))
            mem_str = stats[1].split("/")[0].strip()
            mem_val = 0
            if "GiB" in mem_str:
                mem_val = int(float(mem_str.replace("GiB","")) * 1024)
            elif "MiB" in mem_str:
                mem_val = int(float(mem_str.replace("MiB","")))
            if math.isfinite(cpu_val) and cpu_val >= 0:
                cpu_pct, mem_mb = cpu_val, mem_val
        except (ValueError, OverflowError):
            pass

    # Main fetch: 6m window for players/bad-perf/save/water
    logs = run("docker", "logs", "--since", "6m", "--tail", "2000", CONTAINER)
    lines = logs.splitlines()
    rev   = list(reversed(lines))

    # Separate fetch for ecss stats: appears once/min but Session lines (~2/min)
    # flood the tail buffer, so reach back 3m with a small tail targeting only ecss
    ecss_logs = run("docker", "logs", "--since", "3m", "--tail", "200", CONTAINER)
    ecss_rev  = list(reversed(ecss_logs.splitlines()))

    # Player count + pings from last session block
    # Capture all connected players (any state) keyed by slot number
    slot_pings = {}  # slot (int) → ping (int)
    for line in rev:
        if "Session ----" in line:
            break
        m_slot = re.search(r'  m#(\d+)\(', line)
        if m_slot:
            slot = int(m_slot.group(1))
            m_ping = re.search(r'ping (\d+) ms', line)
            if m_ping and int(m_ping.group(1)) > 0:
                slot_pings[slot] = int(m_ping.group(1))
    players = len(slot_pings)

    # Map m#-slot → Steam ID.
    #
    # "Added peer N(...)" uses its OWN peer-connection index — a different
    # numbering scheme from the m#N session-ping slots above, not the same
    # integer space. Matching them directly (the old approach) silently
    # dropped any player whose peer-index happened to be 0, since m#0 is
    # always the reserved baseline slot and is filtered out of slot_pings
    # above — so peer-index 0 could never be "in slot_pings" no matter who
    # actually held it.
    #
    # Instead: correlate by connection recency. Slot numbers are assigned
    # in join order, so pair the currently active m#-slots (ascending) with
    # the most-recently-touched distinct peer identities (also ascending
    # by their last-touched time, oldest of the recent set first) — this
    # includes peer-index 0 as a normal candidate and doesn't depend on the
    # two numbering schemes coincidentally lining up.
    steam_map = {}
    if slot_pings:
        peer_logs = run("docker", "logs", "--tail", "20000", CONTAINER)
        peer_latest = {}   # peer_index -> (last_touched_timestamp_str, steamid)
        for line in peer_logs.splitlines():
            m = re.search(r'^\[I (\S+),\d+\].*Added peer (\d+)\(\d+\) \(steamid:(\d+)\)', line)
            if m:
                peer_ts, peer_idx, steamid = m.group(1), int(m.group(2)), m.group(3)
                peer_latest[peer_idx] = (peer_ts, steamid)   # later lines overwrite -> most recent wins

        active_slots = sorted(slot_pings)
        recent = sorted(peer_latest.values())[-len(active_slots):]   # oldest-of-recent first
        for slot, (_ts, steamid) in zip(active_slots, recent):
            steam_map[slot] = steamid

    pings = build_player_entries(slot_pings, steam_map)

    # Bad perf events (all lines already time-bounded by --since 6m)
    bad_perf = sum(1 for l in lines if "Bad Performance" in l)

    # ecss stats — entity count + avg tick; use dedicated ecss fetch to avoid
    # being crowded out by Session lines in the main tail buffer
    entity_count, avg_tick_ms = 0, 0.0
    for line in ecss_rev:
        if 'Ent:' in line and '[ecss]' in line:
            m = re.search(r'Ent:(\d+(?:,\d{3})*)(?![\d,])', line)
            if m:
                entity_count = int(m.group(1).replace(",",""))
            m2 = re.search(r'Avg:(\d+(?:\.\d+)?)ms', line)
            if m2:
                avg_tick_ms = float(m2.group(1))
            break

    # World save size (most recent)
    save_kb = 0
    for line in rev:
        m = re.search(r'\[savexxx\] SAVE.*size (\d+(?:,\d{3})*)(?![\d,])', line)
        if m:
            save_kb = int(m.group(1).replace(",","")) // 1024
            break

    # Water save size (most recent)
    water_kb = 0
    for line in rev:
        m = re.search(r'WaterSaveSize: (\d+(?:,\d{3})*)(?![\d,])', line)
        if m:
            water_kb = int(m.group(1).replace(",","")) // 1024
            break

    return ts, round(cpu_pct,1), mem_mb, players, bad_perf, entity_count, round(avg_tick_ms,1), save_kb, water_kb, pings, online

def append_csv(row):
    write_header = not os.path.exists(CSV_FILE)
    text = (CSV_HEADER if write_header else "") + ",".join(str(x) for x in row[:9]) + "\n"
    _cfgmod.safe_append(CSV_FILE, text, mode=0o640)

def trim_csv(max_rows=None):
    """Keep only the newest `max_rows` data rows (header preserved)."""
    max_rows = MAX_CSV_ROWS if max_rows is None else max_rows
    try:
        with open(CSV_FILE) as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return
    if len(lines) - 1 <= max_rows:
        return
    keep = [CSV_HEADER.rstrip("\n")] + lines[-max_rows:]
    _cfgmod.atomic_write(CSV_FILE, "\n".join(keep) + "\n", mode=0o640)

_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

def _valid_ts(t):
    if not _TS_RE.fullmatch(t):
        return False
    try:
        datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True

def _finite(x):
    x = float(x)
    if not math.isfinite(x):
        raise ValueError("non-finite number")
    return x

def read_csv():
    if not os.path.exists(CSV_FILE):
        return []
    rows = []
    with open(CSV_FILE) as f:
        for i, line in enumerate(f):
            if i == 0:
                continue
            p = line.strip().split(",")
            if len(p) < 5:
                continue
            if not _valid_ts(p[0]):
                continue
            try:
                rows.append({
                    "t":        p[0],
                    "cpu":      _finite(p[1]),
                    "mem":      int(_finite(p[2])),
                    "players":  int(p[3]),
                    "bad_perf": int(p[4]),
                    "entities": int(p[5]) if len(p) > 5 else 0,
                    "tick":     _finite(p[6]) if len(p) > 6 else 0,
                    "save_kb":  int(p[7]) if len(p) > 7 else 0,
                    "water_kb": int(p[8]) if len(p) > 8 else 0,
                })
            except (ValueError, OverflowError):
                pass
    return rows

def _js_json(obj):
    """JSON for embedding inside a <script> block: no raw <, >, & or
    U+2028/2029, so nothing can close the script tag or break out of it."""
    return (json.dumps(obj).replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def generate_html(rows, live, now=None):
    data_json = _js_json(rows)   # never raw json.dumps inside <script>
    reboot_json = _js_json({"time": REBOOT_MARKER_TIME or "", "label": REBOOT_MARKER_LABEL})
    now        = datetime.now() if now is None else now
    updated    = now.strftime("%Y-%m-%d %H:%M:%S")
    status     = live.get("status") or ("online" if live.get("online") else "offline")
    if status not in ("online", "offline", "unknown", "stale"):
        status = "unknown"   # status is embedded in markup and script
    # Embed an epoch-ms timestamp alongside the display string so the page
    # itself (client-side, against the viewer's own clock) can tell whether
    # it's looking at a fresh read or a frozen one — the generator process
    # can't vouch for its own future staleness if it ever stops running.
    updated_epoch_ms = int(now.timestamp() * 1000)
    cpu       = live.get("cpu", 0)
    mem       = live.get("mem", 0)
    players   = live.get("players", 0)
    bad_perf  = live.get("bad_perf", 0)
    entities  = live.get("entity_count", 0)
    avg_tick  = live.get("avg_tick_ms", 0)
    save_kb   = live.get("save_size_kb", 0)
    water_kb  = live.get("water_size_kb", 0)
    pings     = live.get("pings", [])

    cores_str = f"{cpu/100:.2f}"
    save_str  = f"{save_kb/1024:.1f} MB" if save_kb > 1024 else f"{save_kb} KB"
    water_str = f"{water_kb/1024:.1f} MB" if water_kb > 1024 else f"{water_kb} KB"
    tick_color = "#4ade80" if avg_tick < 10 else "#facc15" if avg_tick < 20 else "#f87171"
    # Old formats (bare ints / entries carrying steam_id) are normalised;
    # identities are never rendered from here, only the (already public) name.
    pings = [{"ping": p, "name": None} if isinstance(p, int) else p for p in pings]
    if pings:
        _rows = []
        for p in pings:
            pval = p["ping"]
            pcol = '#4ade80' if pval < 60 else '#facc15' if pval < 120 else '#f87171'
            pspan = f"<span style='color:{pcol}'>{pval}ms</span>"
            label = html.escape(str(p.get("name") or f"Player {len(_rows) + 1}"))
            name_html = f"<span style='color:var(--text)'>{label}</span>"
            _rows.append(
                f"<div style='display:flex;justify-content:space-between;"
                f"align-items:center;padding:3px 0'>{name_html}{pspan}</div>"
            )
        ping_html = "".join(_rows)
    else:
        ping_html = "<span style='color:var(--muted)'>no players</span>"

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="300">
<title>Enshrouded Monitor — """ + SERVER_NAME + """</title>
<style>
  :root{--bg:#f5f5f5;--card:#fff;--border:#e0e0e0;--text:#1a1a1a;--muted:#666;--cpu-color:#e05c00;--player-color:#2563eb;--save-color:#a855f7;--water-color:#06b6d4;--tick-color:#d97706;--entity-color:#16a34a;}
  @media(prefers-color-scheme:dark){:root{--bg:#111;--card:#1e1e1e;--border:#333;--text:#f0f0f0;--muted:#999;--cpu-color:#f97316;--player-color:#60a5fa;--save-color:#c084fc;--water-color:#22d3ee;--tick-color:#fbbf24;--entity-color:#4ade80;}}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;padding:20px}
  h1{font-size:1.1rem;font-weight:600;margin-bottom:4px}
  .sub{font-size:.8rem;color:var(--muted);margin-bottom:16px}
  .stats{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:16px}
  .stat{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
  .stat-label{font-size:.65rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:4px}
  .stat-value{font-size:1.5rem;font-weight:700}
  .stat-value.small{font-size:1.1rem}
  .cpu{color:var(--cpu-color)}.players{color:var(--player-color)}
  .wide{grid-column:1/-1}
  .ping-row{font-size:.9rem;padding:10px 14px}
  .chart-wrap{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px}
  .chart-title{font-size:.75rem;color:var(--muted);margin-bottom:10px}
  canvas{width:100%;display:block}
  .legend{display:flex;gap:16px;margin-top:10px;font-size:.75rem;color:var(--muted);flex-wrap:wrap}
  .legend span{display:flex;align-items:center;gap:6px}
  .dot{width:10px;height:10px;border-radius:50%;display:inline-block}
  .topbar{display:flex;align-items:baseline;gap:12px;margin-bottom:16px;flex-wrap:wrap}
  .topbar .sub{margin-bottom:0}
  select{background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 8px;font-size:.8rem;cursor:pointer}
  #statusBadge{display:inline-block;font-size:.75rem;font-weight:700;letter-spacing:.05em;border-radius:6px;padding:3px 10px;margin-bottom:10px;background:#16a34a;color:#fff}
  #statusBadge.offline{background:#dc2626}#statusBadge.unknown,#statusBadge.stale{background:#d97706}
  #staleBanner{display:none;background:#f87171;color:#1a1a1a;font-weight:600;font-size:.85rem;border-radius:8px;padding:10px 14px;margin-bottom:12px}
</style>
</head>
<body>
<h1>Enshrouded Monitor — """ + SERVER_NAME + """</h1>
<div><span id="statusBadge" class='""" + status + """'>""" + status.upper() + """</span></div>
<div id="staleBanner"></div>
<div class="topbar">
  <p class="sub">Updated """ + updated + """ &nbsp;·&nbsp; auto-refreshes every 5 min</p>
  <select id="range">
    <option value="72">Last 6 hours</option>
    <option value="288" selected>Last 24 hours</option>
    <option value="864">Last 3 days</option>
    <option value="2016">Last 7 days</option>
    <option value="0">All data</option>
  </select>
</div>
<div class="stats">
  <div class="stat">
    <div class="stat-label">Cores</div>
    <div class="stat-value cpu">""" + cores_str + """<span style="font-size:1rem;font-weight:400;color:var(--muted)">""" + (f"/{CPU_CORES}" if CPU_CORES else "") + """</span></div>
  </div>
  <div class="stat">
    <div class="stat-label">Memory</div>
    <div class="stat-value">""" + str(mem) + """ <span style="font-size:1rem;font-weight:400;color:var(--muted)">MB</span></div>
  </div>
  <div class="stat">
    <div class="stat-label">Players</div>
    <div class="stat-value players">""" + str(players) + """</div>
  </div>
  <div class="stat">
    <div class="stat-label">Bad Perf (5m)</div>
    <div class="stat-value">""" + str(bad_perf) + """</div>
  </div>
  <div class="stat">
    <div class="stat-label">Entities</div>
    <div class="stat-value small">""" + f"{entities:,}" + """</div>
  </div>
  <div class="stat">
    <div class="stat-label">Avg Tick</div>
    <div class="stat-value small" style="color:""" + tick_color + """">""" + str(avg_tick) + """ <span style="font-size:.9rem;font-weight:400;color:var(--muted)">ms</span></div>
  </div>
  <div class="stat">
    <div class="stat-label">World Save</div>
    <div class="stat-value small">""" + save_str + """</div>
  </div>
  <div class="stat">
    <div class="stat-label">Water Size</div>
    <div class="stat-value small">""" + water_str + """</div>
  </div>
  <div class="stat wide ping-row">
    <div class="stat-label">Player Pings</div>
    <div style="margin-top:6px">""" + ping_html + """</div>
  </div>
</div>

<div class="chart-wrap">
  <div class="chart-title">Last 24 hours — cores used and player count</div>
  <canvas id="chart1" height="280"></canvas>
  <div class="legend">
    <span><span class="dot" style="background:var(--cpu-color)"></span>Cores used</span>
    <span><span class="dot" style="background:var(--player-color)"></span>Players</span>
    <span><span class="dot" style="background:rgba(239,68,68,0.8)"></span>Bad perf</span>
  </div>
</div>

<div class="chart-wrap">
  <div class="chart-title">Last 24 hours — world size, entities, and tick time</div>
  <canvas id="chart2" height="220"></canvas>
  <div class="legend">
    <span><span class="dot" style="background:var(--save-color)"></span>World save (KB)</span>
    <span><span class="dot" style="background:var(--water-color)"></span>Water (KB)</span>
    <span><span class="dot" style="background:var(--entity-color)"></span>Entities (K, right)</span>
    <span><span class="dot" style="background:var(--tick-color)"></span>Avg tick (ms, right)</span>
  </div>
</div>

<script>
const raw=""" + data_json + """;
const REBOOT=""" + reboot_json + """;

// Status check, done client-side against the viewer's own clock: this page
// is a static file, so if the generator stops running nothing else would
// ever change it. Recorded status is only trusted while the data is fresh.
(function(){
  const updatedMs = """ + str(updated_epoch_ms) + """;
  const staleAfterMin = """ + str(STALE_AFTER_S / 60) + """;
  const recorded = '""" + status + """';
  const ageMin = (Date.now() - updatedMs) / 60000;
  const badge = document.getElementById('statusBadge');
  const b = document.getElementById('staleBanner');
  function show(cls, text){ badge.className = cls; badge.textContent = cls.toUpperCase();
    if (text) { b.style.display = 'block'; b.textContent = text; } }
  if (ageMin > staleAfterMin) {
    show('stale', `\u26a0 Data is ${ageMin.toFixed(0)} minutes old \u2014 the monitor may be stuck or the server may be down. This page cannot currently confirm real status.`);
  } else if (recorded === 'offline') {
    show('offline', 'Server is OFFLINE (container is not running).');
  } else if (recorded === 'unknown') {
    show('unknown', 'Server status UNKNOWN (could not query Docker). Numbers below are not live.');
  }
})();

function fmtLabel(t,multiDay){
  const time=t.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',hour12:false});
  if(!multiDay)return time;
  return `${t.getMonth()+1}/${t.getDate()} ${time}`;
}

function redraw(){
  const n=parseInt(document.getElementById('range').value);
  const data=n>0?raw.slice(-n):raw;
  drawChart1(data);
  drawChart2(data);
}

function drawChart1(data){
  const canvas=document.getElementById('chart1');
  const dpr=window.devicePixelRatio||1;
  const W=canvas.parentElement.clientWidth-32,H=280;
  canvas.width=W*dpr;canvas.height=H*dpr;
  canvas.style.width=W+'px';canvas.style.height=H+'px';
  const ctx=canvas.getContext('2d');ctx.scale(dpr,dpr);
  const PAD={top:10,right:50,bottom:60,left:55};
  const W2=W-PAD.left-PAD.right,H2=H-PAD.top-PAD.bottom;
  const cs=getComputedStyle(document.documentElement);
  const cpuColor=cs.getPropertyValue('--cpu-color').trim();
  const playerColor=cs.getPropertyValue('--player-color').trim();
  const mutedColor=cs.getPropertyValue('--muted').trim();
  const borderColor=cs.getPropertyValue('--border').trim();
  const BAD_H=36;
  if(data.length<2){
    ctx.fillStyle=mutedColor;ctx.font='12px system-ui';ctx.textAlign='center';
    ctx.fillText('Collecting data...',W/2,H/2);
    return;
  }
  const maxOf=(a,m)=>a.reduce((x,v)=>v>x?v:x,m);
  const maxCores=Math.ceil(maxOf(data.map(d=>d.cpu/100),0)/2)*2||2;
  const maxPlayers=maxOf(data.map(d=>d.players),1);
  const maxBadPerf=maxOf(data.map(d=>d.bad_perf),1);
  const xPos=i=>PAD.left+(i/(data.length-1))*W2;
  const yC=v=>PAD.top+(H2-BAD_H)-(v/100/maxCores)*(H2-BAD_H);
  const yP=v=>PAD.top+(H2-BAD_H)-(v/maxPlayers)*(H2-BAD_H);

  ctx.font='11px system-ui';
  [0,2,4,6,8,10,12].filter(c=>c<=maxCores+1).forEach(c=>{
    const y=yC(c*100);
    ctx.strokeStyle=borderColor;ctx.lineWidth=1;
    ctx.beginPath();ctx.moveTo(PAD.left,y);ctx.lineTo(PAD.left+W2,y);
    ctx.globalAlpha=.3;ctx.stroke();ctx.globalAlpha=1;
    ctx.fillStyle=mutedColor;ctx.textAlign='right';ctx.fillText(c,PAD.left-6,y+4);
  });
  ctx.save();ctx.translate(14,PAD.top+(H2-BAD_H)/2);ctx.rotate(-Math.PI/2);
  ctx.textAlign='center';ctx.fillStyle=mutedColor;ctx.font='11px system-ui';
  ctx.fillText('cores',0,0);ctx.restore();

  ctx.fillStyle=playerColor;ctx.textAlign='left';ctx.font='11px system-ui';
  for(let v=0;v<=maxPlayers;v++){ctx.fillText(v,PAD.left+W2+6,yP(v)+4);}

  // X labels
  ctx.fillStyle=mutedColor;ctx.textAlign='right';ctx.font='11px system-ui';
  const multiDay1=data.length>1&&new Date(data[0].t).toDateString()!==new Date(data[data.length-1].t).toDateString();
  const lc=Math.min(6,data.length);
  for(let i=0;i<lc;i++){
    const idx=Math.round(i*(data.length-1)/(lc-1));
    const t=new Date(data[idx].t);
    ctx.save();ctx.translate(xPos(idx),PAD.top+H2-BAD_H+12);ctx.rotate(-Math.PI/4);
    ctx.fillText(fmtLabel(t,multiDay1),0,0);ctx.restore();
  }

  // Healthy idle
  const hy=yC(45);
  ctx.save();ctx.setLineDash([4,4]);ctx.strokeStyle=playerColor;ctx.lineWidth=1;ctx.globalAlpha=0.4;
  ctx.beginPath();ctx.moveTo(PAD.left,hy);ctx.lineTo(PAD.left+W2,hy);ctx.stroke();
  ctx.globalAlpha=1;ctx.setLineDash([]);
  ctx.font='10px system-ui';ctx.fillStyle=playerColor;ctx.textAlign='left';
  ctx.fillText('healthy idle',PAD.left+4,hy-4);ctx.restore();

  // Configurable reboot marker (browser-local time, off when REBOOT.time is empty)
  if(REBOOT.time){
  const rm=/^(\\d{2}):(\\d{2})$/.exec(REBOOT.time),rebootMins=+rm[1]*60+ +rm[2];
  const rebootText=REBOOT.time+(REBOOT.label?' '+REBOOT.label:'');
  ctx.save();ctx.setLineDash([6,3]);ctx.strokeStyle=mutedColor;ctx.lineWidth=1.5;ctx.globalAlpha=0.6;
  ctx.font='10px system-ui';ctx.fillStyle=mutedColor;ctx.textAlign='center';
  for(let i=1;i<data.length;i++){
    const t=new Date(data[i].t),prev=new Date(data[i-1].t);
    // full date/time comparison so a marker at 00:00 (or across a gap) works
    let crossed=false;
    for(const base of [prev,t]){
      const R=new Date(base.getFullYear(),base.getMonth(),base.getDate(),Math.floor(rebootMins/60),rebootMins%60);
      if(prev<R&&R<=t)crossed=true;
    }
    if(crossed){
      const x=xPos(i);
      ctx.beginPath();ctx.moveTo(x,PAD.top);ctx.lineTo(x,PAD.top+H2-BAD_H);ctx.stroke();
      ctx.globalAlpha=1;ctx.fillText(rebootText,x,PAD.top+14);ctx.globalAlpha=0.6;
    }
  }
  ctx.restore();
  }

  // CPU area + line
  ctx.beginPath();
  data.forEach((d,i)=>{const x=xPos(i),y=yC(d.cpu);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});
  ctx.lineTo(xPos(data.length-1),PAD.top+H2-BAD_H);
  ctx.lineTo(xPos(0),PAD.top+H2-BAD_H);
  ctx.closePath();ctx.fillStyle=cpuColor;ctx.globalAlpha=.15;ctx.fill();ctx.globalAlpha=1;
  ctx.beginPath();
  data.forEach((d,i)=>{const x=xPos(i),y=yC(d.cpu);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});
  ctx.strokeStyle=cpuColor;ctx.lineWidth=2;ctx.lineJoin='round';ctx.stroke();

  // Player step line + dots
  ctx.beginPath();
  data.forEach((d,i)=>{
    const x=xPos(i),y=yP(d.players);
    if(i===0){ctx.moveTo(x,y);return;}
    ctx.lineTo(x,yP(data[i-1].players));ctx.lineTo(x,y);
  });
  ctx.strokeStyle=playerColor;ctx.lineWidth=2;ctx.stroke();
  data.forEach((d,i)=>{
    if(d.players>0){ctx.beginPath();ctx.arc(xPos(i),yP(d.players),3,0,Math.PI*2);ctx.fillStyle=playerColor;ctx.fill();}
  });

  // Bad perf bars
  const barTop=PAD.top+H2-BAD_H+4,barMaxH=BAD_H-8,barW=Math.max(2,W2/data.length-1);
  data.forEach((d,i)=>{
    if(d.bad_perf>0){
      const bh=Math.max(2,(d.bad_perf/Math.max(maxBadPerf,13))*barMaxH);
      ctx.fillStyle='rgba(239,68,68,0.8)';
      ctx.fillRect(xPos(i)-barW/2,barTop+barMaxH-bh,barW,bh);
    }
  });
  ctx.strokeStyle=borderColor;ctx.lineWidth=1;ctx.globalAlpha=0.4;
  ctx.beginPath();ctx.moveTo(PAD.left,PAD.top+H2-BAD_H);ctx.lineTo(PAD.left+W2,PAD.top+H2-BAD_H);ctx.stroke();
  ctx.globalAlpha=1;ctx.fillStyle=mutedColor;ctx.font='9px system-ui';ctx.textAlign='right';
  ctx.fillText('bad perf',PAD.left-3,barTop+barMaxH/2+4);

  ctx.beginPath();
  ctx.moveTo(PAD.left,PAD.top);ctx.lineTo(PAD.left,PAD.top+H2);ctx.lineTo(PAD.left+W2,PAD.top+H2);
  ctx.strokeStyle=borderColor;ctx.lineWidth=1;ctx.globalAlpha=1;ctx.stroke();
}

function drawChart2(data){
  const canvas=document.getElementById('chart2');
  const dpr=window.devicePixelRatio||1;
  const W=canvas.parentElement.clientWidth-32,H=220;
  canvas.width=W*dpr;canvas.height=H*dpr;
  canvas.style.width=W+'px';canvas.style.height=H+'px';
  const ctx=canvas.getContext('2d');ctx.scale(dpr,dpr);
  // right pad = 100: first 45px for entity K labels, next 45px for tick ms labels
  const PAD={top:10,right:100,bottom:60,left:65};
  const W2=W-PAD.left-PAD.right,H2=H-PAD.top-PAD.bottom;
  const cs=getComputedStyle(document.documentElement);
  const saveColor=cs.getPropertyValue('--save-color').trim();
  const waterColor=cs.getPropertyValue('--water-color').trim();
  const tickColor=cs.getPropertyValue('--tick-color').trim();
  const entityColor=cs.getPropertyValue('--entity-color').trim();
  const mutedColor=cs.getPropertyValue('--muted').trim();
  const borderColor=cs.getPropertyValue('--border').trim();

  // Only include rows where we have save/water/tick/entity data
  const valid=data.filter(d=>d.save_kb>0||d.tick>0||d.entities>0);
  if(valid.length<2){
    ctx.fillStyle=mutedColor;ctx.font='12px system-ui';ctx.textAlign='center';
    ctx.fillText('Collecting data...',W/2,H/2);
    return;
  }

  const maxOf=(a,m)=>a.reduce((x,v)=>v>x?v:x,m);
  const maxSave=maxOf(valid.map(d=>d.save_kb),1);
  const maxEntK=maxOf(valid.map(d=>d.entities/1000),1);
  const maxTick=maxOf(valid.map(d=>d.tick),1);
  const xPos=i=>PAD.left+(i/(valid.length-1))*W2;
  const yS=v=>PAD.top+H2-(v/maxSave)*H2;
  const yE=v=>PAD.top+H2-(v/maxEntK)*H2;   // v in K
  const yT=v=>PAD.top+H2-(v/maxTick)*H2;   // v in ms

  ctx.font='11px system-ui';

  // Left axis: save/water (KB)
  const saveSteps=4;
  for(let s=0;s<=saveSteps;s++){
    const v=(maxSave/saveSteps)*s;
    const y=yS(v);
    ctx.strokeStyle=borderColor;ctx.lineWidth=1;
    ctx.beginPath();ctx.moveTo(PAD.left,y);ctx.lineTo(PAD.left+W2,y);
    ctx.globalAlpha=.2;ctx.stroke();ctx.globalAlpha=1;
    ctx.fillStyle=mutedColor;ctx.textAlign='right';
    const lbl=v>=1024?`${(v/1024).toFixed(1)}M`:`${Math.round(v)}K`;
    ctx.fillText(lbl,PAD.left-6,y+4);
  }
  ctx.save();ctx.translate(14,PAD.top+H2/2);ctx.rotate(-Math.PI/2);
  ctx.textAlign='center';ctx.fillStyle=mutedColor;ctx.font='11px system-ui';
  ctx.fillText('size (KB)',0,0);ctx.restore();

  // Right axis: entity count in K (green, near right edge)
  ctx.fillStyle=entityColor;ctx.textAlign='left';ctx.font='11px system-ui';
  for(let s=0;s<=4;s++){
    const v=(maxEntK/4)*s;
    ctx.fillText(`${Math.round(v)}K`,PAD.left+W2+6,yE(v)+4);
  }
  ctx.save();ctx.translate(W-18,PAD.top+H2/2);ctx.rotate(Math.PI/2);
  ctx.textAlign='center';ctx.fillStyle=entityColor;ctx.font='10px system-ui';
  ctx.fillText('entities',0,0);ctx.restore();

  // Far right axis: tick ms (amber)
  ctx.fillStyle=tickColor;ctx.textAlign='left';ctx.font='10px system-ui';
  for(let s=0;s<=4;s++){
    const v=(maxTick/4)*s;
    ctx.fillText(`${Math.round(v)}ms`,PAD.left+W2+52,yT(v)+4);
  }

  // X labels
  ctx.fillStyle=mutedColor;ctx.textAlign='right';ctx.font='11px system-ui';
  const multiDay2=valid.length>1&&new Date(valid[0].t).toDateString()!==new Date(valid[valid.length-1].t).toDateString();
  const lc=Math.min(6,valid.length);
  for(let i=0;i<lc;i++){
    const idx=Math.round(i*(valid.length-1)/(lc-1));
    const t=new Date(valid[idx].t);
    ctx.save();ctx.translate(xPos(idx),PAD.top+H2+12);ctx.rotate(-Math.PI/4);
    ctx.fillText(fmtLabel(t,multiDay2),0,0);ctx.restore();
  }

  // Water area fill + line
  ctx.beginPath();
  valid.forEach((d,i)=>{const x=xPos(i),y=yS(d.water_kb);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});
  ctx.lineTo(xPos(valid.length-1),PAD.top+H2);ctx.lineTo(xPos(0),PAD.top+H2);
  ctx.closePath();ctx.fillStyle=waterColor;ctx.globalAlpha=.15;ctx.fill();ctx.globalAlpha=1;
  ctx.beginPath();
  valid.forEach((d,i)=>{const x=xPos(i),y=yS(d.water_kb);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});
  ctx.strokeStyle=waterColor;ctx.lineWidth=2;ctx.lineJoin='round';ctx.stroke();

  // Save area fill + line
  ctx.beginPath();
  valid.forEach((d,i)=>{const x=xPos(i),y=yS(d.save_kb);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});
  ctx.lineTo(xPos(valid.length-1),PAD.top+H2);ctx.lineTo(xPos(0),PAD.top+H2);
  ctx.closePath();ctx.fillStyle=saveColor;ctx.globalAlpha=.1;ctx.fill();ctx.globalAlpha=1;
  ctx.beginPath();
  valid.forEach((d,i)=>{const x=xPos(i),y=yS(d.save_kb);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});
  ctx.strokeStyle=saveColor;ctx.lineWidth=2;ctx.lineJoin='round';ctx.stroke();

  // Entity count line (green, right axis in K)
  ctx.beginPath();
  let entityStarted=false;
  valid.forEach((d,i)=>{
    if(d.entities===0){entityStarted=false;return;}
    const x=xPos(i),y=yE(d.entities/1000);
    if(!entityStarted){ctx.moveTo(x,y);entityStarted=true;}else{ctx.lineTo(x,y);}
  });
  ctx.strokeStyle=entityColor;ctx.lineWidth=2;ctx.lineJoin='round';ctx.stroke();

  // Avg tick line (amber, right axis in ms)
  ctx.beginPath();
  let tickStarted=false;
  valid.forEach((d,i)=>{
    if(d.tick===0){tickStarted=false;return;}
    const x=xPos(i),y=yT(d.tick);
    if(!tickStarted){ctx.moveTo(x,y);tickStarted=true;}else{ctx.lineTo(x,y);}
  });
  ctx.strokeStyle=tickColor;ctx.lineWidth=1.5;ctx.lineJoin='round';ctx.stroke();

  // Axes
  ctx.beginPath();
  ctx.moveTo(PAD.left,PAD.top);ctx.lineTo(PAD.left,PAD.top+H2);ctx.lineTo(PAD.left+W2,PAD.top+H2);
  ctx.strokeStyle=borderColor;ctx.lineWidth=1;ctx.stroke();
}

document.getElementById('range').addEventListener('change',redraw);
redraw();
</script>
</body>
</html>"""

def last_known(field_idx, cast=int):
    """Return the last non-zero value for a CSV column, or 0 if none found."""
    if not os.path.exists(CSV_FILE):
        return 0
    result = 0
    with open(CSV_FILE) as f:
        for i, line in enumerate(f):
            if i == 0:
                continue
            p = line.strip().split(",")
            if len(p) > field_idx:
                try:
                    v = cast(p[field_idx])
                    if math.isfinite(v) and v > 0:
                        result = v
                except (ValueError, OverflowError):
                    pass
    return result

def main():
    os.umask(0o027)   # data files are group-readable at most, never world-readable
    os.makedirs(DATA_DIR, mode=0o750, exist_ok=True)
    row = collect()
    row = list(row)
    # Game stops logging save/water events when no players are online.
    # Fall back to last known value from CSV so the stat cards don't show 0.
    # An idle server logs its [ecss] stats only every ~4+ minutes, often
    # outside the 3-minute window, so carry entities/tick forward too.
    if row[10] == "online":
        if row[5] == 0:
            row[5] = last_known(5)
        if row[6] == 0:
            row[6] = last_known(6, float)
    if row[7] == 0:
        row[7] = last_known(7)  # save_kb
    if row[8] == 0:
        row[8] = last_known(8)  # water_kb
    append_csv(row)
    trim_csv()
    status = row[10]
    now = datetime.now(timezone.utc)
    live = {
        "status": status,
        "online": status == "online",
        "updated_epoch": int(now.timestamp()),
        "updated": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cpu": row[1], "mem": row[2], "players": row[3], "bad_perf": row[4],
        "entity_count": row[5], "avg_tick_ms": row[6],
        "save_size_kb": row[7], "water_size_kb": row[8], "pings": row[9]
    }
    # atomic replace: readers never see a partial file; refuses symlinks
    _cfgmod.atomic_write(LIVE_FILE, json.dumps(live), mode=0o640)
    rows = read_csv()
    _cfgmod.atomic_write(HTML_FILE, generate_html(rows, live), mode=0o640)
    print(f"[{row[0]}] status={status} cpu={row[1]}% players={row[3]} ent={row[5]} tick={row[6]}ms save={row[7]}KB water={row[8]}KB bad={row[4]}")

if __name__ == "__main__":
    main()
