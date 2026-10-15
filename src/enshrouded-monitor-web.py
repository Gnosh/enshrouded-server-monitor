#!/usr/bin/env python3
"""
Enshrouded Monitor — authenticated HTTP server.
Replaces `python3 -m http.server` for the monitor web service.

Env vars: ENSHROUDED_SHARED_PASSWORD (required), ENSHROUDED_ADMIN_TOKEN
(required only when [admin] compose_file is set). All other settings come
from the config file (see config.example.toml).

Cookie contract (may be shared with other services that verify the same cookie):
  Name:    enshrouded_session
  Value:   <expiry_unix_seconds>.<base64url_no_pad(HMAC-SHA256(password, expiry_str))>
  Domain:  [web] cookie_domain from config (HTTPS path only; empty = host-only)
  Path:    /
  Flags:   HttpOnly; Secure; SameSite=Lax; Max-Age=31536000
  Direct HTTP access: same cookie value, same name, no Domain, no Secure flag.

Admin restart contract:
  POST /admin/restart, header: Authorization: Bearer <ENSHROUDED_ADMIN_TOKEN>
  Deliberately a separate secret from ENSHROUDED_SHARED_PASSWORD — leaking
  the read-only status password must not grant restart capability.
  Synchronous: the container's own entrypoint already checks Steam for an
  update and applies it on every start, so a restart *is* the update-apply
  step — nothing extra needed there. Response can take up to ~90s (graceful
  stop timeout + startup + a short post-start log check); size any caller
  timeout accordingly.
"""
import base64, hashlib, hmac, ipaddress, json, os, subprocess, sys, threading, time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# ── Config ────────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import enshrouded_monitor_config as _cfgmod  # noqa: E402

_CFG = _cfgmod.load_config()
BIND           = _CFG["web"]["bind"]
PORT           = int(_CFG["web"]["port"])
DATA_DIR       = _CFG["general"]["data_dir"]
COOKIE_NAME    = _CFG["web"]["cookie_name"]
COOKIE_DOMAIN  = _CFG["web"]["cookie_domain"]
COOKIE_MAX_AGE = 31_536_000   # 1 year in seconds
LOCKOUT_SECS   = 30
LOCKOUT_CAP    = 2_048        # max in-memory lockout entries
STALE_AFTER_S  = float(_CFG["general"]["stale_after_seconds"])

# Admin restart (disabled unless compose_file is configured)
COMPOSE_FILE        = _CFG["admin"]["compose_file"]
GAME_CONTAINER      = _CFG["general"]["container"]
RESTART_LOG         = os.path.join(DATA_DIR, "admin-restart.log")
RESTART_COOLDOWN_S  = int(_CFG["admin"]["restart_cooldown_seconds"])
STOP_TIMEOUT_S      = int(_CFG["admin"]["stop_timeout_seconds"])
POST_START_WAIT_S   = int(_CFG["admin"]["post_start_wait_seconds"])

# X-Real-IP is trusted only from peers in these networks (your reverse
# proxy); all other callers use their direct socket address.
_TRUSTED_PROXY_NETS = [ipaddress.ip_network(n, strict=False)
                       for n in _CFG["web"]["trusted_proxy_networks"]]


# ── Crypto ────────────────────────────────────────────────────────────────────

def _pw() -> str:
    v = os.environ.get("ENSHROUDED_SHARED_PASSWORD", "")
    if not v:
        sys.exit("FATAL: ENSHROUDED_SHARED_PASSWORD not set")
    return v


def _admin_token() -> str:
    v = os.environ.get("ENSHROUDED_ADMIN_TOKEN", "")
    if not v:
        sys.exit("FATAL: ENSHROUDED_ADMIN_TOKEN not set")
    return v


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign(password: str, expiry_str: str) -> str:
    return _b64url(hmac.new(password.encode(), expiry_str.encode(), hashlib.sha256).digest())


def make_cookie_value(password: str, now: int = None) -> str:
    expiry = str((now if now is not None else int(time.time())) + COOKIE_MAX_AGE)
    return f"{expiry}.{_sign(password, expiry)}"


def verify_cookie_value(value: str, password: str, now: int = None) -> bool:
    """True iff value is a valid, non-expired, correctly-signed cookie token."""
    try:
        dot        = value.index(".")
        expiry_str = value[:dot]
        sig        = value[dot + 1:]
        expiry     = int(expiry_str)
        t          = now if now is not None else int(time.time())
        if expiry <= t:
            return False
        if expiry > t + COOKIE_MAX_AGE + 60:   # implausibly far future
            return False
        return hmac.compare_digest(sig, _sign(password, expiry_str))
    except Exception:
        return False


# ── Lockout ───────────────────────────────────────────────────────────────────

_lockouts: dict = {}   # ip -> unlock_at float
_lock = threading.Lock()


def lockout_remaining(ip: str) -> float:
    with _lock:
        _prune()
        return max(0.0, _lockouts.get(ip, 0.0) - time.time())


def set_lockout(ip: str) -> None:
    with _lock:
        _prune()
        if len(_lockouts) < LOCKOUT_CAP:
            _lockouts[ip] = time.time() + LOCKOUT_SECS


def _prune() -> None:
    """Remove expired entries. Caller must hold _lock."""
    t   = time.time()
    old = [k for k, v in _lockouts.items() if v <= t]
    for k in old:
        del _lockouts[k]


# ── Admin restart ─────────────────────────────────────────────────────────────

_admin_state = {"last_restart_at": 0.0}


def _restart_cooldown_remaining() -> float:
    with _lock:
        return max(0.0, RESTART_COOLDOWN_S - (time.time() - _admin_state["last_restart_at"]))


def _claim_restart_slot() -> bool:
    """Atomically check-and-set the cooldown. False if one's already active —
    this doubles as the mutex against a second trigger firing mid-restart,
    since the clock starts before the (slow) restart work even begins."""
    with _lock:
        if time.time() - _admin_state["last_restart_at"] < RESTART_COOLDOWN_S:
            return False
        _admin_state["last_restart_at"] = time.time()
        return True


def _log_restart(ts: str, *, ok: bool, update_applied=None, note: str = None) -> None:
    parts = [ts, "ok" if ok else "FAIL"]
    if update_applied is not None:
        parts.append(f"update_applied={update_applied}")
    if note:
        parts.append(note)
    line = " ".join(parts)
    try:
        with open(RESTART_LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass
    print(f"[admin-restart] {line}", flush=True)


def _do_restart() -> dict:
    """Graceful stop (respecting the game's save-on-exit) then start back up.
    The container's own entrypoint checks Steam for an update and applies it
    on every start — that's *why* a plain restart satisfies "check for update,
    apply if found" with no separate step needed here."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        stop = subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "stop", "-t", str(STOP_TIMEOUT_S)],
            capture_output=True, text=True, timeout=STOP_TIMEOUT_S + 30,
        )
        if stop.returncode != 0:
            _log_restart(ts, ok=False, note=f"stop failed: {stop.stderr.strip()[:200]}")
            return {"ok": False, "reason": "stop_failed", "message": stop.stderr.strip()[:500]}

        up = subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "up", "-d"],
            capture_output=True, text=True, timeout=60,
        )
        if up.returncode != 0:
            _log_restart(ts, ok=False, note=f"start failed: {up.stderr.strip()[:200]}")
            return {"ok": False, "reason": "start_failed", "message": up.stderr.strip()[:500]}

        # Let the entrypoint reach its update-check phase, then look at what
        # it actually did. "Downloading update"/"Installing update" is the
        # concrete signal an update was applied; there's no equally concrete
        # signal for "checked, none was available" vs. "checked, found one" —
        # so updateFound mirrors updateApplied rather than guessing.
        time.sleep(POST_START_WAIT_S)
        logs = subprocess.run(
            ["docker", "logs", "--since", f"{POST_START_WAIT_S + 15}s", GAME_CONTAINER],
            capture_output=True, text=True, timeout=15,
        ).stdout
        update_applied = ("Downloading update" in logs) or ("Installing update" in logs)

        _log_restart(ts, ok=True, update_applied=update_applied)
        return {
            "ok": True, "updateFound": update_applied, "updateApplied": update_applied,
            "restarted": True,
            "message": ("Update applied, server restarted cleanly." if update_applied
                        else "Server restarted cleanly, no update was pending."),
        }
    except subprocess.TimeoutExpired as e:
        _log_restart(ts, ok=False, note=f"timeout: {e}")
        return {"ok": False, "reason": "timeout", "message": str(e)}
    except Exception as e:
        _log_restart(ts, ok=False, note=f"exception: {e}")
        return {"ok": False, "reason": "error", "message": str(e)}


# ── Security headers ──────────────────────────────────────────────────────────

_SEC = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy",
     "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"),
]

# ── Login page ────────────────────────────────────────────────────────────────

_LOGIN = """\
<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Sign in</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
     background:#111;color:#eee;font-family:system-ui,sans-serif}
.card{width:320px;padding:2rem;background:#1e1e1e;border-radius:8px;
      box-shadow:0 4px 24px #0008}
h1{font-size:1rem;margin-bottom:1.5rem;color:#888;font-weight:400;
   text-transform:uppercase;letter-spacing:.06em}
input[type=password]{width:100%%;padding:.65rem .8rem;border-radius:4px;
  border:1px solid #333;background:#2a2a2a;color:#eee;font-size:1rem;outline:none}
input:focus{border-color:#e5702a}
button{margin-top:.75rem;width:100%%;padding:.65rem;border-radius:4px;
  border:none;background:#e5702a;color:#fff;font-size:1rem;cursor:pointer}
button:disabled,input:disabled{opacity:.45;cursor:not-allowed}
.msg{margin-top:.75rem;font-size:.875rem}
.err{color:#f87171}.inf{color:#94a3b8}
</style></head>
<body><div class="card">
<h1>Enshrouded Monitor</h1>
<form method="post" action="/_auth/login">
<input type="password" name="password" placeholder="Password" id="pw" __DISABLED__ __AUTOFOCUS__ required>
<button type="submit" id="btn" __DISABLED__>Sign in</button>
__MSG__
</form></div>
<script>
(function(){
  var s=__LOCKOUT__;
  if(!s)return;
  var el=document.getElementById('cd');
  function tick(){
    if(s<=0){
      document.getElementById('btn').disabled=false;
      document.getElementById('pw').disabled=false;
      if(el)el.textContent='';return;
    }
    if(el)el.textContent='Try again in '+s+'s';
    s--;setTimeout(tick,1000);
  }
  tick();
})();
</script></body></html>"""


def _login_html(*, lockout: float = 0.0, wrong: bool = False) -> bytes:
    secs = max(0, int(lockout))
    if secs > 0:
        disabled, autofocus = "disabled", ""
        msg       = '<p class="msg inf"><span id="cd"></span></p>'
        countdown = secs + 1
    elif wrong:
        disabled, autofocus = "", "autofocus"
        msg       = '<p class="msg err">Incorrect password.</p>'
        countdown = 0
    else:
        disabled, autofocus = "", "autofocus"
        msg, countdown = "", 0
    return (_LOGIN
            .replace("__DISABLED__",  disabled)
            .replace("__AUTOFOCUS__", autofocus)
            .replace("__MSG__",       msg)
            .replace("__LOCKOUT__",   str(countdown))
            ).encode()


# ── HTTP handler ──────────────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):
    server_version = "EnshroudedMonitor/1"
    sys_version    = ""

    def log_message(self, fmt, *args):
        pass   # never log paths — could contain form data in edge cases

    def log_request(self, code="-", size="-"):
        pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _ip(self) -> str:
        """
        Return the client IP to use for lockout keying.

        Trust X-Real-IP only when the direct TCP peer is in one of the
        configured trusted_proxy_networks. All other callers use their
        socket address as-is.
        """
        peer = self.client_address[0]
        try:
            if any(ipaddress.ip_address(peer) in n for n in _TRUSTED_PROXY_NETS):
                real_ip = self.headers.get("X-Real-IP", "").strip()
                if real_ip:
                    ipaddress.ip_address(real_ip)   # validate format
                    return real_ip
        except ValueError:
            pass
        return peer

    def _is_production(self) -> bool:
        """True when a cookie_domain is configured and the request Host matches it."""
        if not COOKIE_DOMAIN:
            return False
        host = self.headers.get("Host", "").split(":")[0]
        return host == COOKIE_DOMAIN or host.endswith("." + COOKIE_DOMAIN)

    def _cookie_value(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k.strip() == COOKIE_NAME:
                return v.strip()
        return None

    def _authed(self) -> bool:
        c = self._cookie_value()
        return c is not None and verify_cookie_value(c, _pw())

    def _send(self, code: int, ct: str, body: bytes,
              extra=(), no_store: bool = False) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if no_store:
            self.send_header("Cache-Control", "no-store")
        for k, v in _SEC:
            self.send_header(k, v)
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, obj: dict, extra=()) -> None:
        self._send(code, "application/json", json.dumps(obj).encode(),
                   extra=extra, no_store=True)

    def _redirect(self, loc: str, extra=()) -> None:
        self.send_response(303)
        self.send_header("Location", loc)
        self.send_header("Cache-Control", "no-store")
        for k, v in _SEC:
            self.send_header(k, v)
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()

    def _cookie_header(self) -> str:
        val = make_cookie_value(_pw())
        if self._is_production():
            return (f"{COOKIE_NAME}={val}; Domain={COOKIE_DOMAIN}; Path=/; "
                    f"Max-Age={COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Lax")
        # LAN/HTTP: same token, no Domain restriction, no Secure flag
        return (f"{COOKIE_NAME}={val}; Path=/; "
                f"Max-Age={COOKIE_MAX_AGE}; HttpOnly; SameSite=Lax")

    def _clear_cookie_header(self) -> str:
        if self._is_production():
            return (f"{COOKIE_NAME}=deleted; Domain={COOKIE_DOMAIN}; Path=/; "
                    f"Max-Age=0; HttpOnly; Secure; SameSite=Lax")
        return f"{COOKIE_NAME}=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"

    def _show_login(self, *, lockout: float = 0.0, wrong: bool = False) -> None:
        body = _login_html(lockout=lockout, wrong=wrong)
        self._send(200, "text/html; charset=utf-8", body, no_store=True)

    def _send_429(self, remaining: float) -> None:
        body = _login_html(lockout=remaining)
        self._send(429, "text/html; charset=utf-8", body,
                   extra=[("Retry-After", str(int(remaining) + 1))],
                   no_store=True)

    # ── Request handlers ──────────────────────────────────────────────────────

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/_auth/logout":
            self._logout(); return
        if not self._authed():
            self._show_login(lockout=lockout_remaining(self._ip())); return
        if path in ("/", "/index.html"):
            self._serve("index.html", "text/html; charset=utf-8")
        elif path == "/live.json":
            self._serve_live()
        elif path == "/metrics.csv":
            self._serve("metrics.csv", "text/csv")
        else:
            self._send(404, "text/plain", b"Not found")

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/_auth/login":
            self._login()
        elif path == "/_auth/logout":
            self._logout()
        elif path == "/admin/restart":
            self._admin_restart()
        else:
            self._send(404, "text/plain", b"Not found")

    def _login(self) -> None:
        ip  = self._ip()
        rem = lockout_remaining(ip)
        if rem > 0:
            self._send_429(rem); return

        try:
            length = max(0, int(self.headers.get("Content-Length", 0)))
        except ValueError:
            length = 0
        raw     = self.rfile.read(min(length, 4096)).decode(errors="replace")
        attempt = parse_qs(raw).get("password", [""])[0]
        # attempt is never logged, stored, or passed outside this scope

        if hmac.compare_digest(attempt.encode(), _pw().encode()):
            self._redirect("/", extra=[("Set-Cookie", self._cookie_header())])
        else:
            set_lockout(ip)
            self._send_429(lockout_remaining(ip))

    def _logout(self) -> None:
        self._redirect("/", extra=[("Set-Cookie", self._clear_cookie_header())])

    def _admin_restart(self) -> None:
        if not COMPOSE_FILE:
            self._send_json(404, {"ok": False, "reason": "admin_disabled"})
            return
        ip        = self._ip()
        admin_key = "admin:" + ip

        rem = lockout_remaining(admin_key)
        if rem > 0:
            self._send_json(429, {"ok": False, "reason": "auth_lockout",
                                   "retryAfterSeconds": int(rem) + 1},
                            extra=[("Retry-After", str(int(rem) + 1))])
            return

        auth  = self.headers.get("Authorization", "")
        token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
        if not token or not hmac.compare_digest(token.encode(), _admin_token().encode()):
            set_lockout(admin_key)
            self._send_json(401, {"ok": False, "reason": "unauthorized"})
            return

        if not _claim_restart_slot():
            rem = _restart_cooldown_remaining()
            self._send_json(429, {"ok": False, "reason": "cooldown",
                                   "retryAfterSeconds": int(rem) + 1},
                            extra=[("Retry-After", str(int(rem) + 1))])
            return

        result = _do_restart()
        self._send_json(200 if result["ok"] else 500, result)

    def _serve_live(self) -> None:
        """Serve live.json with a server-computed `status` that accounts for
        staleness (missing/old/garbled data -> "stale")."""
        fpath = os.path.join(DATA_DIR, "live.json")
        try:
            with open(fpath, "rb") as f:
                live = json.loads(f.read())
            if not isinstance(live, dict):
                raise ValueError
        except FileNotFoundError:
            live = {"status": "stale", "reason": "no data yet"}
            self._send_json(200, live); return
        except ValueError:
            live = {"status": "stale", "reason": "unreadable data"}
            self._send_json(200, live); return
        # Defence in depth: never emit Steam IDs, even from an old live.json.
        live["pings"] = [{"ping": p.get("ping"), "name": p.get("name") or f"Player {i}"}
                         for i, p in enumerate(live.get("pings") or [], 1)
                         if isinstance(p, dict)]
        live["recorded_status"] = live.get("status")
        live["status"] = _cfgmod.effective_status(live, time.time(), STALE_AFTER_S)
        if live["status"] != "online":
            live["online"] = False
        self._send_json(200, live)

    def _serve(self, filename: str, ct: str) -> None:
        fpath = os.path.join(DATA_DIR, filename)
        try:
            with open(fpath, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            self._send(404, "text/plain", b"Not found"); return
        self._send(200, ct, data)


if __name__ == "__main__":
    _pw()            # fail fast if env vars missing
    if COMPOSE_FILE:
        _admin_token()
    # Threaded: a slow /admin/restart request must not block ordinary
    # /live.json or dashboard traffic for other visitors while it runs.
    _srv = ThreadingHTTPServer((BIND, PORT), _Handler)   # bind first: fail loudly if port busy
    print(f"[enshrouded-monitor-web] listening {BIND}:{PORT}", flush=True)
    _srv.serve_forever()
