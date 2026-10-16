#!/usr/bin/env python3
"""
Enshrouded Monitor - authenticated HTTP server.
Replaces `python3 -m http.server` for the monitor web service.

Env vars:
  ENSHROUDED_SHARED_PASSWORD  (required) status page password
  ENSHROUDED_ADMIN_TOKEN      (required only when [admin] compose_file is set;
                               must differ from the password)
  ENSHROUDED_COOKIE_SECRET    (optional, >= 32 chars) HMAC key for session cookies.
                               If unset a random key is generated at every start, so
                               all sessions end when the service restarts. Set it
                               to keep sessions across restarts (or to share the
                               cookie with another service that knows the same
                               secret). It is deliberately NOT derived from the
                               password, so a stolen cookie gives no offline
                               password-guessing oracle.
All other settings come from the config file (see config.example.toml).

Cookie contract:
  Name:    [web] cookie_name (default enshrouded_session)
  Value:   <expiry_unix_seconds>.<base64url_no_pad(HMAC-SHA256(secret,
           "enshrouded-session-v1:" + expiry_str))>
  Domain:  only if [web] cookie_domain is set (otherwise host-only)
  Path:    /
  Flags:   HttpOnly; SameSite=Lax; Max-Age=<cookie_max_age_seconds>;
           Secure unless [web] cookie_secure = false (plain-HTTP dev only)
  Logout only clears the browser cookie; a copied cookie stays valid until it
  expires or the signing secret changes (restart without COOKIE_SECRET).

Admin restart contract:
  POST /admin/restart, header: Authorization: Bearer <ENSHROUDED_ADMIN_TOKEN>
  Deliberately a separate secret from ENSHROUDED_SHARED_PASSWORD - leaking
  the read-only status password must not grant restart capability.
  Only [admin] compose_service is stopped and started again. Synchronous:
  the container's own entrypoint checks Steam for an update on every start,
  so a restart is the update-apply step. After starting, the container is
  inspected; the call only reports ok if it is running and not unhealthy.
  `updateApplied` is true only when the log shows an update being installed,
  otherwise null ("unknown") - a quiet log is not proof that no update ran.
  Response can take ~90s; size any caller timeout accordingly.
"""
import base64, collections, hashlib, hmac, io, ipaddress, json, os, secrets, socket, subprocess, sys, threading, time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, urlsplit

# ── Config ────────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import enshrouded_monitor_config as _cfgmod  # noqa: E402

_CFG = _cfgmod.load_config()
BIND           = _CFG["web"]["bind"]
PORT           = _CFG["web"]["port"]
DATA_DIR       = _CFG["general"]["data_dir"]
COOKIE_NAME    = _CFG["web"]["cookie_name"]
COOKIE_DOMAIN  = _CFG["web"]["cookie_domain"]
COOKIE_SECURE  = _CFG["web"]["cookie_secure"]
PUBLIC_ORIGIN  = (_cfgmod.parse_public_origin(_CFG["web"]["public_origin"])
                  if _CFG["web"]["public_origin"] else None)   # (scheme, host, port)
COOKIE_MAX_AGE = _CFG["web"]["cookie_max_age_seconds"]
MAX_CONNECTIONS = _CFG["web"]["max_connections"]
REQUEST_TIMEOUT_S = float(_CFG["web"]["request_timeout_seconds"])
GLOBAL_LOGIN_PER_MIN = _CFG["web"]["login_global_limit_per_minute"]
LOCKOUT_SECS   = 30
LOCKOUT_CAP    = 2_048        # max in-memory lockout entries
STALE_AFTER_S  = float(_CFG["general"]["stale_after_seconds"])

# Admin restart (disabled unless compose_file is configured)
COMPOSE_FILE        = _CFG["admin"]["compose_file"]
COMPOSE_SERVICE     = _CFG["admin"]["compose_service"]
GAME_CONTAINER      = _CFG["general"]["container"]
RESTART_LOG         = (_CFG["admin"]["restart_log"]
                       or os.path.join(DATA_DIR, "admin-restart.log"))
RESTART_COOLDOWN_S  = _CFG["admin"]["restart_cooldown_seconds"]
STOP_TIMEOUT_S      = _CFG["admin"]["stop_timeout_seconds"]
POST_START_WAIT_S   = _CFG["admin"]["post_start_wait_seconds"]

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


_SECRET_CACHE: list = []


def _cookie_secret() -> bytes:
    """Cookie signing key: ENSHROUDED_COOKIE_SECRET, else random per process.
    Independent of the password by design."""
    if not _SECRET_CACHE:
        env = os.environ.get("ENSHROUDED_COOKIE_SECRET", "")
        if env:
            if len(env) < 32:
                sys.exit("FATAL: ENSHROUDED_COOKIE_SECRET must be at least 32 characters")
            _SECRET_CACHE.append(env.encode())
        else:
            _SECRET_CACHE.append(secrets.token_bytes(32))
    return _SECRET_CACHE[0]


def startup_checks(password: str, admin_token) -> list:
    """Fatal config problems exit; returns a list of warning strings."""
    warnings = []
    if admin_token is not None and hmac.compare_digest(password.encode(), admin_token.encode()):
        sys.exit("FATAL: ENSHROUDED_ADMIN_TOKEN must differ from ENSHROUDED_SHARED_PASSWORD")
    cs = os.environ.get("ENSHROUDED_COOKIE_SECRET", "")
    if cs and (hmac.compare_digest(cs.encode(), password.encode())
               or (admin_token and hmac.compare_digest(cs.encode(), admin_token.encode()))):
        sys.exit("FATAL: ENSHROUDED_COOKIE_SECRET must differ from the password and admin token")
    if not COOKIE_SECURE:
        warnings.append("cookie_secure = false: session cookies are sent without the "
                        "Secure flag. Use only for plain-HTTP development/LAN.")
    if not cs:
        warnings.append("ENSHROUDED_COOKIE_SECRET not set: using a random per-process "
                        "signing key; all sessions end when this service restarts.")
    return warnings


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign(secret, expiry_str: str) -> str:
    key = secret if isinstance(secret, bytes) else secret.encode()
    msg = b"enshrouded-session-v1:" + expiry_str.encode()   # domain separation
    return _b64url(hmac.new(key, msg, hashlib.sha256).digest())


def make_cookie_value(secret, now: int = None) -> str:
    expiry = str((now if now is not None else int(time.time())) + COOKIE_MAX_AGE)
    return f"{expiry}.{_sign(secret, expiry)}"


def verify_cookie_value(value: str, secret, now: int = None) -> bool:
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
        return hmac.compare_digest(sig, _sign(secret, expiry_str))
    except Exception:
        return False


# ── Lockout / attempt limiting ────────────────────────────────────────────────

_lockouts: dict = {}   # canonical-ip (or "admin:<ip>") -> unlock_at float
_global_hits = {"login": collections.deque(), "admin": collections.deque()}
_lock = threading.Lock()


def canonical_ip(addr: str) -> str:
    """Canonical text form so equivalent spellings share one lockout key."""
    ip = ipaddress.ip_address(addr)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def lockout_remaining(ip: str) -> float:
    with _lock:
        _prune()
        return max(0.0, _lockouts.get(ip, 0.0) - time.time())


def _set_locked(key: str) -> None:
    """Caller holds _lock. Bounded: when full, the entry that unlocks soonest
    (the oldest) is evicted, so a new offender is ALWAYS recorded."""
    if key not in _lockouts and len(_lockouts) >= LOCKOUT_CAP:
        del _lockouts[min(_lockouts, key=_lockouts.get)]
    _lockouts[key] = time.time() + LOCKOUT_SECS


def set_lockout(ip: str) -> None:
    with _lock:
        _prune()
        _set_locked(ip)


_active: dict = {}     # key -> (token, expires_at): attempts currently being verified
ATTEMPT_MARGIN = 5.0   # seconds of processing allowed after the request deadline


def begin_attempt(key: str, bucket: str = "login", hold_secs: float = LOCKOUT_SECS):
    """Atomically check the per-client cooldown, any attempt of this client that
    is still in flight, and the global rate; if all allow it, register an active
    attempt owned by the returned token. Returns (0.0, token) when granted, else
    (seconds_to_wait, None). `hold_secs` must cover the whole request (callers
    pass the time left until the request's absolute deadline plus a margin), so
    a reservation never expires while its request is still being read. The
    failed-login cooldown starts only when finish_attempt() is called."""
    with _lock:
        _prune()
        now = time.time()
        rem = _lockouts.get(key, 0.0) - now
        if rem > 0:
            return rem, None
        act = _active.get(key)
        if act is not None:
            return max(1.0, act[1] - now), None
        hits = _global_hits[bucket]
        while hits and hits[0] <= now - 60:
            hits.popleft()
        if len(hits) >= GLOBAL_LOGIN_PER_MIN:
            return max(1.0, hits[0] + 60 - now), None
        hits.append(now)
        token = object()
        _active[key] = (token, now + hold_secs)
        return 0.0, token


def finish_attempt(key: str, token, ok: bool) -> None:
    """End an attempt. Only the reservation matching `token` is released (an
    older attempt can never clear a newer one). A failed attempt starts the
    cooldown now, i.e. when verification finished, not when it began."""
    with _lock:
        cur = _active.get(key)
        if cur is not None and cur[0] is token:
            del _active[key]
        if not ok:
            _set_locked(key)


def _prune() -> None:
    """Remove expired entries. Caller must hold _lock."""
    t   = time.time()
    old = [k for k, v in _lockouts.items() if v <= t]
    for k in old:
        del _lockouts[k]
    old = [k for k, v in _active.items() if v[1] <= t]
    for k in old:
        del _active[k]


# ── Admin restart ─────────────────────────────────────────────────────────────

_admin_state = {"last_restart_at": 0.0, "in_progress": False}


def _restart_cooldown_remaining() -> float:
    with _lock:
        return max(0.0, RESTART_COOLDOWN_S - (time.time() - _admin_state["last_restart_at"]))


def _claim_restart_slot():
    """Returns (True, None) when claimed, else (False, "in_progress"|"cooldown").
    A dedicated in-progress flag is the mutex; the cooldown (measured from the
    END of the previous restart) is separate and may be configured to 0."""
    with _lock:
        if _admin_state["in_progress"]:
            return False, "in_progress"
        if time.time() - _admin_state["last_restart_at"] < RESTART_COOLDOWN_S:
            return False, "cooldown"
        _admin_state["in_progress"] = True
        return True, None


def _release_restart_slot() -> None:
    with _lock:
        _admin_state["in_progress"] = False
        _admin_state["last_restart_at"] = time.time()


def _log_restart(ts: str, *, ok: bool, update_applied=None, note: str = None) -> None:
    parts = [ts, "ok" if ok else "FAIL"]
    if update_applied is not None:
        parts.append(f"update_applied={update_applied}")
    if note:
        parts.append(note.replace("\n", " "))
    line = " ".join(parts)
    try:
        _cfgmod.safe_append(RESTART_LOG, line + "\n", mode=0o640)
    except OSError as e:
        print(f"[admin-restart] WARNING: cannot write {RESTART_LOG}: {e}", flush=True)
    print(f"[admin-restart] {line}", flush=True)


def _container_state() -> tuple:
    """(running: bool|None, health: str) from docker inspect; None = no answer."""
    r = subprocess.run(
        ["docker", "inspect", "-f",
         "{{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
         GAME_CONTAINER],
        capture_output=True, text=True, timeout=15)
    out = r.stdout.strip().split()
    if r.returncode != 0 or not out or out[0] not in ("true", "false"):
        return None, ""
    return out[0] == "true", (out[1] if len(out) > 1 else "")


def _do_restart() -> dict:
    """Graceful stop (respecting the game's save-on-exit) then start back up -
    only the configured compose service. The container's own entrypoint checks
    Steam for an update and applies it on every start."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    base = ["docker", "compose", "-f", COMPOSE_FILE]
    try:
        stop = subprocess.run(
            base + ["stop", "-t", str(STOP_TIMEOUT_S), COMPOSE_SERVICE],
            capture_output=True, text=True, timeout=STOP_TIMEOUT_S + 30,
        )
        if stop.returncode != 0:
            _log_restart(ts, ok=False, note=f"stop failed: {stop.stderr.strip()[:200]}")
            return {"ok": False, "reason": "stop_failed", "message": stop.stderr.strip()[:500]}

        up = subprocess.run(
            base + ["up", "-d", "--no-deps", COMPOSE_SERVICE],
            capture_output=True, text=True, timeout=120,
        )
        if up.returncode != 0:
            _log_restart(ts, ok=False, note=f"start failed after stop: {up.stderr.strip()[:200]}")
            return {"ok": False, "reason": "start_failed", "stopped": True,
                    "message": up.stderr.strip()[:500]}

        time.sleep(POST_START_WAIT_S)
        running, health = _container_state()
        if running is not True or health == "unhealthy":
            why = "not_running" if running is not True else "unhealthy"
            _log_restart(ts, ok=False, note=f"after start: {why} (running={running} health={health or '-'})")
            return {"ok": False, "reason": why, "running": running, "health": health or None,
                    "message": "Compose started the service but the container is not healthy."}

        logs = subprocess.run(
            ["docker", "logs", "--since", f"{POST_START_WAIT_S + 15}s", GAME_CONTAINER],
            capture_output=True, text=True, timeout=15,
        )
        # Only a positive log line is evidence. Its absence is NOT evidence that
        # no update was pending (log may be incomplete / not yet reached).
        text = logs.stdout + logs.stderr
        applied = True if (logs.returncode == 0 and (
            "Downloading update" in text or "Installing update" in text)) else None

        _log_restart(ts, ok=True, update_applied=("yes" if applied else "unknown"))
        return {
            "ok": True, "restarted": True, "running": True, "health": health or None,
            "updateStatus": "applied" if applied else "unknown",
            "updateFound": applied, "updateApplied": applied,
            "message": ("Update applied, server restarted." if applied
                        else "Server restarted and is running; update status unknown."),
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

class _DeadlineRaw(io.RawIOBase):
    """Raw socket reader that enforces an ABSOLUTE deadline on every receive:
    before each recv the socket timeout is set to min(time left, per-recv
    timeout), so a client dribbling bytes (slowloris) cannot outlast the
    deadline no matter how the buffered layer above chunks its reads."""

    def __init__(self, sock, deadline: float, per_recv: float):
        super().__init__()
        self._sock, self._deadline, self._per_recv = sock, deadline, per_recv

    def readable(self):
        return True

    def readinto(self, buf):
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("request deadline exceeded")
        try:
            self._sock.settimeout(min(left, self._per_recv))
            return self._sock.recv_into(buf)
        finally:
            try:
                self._sock.settimeout(self._per_recv)   # keep writes on the normal timeout
            except OSError:
                pass


class _Handler(BaseHTTPRequestHandler):
    server_version = "EnshroudedMonitor/1"
    sys_version    = ""
    timeout        = REQUEST_TIMEOUT_S      # per-recv socket timeout (StreamRequestHandler)

    def setup(self):
        super().setup()
        self._deadline = time.monotonic() + REQUEST_TIMEOUT_S
        self.rfile.close()   # drop the plain makefile() reader; ours enforces the deadline
        self.rfile = io.BufferedReader(
            _DeadlineRaw(self.connection, self._deadline, float(self.timeout)))

    def _attempt_hold(self) -> float:
        """How long an auth reservation must live: until this request's
        absolute deadline, plus a small processing margin."""
        return max(0.0, self._deadline - time.monotonic()) + ATTEMPT_MARGIN

    def log_message(self, fmt, *args):
        pass   # never log paths — could contain form data in edge cases

    def log_request(self, code="-", size="-"):
        pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _ip(self) -> str:
        """
        Return the canonical client IP to use for lockout keying.

        Trust X-Real-IP only when the direct TCP peer is in one of the
        configured trusted_proxy_networks. All other callers use their
        socket address as-is.
        """
        peer = canonical_ip(self.client_address[0])
        try:
            if any(ipaddress.ip_address(peer) in n for n in _TRUSTED_PROXY_NETS):
                real_ip = self.headers.get("X-Real-IP", "").strip()
                if real_ip:
                    return canonical_ip(real_ip)   # validates + canonicalises
        except ValueError:
            pass
        return peer

    def _peer_trusted(self) -> bool:
        try:
            peer = ipaddress.ip_address(canonical_ip(self.client_address[0]))
            return any(peer in n for n in _TRUSTED_PROXY_NETS)
        except ValueError:
            return False

    def _same_origin(self) -> bool:
        """CSRF guard for browser-driven state changes. Sec-Fetch-Site (set by
        the browser, unforgeable by pages) decides when present. Otherwise an
        Origin header must match scheme + host + effective port of the
        configured [web] public_origin; when that is unset it must match the
        Host header (and the scheme given by X-Forwarded-Proto, honoured only
        from trusted proxy networks). Non-browser clients send none of these
        headers and pass."""
        sfs = self.headers.get("Sec-Fetch-Site")
        if sfs is not None:
            return sfs == "same-origin"
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        try:
            u = urlsplit(origin)
            o_scheme, o_host = u.scheme, (u.hostname or "").lower()
            o_port = u.port or {"http": 80, "https": 443}.get(o_scheme)
        except ValueError:
            return False
        if o_scheme not in ("http", "https") or not o_host or o_port is None:
            return False
        if PUBLIC_ORIGIN is not None:
            return (o_scheme, o_host, o_port) == PUBLIC_ORIGIN
        try:
            h = urlsplit("//" + self.headers.get("Host", ""))
            h_host = (h.hostname or "").lower()
            h_port = h.port if h.port is not None else {"http": 80, "https": 443}[o_scheme]
        except ValueError:
            return False
        if not h_host or (o_host, o_port) != (h_host, h_port):
            return False
        if self._peer_trusted():
            xfp = self.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
            if xfp in ("http", "https") and xfp != o_scheme:
                return False
        return True

    def _cookie_value(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k.strip() == COOKIE_NAME:
                return v.strip()
        return None

    def _authed(self) -> bool:
        c = self._cookie_value()
        return c is not None and verify_cookie_value(c, _cookie_secret())

    def _send(self, code: int, ct: str, body: bytes,
              extra=(), no_store: bool = True) -> None:
        # no_store is kept for compatibility; every response is no-store
        # (authenticated content must never be cached by browsers or proxies).
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
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

    def _cookie_attrs(self) -> str:
        attrs = "Path=/; "
        if COOKIE_DOMAIN:
            attrs = f"Domain={COOKIE_DOMAIN}; " + attrs
        return attrs

    def _cookie_header(self) -> str:
        val = make_cookie_value(_cookie_secret())
        return (f"{COOKIE_NAME}={val}; {self._cookie_attrs()}Max-Age={COOKIE_MAX_AGE}; "
                f"HttpOnly; SameSite=Lax" + ("; Secure" if COOKIE_SECURE else ""))

    def _clear_cookie_header(self) -> str:
        return (f"{COOKIE_NAME}=deleted; {self._cookie_attrs()}Max-Age=0; "
                f"HttpOnly; SameSite=Lax" + ("; Secure" if COOKIE_SECURE else ""))

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
            self._send(405, "text/plain", b"Use POST", extra=[("Allow", "POST")]); return
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
        if not self._same_origin():
            self._send(403, "text/plain", b"Forbidden"); return
        ip  = self._ip()
        # Reserve the attempt BEFORE reading the body or comparing passwords.
        rem, token = begin_attempt(ip, "login", self._attempt_hold())
        if rem > 0:
            self._send_429(rem); return

        ok = False
        try:
            try:
                length = max(0, int(self.headers.get("Content-Length", 0)))
                raw = self.rfile.read(min(length, 4096)).decode(errors="replace")
            except (ValueError, OSError):    # bad length, timeout, reset: counts as a failure
                self.close_connection = True
                return
            attempt = parse_qs(raw).get("password", [""])[0]
            # attempt is never logged, stored, or passed outside this scope
            ok = hmac.compare_digest(attempt.encode(), _pw().encode())
        finally:
            finish_attempt(ip, token, ok)

        if ok:
            self._redirect("/", extra=[("Set-Cookie", self._cookie_header())])
        else:
            self._send_429(lockout_remaining(ip) or LOCKOUT_SECS)

    def _logout(self) -> None:
        if not self._same_origin():
            self._send(403, "text/plain", b"Forbidden"); return
        self._redirect("/", extra=[("Set-Cookie", self._clear_cookie_header())])

    def _admin_restart(self) -> None:
        if not COMPOSE_FILE:
            self._send_json(404, {"ok": False, "reason": "admin_disabled"})
            return
        ip        = self._ip()
        admin_key = "admin:" + ip

        rem, atoken = begin_attempt(admin_key, "admin", self._attempt_hold())
        if rem > 0:
            self._send_json(429, {"ok": False, "reason": "auth_lockout",
                                   "retryAfterSeconds": int(rem) + 1},
                            extra=[("Retry-After", str(int(rem) + 1))])
            return

        auth  = self.headers.get("Authorization", "")
        token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
        ok = False
        try:
            ok = bool(token) and hmac.compare_digest(token.encode(), _admin_token().encode())
        finally:
            finish_attempt(admin_key, atoken, ok)
        if not ok:
            self._send_json(401, {"ok": False, "reason": "unauthorized"})
            return

        claimed, why = _claim_restart_slot()
        if not claimed:
            rem = _restart_cooldown_remaining() if why == "cooldown" else 5
            self._send_json(429, {"ok": False, "reason": why,
                                   "retryAfterSeconds": int(rem) + 1},
                            extra=[("Retry-After", str(int(rem) + 1))])
            return
        try:
            result = _do_restart()
        finally:
            _release_restart_slot()
        self._send_json(200 if result["ok"] else 500, result)

    def _serve_live(self) -> None:
        """Serve live.json with a server-computed `status` that accounts for
        staleness (missing/old/garbled data -> "stale")."""
        fpath = os.path.join(DATA_DIR, "live.json")
        try:
            live = json.loads(_cfgmod.safe_read(fpath))
            if not isinstance(live, dict):
                raise ValueError
        except FileNotFoundError:
            live = {"status": "stale", "reason": "no data yet"}
            self._send_json(200, live); return
        except (ValueError, OSError):
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
            data = _cfgmod.safe_read(fpath)
        except OSError:      # missing, symlink or not a regular file
            self._send(404, "text/plain", b"Not found"); return
        self._send(200, ct, data)


class _BoundedServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a hard cap on simultaneous handler threads;
    connections over the cap get an immediate 503 instead of a new thread."""
    daemon_threads = True

    def __init__(self, addr, handler, max_connections: int):
        self._slots = threading.BoundedSemaphore(max_connections)
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nRetry-After: 5\r\n"
                                b"Cache-Control: no-store\r\nContent-Length: 0\r\n"
                                b"Connection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


if __name__ == "__main__":
    os.umask(0o027)
    _password = _pw()            # fail fast if env vars missing
    _token = _admin_token() if COMPOSE_FILE else None
    for _w in startup_checks(_password, _token):
        print(f"[enshrouded-monitor-web] WARNING: {_w}", flush=True)
    _cookie_secret()
    # Threaded (bounded): a slow /admin/restart request must not block ordinary
    # /live.json or dashboard traffic for other visitors while it runs.
    _srv = _BoundedServer((BIND, PORT), _Handler, MAX_CONNECTIONS)   # bind first: fail loudly if port busy
    print(f"[enshrouded-monitor-web] listening {BIND}:{PORT}", flush=True)
    _srv.serve_forever()
