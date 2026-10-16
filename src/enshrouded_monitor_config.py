"""Shared configuration loader for the Enshrouded monitor scripts.

Lookup order for the config file (first existing wins):
  1. $ENSHROUDED_MONITOR_CONFIG   (explicit path; error if it does not exist)
  2. ~/.config/enshrouded-monitor/config.toml
  3. /etc/enshrouded-monitor/config.toml
If none exist, built-in defaults are used.  Secrets are NEVER read from the
config file; they come from environment variables only.
"""
import ipaddress
import math
import os
import re
import stat
import tempfile
import sys
import tomllib
from urllib.parse import urlsplit

DEFAULTS = {
    "general": {
        "data_dir": "~/.local/share/enshrouded-monitor",
        "container": "enshrouded",
        "server_name": "My Enshrouded Server",
        "player_display": "anonymous",  # "anonymous" (Player 1..N) | "names"
        "steam_lookup": False,      # opt-in: fetch public Steam names (needs player_display="names")
        "steam_cache_file": "",     # cache path; empty = <data_dir>/steam_names.json
        "steam_names_file": "",     # optional JSON {"<steamid>": "Display name"}; used only with "names"
        "cpu_cores": 0,             # host core count shown as "x/N"; 0 = hide
        "stale_after_seconds": 900, # data older than this is shown as STALE
        "reboot_marker_time": "",   # "HH:MM" (24h, browser-local) chart marker; empty = none
        "reboot_marker_label": "reboot",  # drawn as "<HH:MM> <label>"
        "max_csv_rows": 50000,      # metrics.csv is trimmed to the newest N rows (5-min samples: ~173 days)
    },
    "web": {
        "bind": "127.0.0.1",
        "port": 8083,
        "cookie_name": "enshrouded_session",
        "cookie_domain": "",        # empty = host-only cookie (recommended)
        "public_origin": "",        # e.g. "https://status.example.com"; CSRF Origin check target (optional)
        "cookie_secure": True,      # send the Secure flag; set false ONLY for plain-HTTP dev/LAN
        "cookie_max_age_seconds": 2592000,   # session lifetime (30 days)
        "trusted_proxy_networks": [],  # CIDRs whose X-Real-IP is trusted
        "max_connections": 32,      # max simultaneous handler threads; extra connections get 503
        "request_timeout_seconds": 10,  # per-read socket timeout AND total time allowed to send a request
        "login_global_limit_per_minute": 60,  # login attempts per minute across ALL clients
    },
    "admin": {
        "compose_file": "",         # empty = /admin/restart disabled
        "compose_service": "",      # REQUIRED when compose_file is set: the only service restarted
        "restart_cooldown_seconds": 300,
        "stop_timeout_seconds": 60,
        "post_start_wait_seconds": 15,
        "restart_log": "",          # absolute path; empty = <data_dir>/admin-restart.log
    },
}


# key -> (kind, lo, hi).  kinds: str, bool, int (no floats/bools), num (int or
# float, finite), list (of str).  lo/hi are inclusive bounds for int/num.
SCHEMA = {
    "general": {
        "data_dir": ("str",), "container": ("str",), "server_name": ("str",),
        "player_display": ("str",), "steam_lookup": ("bool",),
        "steam_cache_file": ("str",), "steam_names_file": ("str",),
        "cpu_cores": ("int", 0, 4096), "stale_after_seconds": ("num", 1, 31_536_000),
        "reboot_marker_time": ("str",), "reboot_marker_label": ("str",),
        "max_csv_rows": ("int", 1000, 1_000_000),
    },
    "web": {
        "bind": ("str",), "port": ("int", 1, 65535), "cookie_name": ("str",),
        "cookie_domain": ("str",), "public_origin": ("str",), "cookie_secure": ("bool",),
        "cookie_max_age_seconds": ("int", 60, 31_536_000),
        "trusted_proxy_networks": ("list",),
        "max_connections": ("int", 1, 1024),
        "request_timeout_seconds": ("num", 1, 120),
        "login_global_limit_per_minute": ("int", 1, 10_000),
    },
    "admin": {
        "compose_file": ("str",), "compose_service": ("str",),
        "restart_cooldown_seconds": ("int", 0, 86_400),
        "stop_timeout_seconds": ("int", 1, 600),
        "post_start_wait_seconds": ("int", 0, 300),
        "restart_log": ("str",),
    },
}

_COOKIE_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_DOMAIN_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
_SERVICE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


def _check_value(section, key, value):
    spec = SCHEMA[section][key]
    kind, name = spec[0], f"{section}.{key}"
    if kind == "str":
        ok = isinstance(value, str)
    elif kind == "bool":
        ok = isinstance(value, bool)
    elif kind == "int":
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif kind == "num":
        ok = (isinstance(value, (int, float)) and not isinstance(value, bool)
              and math.isfinite(value))
    else:  # list of str
        ok = isinstance(value, list) and all(isinstance(v, str) for v in value)
    if not ok:
        raise ValueError(f"{name} must be of type {kind}, got {value!r}")
    if kind in ("int", "num") and not (spec[1] <= value <= spec[2]):
        raise ValueError(f"{name} must be between {spec[1]} and {spec[2]}, got {value!r}")


def parse_public_origin(value):
    """'https://host[:port]' -> (scheme, host, effective_port). ValueError if malformed."""
    try:
        u = urlsplit(value)
        port = u.port
    except ValueError:
        raise ValueError(f"web.public_origin is not a valid origin: {value!r}") from None
    if (u.scheme not in ("http", "https") or not u.hostname or u.path not in ("", "/")
            or u.query or u.fragment or u.username is not None):
        raise ValueError("web.public_origin must look like https://host[:port] (no path)")
    return u.scheme, u.hostname.lower(), port or (443 if u.scheme == "https" else 80)


def validate_config(cfg):
    """Raise ValueError on unknown sections/keys, wrong types or bad ranges."""
    for section, values in cfg.items():
        if section not in SCHEMA:
            raise ValueError(f"unknown config section [{section}]")
        if not isinstance(values, dict):
            raise ValueError(f"[{section}] must be a table")
        for key, value in values.items():
            if key not in SCHEMA[section]:
                raise ValueError(f"unknown config key {section}.{key}")
            _check_value(section, key, value)
    w, a = cfg["web"], cfg["admin"]
    if not _COOKIE_NAME_RE.fullmatch(w["cookie_name"]):
        raise ValueError("web.cookie_name must be 1-64 chars of A-Z a-z 0-9 _ -")
    if w["cookie_domain"] and not _DOMAIN_RE.fullmatch(w["cookie_domain"]):
        raise ValueError("web.cookie_domain must be empty or a plain hostname")
    if w["public_origin"]:
        parse_public_origin(w["public_origin"])
    if a["restart_log"] and not os.path.isabs(a["restart_log"]):
        raise ValueError("admin.restart_log must be empty or an absolute path")
    for n in w["trusted_proxy_networks"]:
        try:
            ipaddress.ip_network(n, strict=False)
        except ValueError:
            raise ValueError(f"web.trusted_proxy_networks: invalid CIDR {n!r}") from None
    if a["compose_file"]:
        if not a["compose_service"]:
            raise ValueError("admin.compose_service is required when admin.compose_file is set "
                             "(only that one service is stopped/started)")
        if not _SERVICE_RE.fullmatch(a["compose_service"]):
            raise ValueError("admin.compose_service is not a valid compose service name")
        if not os.path.isabs(a["compose_file"]):
            raise ValueError("admin.compose_file must be an absolute path")
    elif a["compose_service"]:
        raise ValueError("admin.compose_service is set but admin.compose_file is empty")


# ── Safe file helpers (shared by collector and web server) ──────────────────

def atomic_write(path, data, mode=0o640):
    """Write bytes/str to `path` atomically: exclusive random temp file in the
    same directory (never follows a pre-planted name), chmod, rename over the
    target. Refuses to write if `path` is a symlink."""
    if isinstance(data, str):
        data = data.encode()
    if os.path.islink(path):
        raise OSError(f"refusing to write through symlink: {path}")
    directory, base = os.path.split(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=base + ".", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), mode)
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _warn(msg):
    print(f"[enshrouded-monitor] WARNING: {msg}", file=sys.stderr, flush=True)


def enforce_fd_mode(fd, path, mode, what="file"):
    """Make the opened `fd` no more permissive than `mode` (special bits such as
    setgid are kept). If we own it we tighten it with fchmod. If someone else
    owns it we cannot: refuse when it is accessible by 'other', else warn."""
    st = os.fstat(fd)
    cur = stat.S_IMODE(st.st_mode)
    extra = cur & 0o777 & ~mode
    if not extra:
        return
    if st.st_uid == os.geteuid():
        os.fchmod(fd, cur & ~extra)
        return
    msg = (f"{what} {path} is owned by uid {st.st_uid} with mode {cur:04o} (wanted at most "
           f"{mode:04o}) and cannot be tightened by this account; fix with chown/chmod "
           f"(see README, 'Upgrading existing installs')")
    if extra & 0o007:
        raise PermissionError(msg)
    _warn(msg)


def safe_append(path, text, mode=0o640):
    """Append to `path` without following a symlink at the final component.
    An existing file must be a regular file; its mode is enforced via fstat/fchmod."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, mode)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {path}")
        enforce_fd_mode(fd, path, mode)
        with os.fdopen(fd, "a") as f:
            fd = -1
            f.write(text)
    finally:
        if fd >= 0:
            os.close(fd)


def ensure_dir(path, mode=0o750):
    """Create `path` (and parents) if missing, then enforce its mode through an
    O_DIRECTORY|O_NOFOLLOW descriptor (see enforce_fd_mode for non-owned dirs;
    for directories we only warn, never refuse)."""
    os.makedirs(path, mode=mode, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            enforce_fd_mode(fd, path, mode, what="directory")
        except PermissionError as e:
            _warn(str(e))
    finally:
        os.close(fd)


def safe_read(path):
    """Read a regular file's bytes without following a symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise OSError(f"not a regular file: {path}")
        return f.read()


def candidate_paths(environ=None):
    environ = os.environ if environ is None else environ
    explicit = environ.get("ENSHROUDED_MONITOR_CONFIG")
    if explicit:
        return [explicit]
    home = os.path.expanduser("~")
    return [os.path.join(home, ".config", "enshrouded-monitor", "config.toml"),
            "/etc/enshrouded-monitor/config.toml"]


def load_config(path=None, environ=None):
    """Return the merged, validated config dict. Sections merge over DEFAULTS;
    unknown sections/keys and wrong types/ranges raise ValueError."""
    cfg = {k: dict(v) for k, v in DEFAULTS.items()}
    environ = os.environ if environ is None else environ
    if path is None:
        explicit = environ.get("ENSHROUDED_MONITOR_CONFIG")
        for p in candidate_paths(environ):
            if os.path.isfile(p):
                path = p
                break
            if explicit:
                raise FileNotFoundError(f"ENSHROUDED_MONITOR_CONFIG points to missing file: {p}")
    if path:
        with open(path, "rb") as f:
            user = tomllib.load(f)
        for section, values in user.items():
            if section not in SCHEMA or not isinstance(values, dict):
                raise ValueError(f"unknown or malformed config section [{section}]")
            cfg[section].update(values)
    validate_config(cfg)
    g = cfg["general"]
    if g["player_display"] not in ("anonymous", "names"):
        raise ValueError('general.player_display must be "anonymous" or "names"')
    rmt = g.get("reboot_marker_time", "")
    if not isinstance(rmt, str) or (rmt != "" and not (
            re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", rmt))):
        raise ValueError('general.reboot_marker_time must be "" or a 24h "HH:MM" time (e.g. "02:30")')
    if not isinstance(g.get("reboot_marker_label", ""), str):
        raise ValueError("general.reboot_marker_label must be a string")
    g["data_dir"] = os.path.expanduser(str(g["data_dir"]))
    if g.get("steam_cache_file"):
        g["steam_cache_file"] = os.path.expanduser(str(g["steam_cache_file"]))
    if g.get("steam_names_file"):
        g["steam_names_file"] = os.path.expanduser(str(g["steam_names_file"]))
    return cfg


def classify_status(docker_state_output: str) -> str:
    """Map raw `docker inspect -f {{.State.Running}}` output to a status.

    "online"  - docker says Running=true
    "offline" - docker answered and the container is not running / missing
    "unknown" - docker gave no usable answer (hung, timed out, daemon down)
    """
    s = (docker_state_output or "").strip().lower()
    if s == "true":
        return "online"
    if s == "false" or "no such object" in s or "no such container" in s:
        return "offline"
    return "unknown"


def effective_status(live: dict, now: float, stale_after: float) -> str:
    """Status a viewer should see: 'stale' if the data is too old or has no
    usable timestamp, otherwise the recorded status."""
    try:
        age = now - float(live.get("updated_epoch"))
    except (TypeError, ValueError):
        return "stale"
    if age > stale_after or age < -60:
        return "stale"
    status = live.get("status")
    if status in ("online", "offline", "unknown"):
        return status
    return "online" if live.get("online") is True else "unknown"
