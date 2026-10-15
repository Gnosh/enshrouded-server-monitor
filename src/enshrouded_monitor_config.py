"""Shared configuration loader for the Enshrouded monitor scripts.

Lookup order for the config file (first existing wins):
  1. $ENSHROUDED_MONITOR_CONFIG   (explicit path; error if it does not exist)
  2. ~/.config/enshrouded-monitor/config.toml
  3. /etc/enshrouded-monitor/config.toml
If none exist, built-in defaults are used.  Secrets are NEVER read from the
config file; they come from environment variables only.
"""
import os
import re
import tomllib

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
    },
    "web": {
        "bind": "127.0.0.1",
        "port": 8083,
        "cookie_name": "enshrouded_session",
        "cookie_domain": "",        # empty = host-only cookie, no Secure flag
        "trusted_proxy_networks": [],  # CIDRs whose X-Real-IP is trusted
    },
    "admin": {
        "compose_file": "",         # empty = /admin/restart disabled
        "restart_cooldown_seconds": 300,
        "stop_timeout_seconds": 60,
        "post_start_wait_seconds": 15,
    },
}


def candidate_paths(environ=None):
    environ = os.environ if environ is None else environ
    explicit = environ.get("ENSHROUDED_MONITOR_CONFIG")
    if explicit:
        return [explicit]
    home = os.path.expanduser("~")
    return [os.path.join(home, ".config", "enshrouded-monitor", "config.toml"),
            "/etc/enshrouded-monitor/config.toml"]


def load_config(path=None, environ=None):
    """Return the merged config dict. Unknown keys are kept; sections merge."""
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
            if isinstance(values, dict):
                cfg.setdefault(section, {}).update(values)
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
