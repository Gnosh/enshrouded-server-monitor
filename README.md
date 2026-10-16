# Enshrouded Monitor

A small, dependency-free (Python 3.11+ stdlib only) status monitor for an
Enshrouded dedicated server running in Docker.

- `enshrouded-monitor.py` - run every few minutes (systemd timer). Queries
  `docker inspect/stats/logs` for the game container, parses the server log
  (players, pings, entities, tick time, save sizes) and writes `live.json`,
  `metrics.csv` and a static `index.html` dashboard into `data_dir`.
- `enshrouded-monitor-web.py` - password-protected HTTP server for those files,
  plus an optional token-protected `POST /admin/restart`.

## Status semantics

Every reading has a status, shown as a badge on the page and in `live.json`:

| status    | meaning |
|-----------|---------|
| `online`  | Docker reports the container Running. |
| `offline` | Docker answered and the container is stopped or missing. |
| `unknown` | Docker gave no usable answer (hung, timed out, daemon down). |
| `stale`   | The reading is older than `stale_after_seconds` (monitor stopped running), or has no timestamp. |

`/live.json` computes staleness at request time; the static page checks it in
the browser against the viewer's own clock.

## Install

```sh
sudo install -d /opt/enshrouded-monitor
sudo cp src/* /opt/enshrouded-monitor/        # keep all files together
sudo install -d /etc/enshrouded-monitor
sudo cp config.example.toml /etc/enshrouded-monitor/config.toml   # then edit
```

Then create the units from `deploy/systemd-units.reference.txt`.

## Configuration

Config file lookup (first match wins; defaults are used if none exists):

1. `$ENSHROUDED_MONITOR_CONFIG` (error if it points to a missing file)
2. `~/.config/enshrouded-monitor/config.toml`
3. `/etc/enshrouded-monitor/config.toml`

See `config.example.toml` for every option. To mark a daily restart on the chart, set `reboot_marker_time = "02:30"` (24h `HH:MM`, in the viewer's browser-local time) under `[general]`; `reboot_marker_label` (default `reboot`) is drawn as plain text after the time. The default empty time draws no marker. Never commit your real config.
`steam_names_file` may point to a JSON file `{"<steam id>": "Name"}` kept
outside the repo.

## Player display

`player_display` controls how connected players appear on the page and in `live.json`:

- `"anonymous"` (default): generic labels `Player 1`, `Player 2`, ... in connection order.
- `"names"`: real names, taken only from the JSON file at `steam_names_file`
  (`{"<steam id>": "Name"}`). Players missing from the file still get `Player N`.

Optionally, `steam_lookup = true` (default `false`, only used in `"names"` mode) fetches a player's
public Steam display name from steamcommunity.com for IDs not in the mapping file. Results are cached in
`steam_cache_file` (default `<data_dir>/steam_names.json`). Lookups have a 5 second timeout, at most 3
new fetches per run, and any failure just falls back to `Player N`, so the monitor loop is never blocked.
In `"anonymous"` mode no lookup is ever made.

**Privacy:** enabling `"names"` (with or without lookup) shows players' Steam display names to everyone
who can open the page. Keep the web UI behind authentication (it is by default) and leave this off unless
players are fine with it. Default is off.

Steam IDs are never written to `live.json` or the page in either mode, and names are plain text (no
profile links).

## Secrets (environment variables only)

| variable | purpose |
|----------|---------|
| `ENSHROUDED_SHARED_PASSWORD` | Password for the status page (required by the web server). |
| `ENSHROUDED_ADMIN_TOKEN` | Bearer token for `POST /admin/restart` (required only if `[admin] compose_file` is set). Must differ from the password (startup fails otherwise). |
| `ENSHROUDED_COOKIE_SECRET` | Optional, >= 32 chars. Session-cookie signing key; if unset a random key is used per process start (sessions end on restart). Must differ from the password and token. |

Put them in a root-only `EnvironmentFile` (mode 0600). Never in the config file or the repo.

## Tests

No Docker or network needed:

```sh
python3 -I -m unittest
```

## Security

Threat model: the web UI is a small shared-password page, possibly internet-facing behind a
reverse proxy. What the code does:

- **Sessions**: HMAC-signed, stateless cookie. The signing key is independent of the password:
  `ENSHROUDED_COOKIE_SECRET` if set (>= 32 chars), otherwise a random key generated at each start
  (sessions then end when the service restarts - this is intentional and safe). Cookies are
  `HttpOnly; SameSite=Lax; Secure`, host-only unless `cookie_domain` is set, and last
  `cookie_max_age_seconds` (30 days by default). `cookie_secure = false` exists for plain-HTTP
  dev/LAN only and prints a startup warning. Logout only clears the browser cookie; a copied cookie
  stays valid until it expires or the signing key changes (restart without a fixed secret).
  A cookie issued by another service that signs with the old password-based scheme is not accepted.
- **Brute force**: every login (and admin) attempt is reserved atomically before the body is read, so
  concurrent guesses from one client are impossible. The reservation is owned by a token, lives until
  the request's absolute deadline (plus a few seconds), and only its owner releases it. A failed attempt
  starts a 30 s cooldown for the client IP when verification finishes, and
  `login_global_limit_per_minute` caps attempts across all clients. The lockout table is bounded and
  evicts the oldest entry when full (it never stops locking). IPs are canonicalised.
  The proxy must **overwrite** `X-Real-IP` and `trusted_proxy_networks` must list only that proxy.
- **Slowloris**: the whole request (request line, headers and body) must arrive within
  `request_timeout_seconds`. The deadline is enforced inside every socket receive (the timeout is
  recomputed as min(time left, per-read timeout) before each `recv`), so dribbling bytes cannot extend
  it. At most `max_connections` handler threads exist; extra connections receive `503`. The
  deadline covers reading the request only, not a long-running `/admin/restart`. Keep your proxy's
  timeouts as well.
- **CSRF**: login and logout are `POST`-only and reject cross-site requests. `Sec-Fetch-Site` decides
  when the browser sends it. Otherwise an `Origin` header must match scheme, host and effective port of
  `[web] public_origin` (recommended, e.g. `"https://status.example.com"`). If that is unset, `Origin`
  must match the `Host` header (host and port), and the scheme must also match `X-Forwarded-Proto`
  when the request comes from a `trusted_proxy_networks` peer (the header is ignored from anyone
  else). Non-browser clients that send neither header are accepted; they are covered by the
  password and rate limits, not by CSRF checks.
- **Caching**: every response carries `Cache-Control: no-store`.
- **Files**: collector output is written atomically to exclusive temp files, never through a
  symlink, with mode 0640 (Steam name cache 0600) and umask 027. Appended files (CSV, restart log) are
  checked with `fstat` on the opened descriptor: they must be regular files, and a mode more permissive
  than 0640 is tightened with `fchmod` when the running account owns the file. If another account
  owns it, the write is refused when it is accessible by "other" and a warning is logged when only the
  group is too permissive. The data directory is tightened to 0750 (setgid kept) the same way. Run the
  collector, dashboard and admin instance as three different accounts (see the units file).
- **XSS**: chart data is embedded with script-safe JSON, CSV timestamps and numbers are validated.
  The CSP still allows inline scripts (the dashboard is one generated file); the only remaining
  inline-script input is data written by the collector account, so protect write access to `data_dir`.
- **Admin restart** (`POST /admin/restart`, bearer token, disabled by default): restarts only
  `[admin] compose_service`, one restart at a time, then checks the container is running/healthy.
  `updateApplied` is `true` only when the log proves an update, otherwise `null` (unknown).
  **Implication:** the process that runs `docker compose` has Docker access, which is equivalent to
  root on the host. Do not enable it on the instance that serves the dashboard unless you accept
  that; the preferred setup is a separate, loopback-only privileged instance (see the units file)
  that your proxy exposes for `POST /admin/restart` only, running under its OWN Unix account (not the
  dashboard's: processes of one account can read each other's memory and environment) and writing
  its log to its own directory via `[admin] restart_log`. The admin token must differ from the
  password (checked at startup).
- Use a separate, strong, unique password and token. Supply them only via environment variables.
- Not covered: TLS, per-user accounts, audit logging, or revoking individual sessions. Do not
  expose the backend port directly; firewall it and bind to `127.0.0.1`.

### Upgrading existing installs (ownership and modes)

Older versions created files with the default mode, and `open()` never changes the mode of a file that
already exists. After upgrading, check once (paths are examples):

```sh
sudo chown -R enshrouded-collector:enshrouded-monitor /var/lib/enshrouded-monitor
sudo chmod 2750 /var/lib/enshrouded-monitor
sudo find /var/lib/enshrouded-monitor -type f -exec chmod 0640 {} +
sudo chmod 0600 /var/lib/enshrouded-monitor/steam_names.json 2>/dev/null || true
# Old restart log in the data dir: move it to the admin account's own directory
sudo install -d -o enshrouded-admin -g enshrouded-admin -m 0750 /var/lib/enshrouded-monitor-admin
sudo mv /var/lib/enshrouded-monitor/admin-restart.log /var/lib/enshrouded-monitor-admin/ 2>/dev/null || true
sudo chown enshrouded-admin:enshrouded-admin /var/lib/enshrouded-monitor-admin/admin-restart.log 2>/dev/null || true
```

and set `restart_log = "/var/lib/enshrouded-monitor-admin/admin-restart.log"` in the admin instance's
config. If you keep running everything as one account, nothing breaks: the code tightens modes of
files that account owns, and just warns for files it cannot fix.

### Deploying behind HTTPS reverse proxy

Terminate TLS at the proxy, keep the backend on `127.0.0.1:8083`, and make the proxy enforce
timeouts, body limits and overwrite the client IP header. Example nginx:

```nginx
limit_req_zone $binary_remote_addr zone=emon:1m rate=30r/m;

server {
    listen 443 ssl;
    http2 on;
    server_name status.example.com;
    # ssl_certificate / ssl_certificate_key ...

    client_header_timeout 10s;
    client_body_timeout   10s;
    send_timeout          15s;
    client_max_body_size  4k;          # the login form is tiny
    large_client_header_buffers 4 8k;

    location / {
        limit_req zone=emon burst=20 nodelay;
        proxy_pass http://127.0.0.1:8083;
        proxy_set_header Host            $host;
        proxy_set_header X-Real-IP       $remote_addr;   # OVERWRITES any client-supplied value
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout    15s;
        proxy_connect_timeout 3s;
        proxy_cache off;               # never cache authenticated responses
    }

    # Only if you run the privileged restart instance (separate port, e.g. 8084):
    # location = /admin/restart { limit_except POST { deny all; }
    #     proxy_pass http://127.0.0.1:8084; proxy_read_timeout 150s;
    #     proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr; }
}
```

Set `trusted_proxy_networks = ["127.0.0.1/32"]` (the proxy's address as seen by the backend),
`public_origin = "https://status.example.com"`, leave `cookie_secure = true`, and redirect port 80
to HTTPS.

## License

MIT
