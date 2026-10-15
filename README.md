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

See `config.example.toml` for every option. Never commit your real config.
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
| `ENSHROUDED_ADMIN_TOKEN` | Bearer token for `POST /admin/restart` (required only if `[admin] compose_file` is set). Keep it different from the password. |

Put them in a root-only `EnvironmentFile` (mode 0600). Never in the config file or the repo.

## Tests

No Docker or network needed:

```sh
python3 -I -m unittest
```

## Security notes

- The web server speaks plain HTTP. Bind to `127.0.0.1` (the default) and put a TLS reverse proxy
  in front, or restrict access with a firewall. Set `cookie_domain` only when served over HTTPS.
- Set `trusted_proxy_networks` to your proxy's network only; `X-Real-IP` is trusted solely from there
  and is used for the failed-login lockout.
- Failed logins lock out the client for 30 seconds. There is no TLS, user accounts or rate limiting
  beyond this; do not expose it directly to the internet.
- `/admin/restart` runs `docker compose` as the web server's user, which effectively needs Docker
  access. Leave `compose_file` empty to disable it.
- Use a separate, strong, unique password for `ENSHROUDED_SHARED_PASSWORD`. Do not reuse the game
  server's password (or any other password) for the web UI. Setting up the password and token is
  your responsibility; supply them only through environment variables.

## License

MIT
