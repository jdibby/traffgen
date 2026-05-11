# Web Dashboard

Traffgen includes a built-in HTTPS monitoring dashboard on **port 7777**. It starts automatically with the container — no configuration required.

```
https://<host-ip>:7777
```

The dashboard uses a self-signed TLS certificate generated at startup. Your browser will show a certificate warning — click **Advanced → Proceed** (Chrome) or **Accept the Risk** (Firefox) to continue.

---

## Authentication

The dashboard requires a login on every visit.

### Initial credentials

On the **first container start**, traffgen generates a random password and prints it **once** to the container logs:

```
docker logs traffgen
```

Look for the credentials block:

```
==========================================================
  traffgen dashboard — initial credentials
  Username : traffadmin
  Password : <generated>
  You will be prompted to set a new password on first login.
  To reset credentials, remove and recreate the container.
==========================================================
```

If you deployed with `stager.sh`, the credentials are extracted from the container logs and displayed directly in the terminal at the end of installation — no need to run `docker logs` separately.

### First login

After signing in with the generated password you are immediately redirected to a **Set your password** page. Enter a new password (minimum 8 characters) and confirm it. This is the only time in-app password change is available.

### Password reset

There is no in-app reset. If you forget your password:

1. Remove the container: `docker rm -f traffgen`
2. Re-run your original `docker run` or `stager.sh` command
3. A new password is generated and printed to the logs on the next first start

---

## Enabling the Dashboard

Add `-p 7777:7777` to your `docker run` command, or use `--network=host` (Linux only) to also enable `lateral-movement` LAN scanning:

```bash
# Port mapping only
docker run --pull=always --detach --restart unless-stopped \
  -p 7777:7777 --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop

# Full host network (Linux only — enables lateral movement + host IP display)
docker run --pull=always --detach --restart unless-stopped \
  --network=host --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop
```

If deployed via `stager.sh`, port 7777 is opened automatically and the dashboard URL is printed at the end of installation.

---

## Layout

The dashboard has a **dark sidebar** on the left with navigation, and a main content area on the right.

**Topbar** (always visible across all pages):
- **Page title** — current page name on the left
- **Host LAN IP** — the physical host's IP address (when available), so you can identify which device you're looking at when running multiple instances
- **Active test pill** — currently running suite name with emoji icon and pulse dot, always centered in the topbar
- **suite/size pills** — current configuration at a glance
- **Status pill** — `Running` (pulse dot), `Between Tests (Ns)` with countdown, `Paused`, or `Stopped`
- **Controls** — pause ⏸, stop ⏹, settings ⚙, theme toggle ☾, LIVE indicator

---

## Dashboard Tabs

### Overview

The main at-a-glance view:

- **Stat cards** — Total Requests, Success Rate, Active Test, Iteration count
- **Network I/O sparkline** — live bandwidth in Mbps, 1-second default refresh with selectable interval (1s / 5s / 10s / 30s)
- **Success/Failure donut** — outcome distribution chart
- **Requests-over-time sparkline** — rolling request rate over the last N samples
- **Per-test breakdown table** — each suite with attempt/ok/fail counts and a colour-coded success bar
- **LIVE EVENTS feed** — real-time event stream: timestamp · suite · message · outcome, with level colouring (✔ OK green, ✗ Error red, ⚠ Warn yellow)

### Security

Dedicated security posture page modeled on NGFW/SASE dashboards:

- **KPI cards** — Total Probes · Blocked · Silently Dropped · Allowed
- **Outcome distribution donut** — visual allowed/blocked/dropped breakdown
- **Block & Drop Trend** — sparkline of block% and drop% over time; hover over any data point to see exact values
- **Per-suite security breakdown table** — sorted by blocked count; shows each suite's allowed/blocked/dropped/failed counts
- **Block signal breakdown** — exactly how controls are signalling blocks: HTTP 403 block page, TCP RST, proxy refused, TLS intercept, DNS sinkhole, timeout
- Configurable refresh interval (default 1 min; 30 s–5 min)

### Tests

Card grid for every available suite:

- Each card shows: suite name with emoji icon, description tooltip on hover, attempt/ok/fail counters, and a colour-coded success bar
- **Click any card** to launch that suite immediately — a modal lets you set size, confirm, and the generator switches to that suite at the next test boundary
- Auto-navigates to Live View when you click Run

### Live View

CLI-style live log mirroring terminal output:

- **Level colours**: ✔ OK (green), ✗ Error (red), ⚠ Warn (amber), — Info/Debug (dim)
- **Automatic level classification** — connection errors, timeouts, "no links found", and HTTP 4xx/5xx responses are automatically tagged `WARN` or `ERROR` rather than `INFO`, so failures stand out without manual filtering
- **User-Agent condensing** — long `Mozilla/5.0 ...` UA strings in log lines are condensed to compact labels (e.g. `[Chrome/130/Android 14]`) to prevent wrapping
- **Sub-result indentation** — follow-up detail lines prefixed with `↳` are indented proportionally, matching the visual nesting shown in the terminal
- Section banners and rule separators matching terminal format
- **Filter** by level (OK / Warn / Error / Info)
- **Auto-scroll** — follows new output; scroll up to review history without breaking auto-scroll
- **Clear** — wipe the current log buffer
- **Pop Out** — open the live log in a standalone browser window

### Health

System resource monitoring:

- **CPU / Memory gauges** — current utilisation with colour thresholds
- **Load average** — 1/5/15 minute load
- **Disk I/O bars** — read/write activity per device
- **Network sparkline** — live Mbps (same as Overview)
- **Network Info widget** — interface table showing name, IP, MAC, speed, MTU, and link state; Host LAN IP and Public IP displayed in the header; virtual/bridge interfaces (veth*, docker*, br-*) filtered out
- **Top processes table** — CPU and memory usage per process, sampled every 2 seconds

### About

Version info, suite count, and architecture details.

---

## Controls

### Settings Drawer

Click the **⚙** icon in the sidebar or topbar. From the drawer you can change:

- **Suite** — dropdown lists all available suites with descriptions
- **Size** — traffic volume (`XS` → `XL`)
- **Max wait** — seconds between tests (5–300 s slider)
- **Loop mode** — run indefinitely vs. single pass
- **No wait** — disable all inter-test pauses

Click **Apply & Restart** to write the new settings. The generator detects the change at the next test boundary and restarts automatically — no container restart needed.

### Pause / Resume / Stop

- **Pause** (⏸) — suspends between-test scheduling; the current test completes before pausing
- **Resume** — continues from where it paused
- **Stop** (⏹) / **LIVE pill** — stops all tests immediately; click **LIVE** in the topbar as a shortcut

---

## Features

### Draggable Widgets

Widgets on the Overview, Security, and Health pages can be dragged to reorder. Grab the **⠿** handle in any widget's header and drag it to a new position. Order is saved to `localStorage` and restored on next load.

### Suite Name Tooltips

Hover over any suite name anywhere in the dashboard to see its full description in a tooltip.

### Chart Hover Values

Hover over any sparkline or trend chart — Overview sparklines, Block & Drop Trend — to see exact values at any data point.

### Dark / Light Mode

Click the **☾** button in the topbar. Preference is saved to `localStorage` and restored automatically.

### Multi-user

The first browser tab to connect gets full control. Additional tabs are **read-only** with a visible banner — they can monitor but cannot change settings or control tests.

---

## Security Design

The dashboard requires authentication for every page and API call. Sessions are tied to the server process — restarting the container invalidates all active sessions. All responses include security headers (`CSP`, `X-Frame-Options`, `HSTS`, etc.).

Passwords are stored as PBKDF2-HMAC-SHA256 hashes (260 000 iterations, per-install random salt) in `/tmp/traffgen_auth.json` inside the container. The file is `chmod 600` and is lost when the container is removed, which is the intended credential-reset mechanism.

> If you do not want the dashboard exposed, omit the `-p 7777:7777` flag. The dashboard still runs inside the container but is not reachable from outside.
