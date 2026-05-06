# Web Dashboard

Traffgen includes a built-in HTTPS monitoring dashboard available on **port 7777** when the container is running with `-p 7777:7777`.

```
https://<host-ip>:7777
```

The dashboard uses a self-signed TLS certificate generated at startup. Your browser will show a certificate warning the first time — this is expected. Click **Advanced → Proceed** (Chrome) or **Accept the Risk** (Firefox) to continue.

---

## Enabling the Dashboard

Add `-p 7777:7777` to your `docker run` command:

```bash
docker run --pull=always --detach --restart unless-stopped \
  -p 7777:7777 \
  --name traffgen jdibby/traffgen:latest \
  --suite=all --size=XS --max-wait-secs=20 --loop
```

If deployed via `stager.sh`, port 7777 is opened automatically and the dashboard URL is printed at the end of installation.

---

## Layout

The dashboard has a **dark sidebar** on the left with navigation, and a main content area on the right.

```
┌─────────────────┬──────────────────────────────────────────────────────┐
│  🚦 traffgen    │  [Page Title]   suite:all  size:XS  ● Running        │
│                 │                                         ⏸  ⏹  ⚙  LIVE│
│  MONITOR        ├──────────────────────────────────────────────────────┤
│  ◈ Overview     │                                                        │
│  ⚗ Tests        │              Main content area                        │
│  ⬛ Output       │                                                        │
│                 │                                                        │
│  SYSTEM         │                                                        │
│  ⚡ Health       │                                                        │
│                 │                                                        │
│  INFO           │                                                        │
│  ◎ About        │                                                        │
│                 │                                                        │
│  CONTROL        │                                                        │
│  ⚙ Settings     │                                                        │
│                 │                                                        │
│  version 1.x.x  │                                                        │
│  up 00:14:32    │                                                        │
└─────────────────┴──────────────────────────────────────────────────────┘
```

The **topbar** shows the current suite and size configuration, a status pill (Running / Paused / Stopped), and control buttons.

---

## Tabs

### Overview

The default landing page. Shows at a glance:

| Card | What it shows |
|------|---------------|
| Total Requests | Cumulative request count (OK + Fail) |
| Success Rate | % of successful requests, color-coded green/amber/red |
| Active Test | Currently running test name and elapsed time |
| Iteration | Current loop iteration number |

Below the cards:

- **Network I/O widget** — live TX/RX throughput (KB/s or MB/s) with a rolling sparkline chart. Updates every 2.5 seconds regardless of which tab is active.
- **Success / Failure donut chart** — proportion of OK vs failed requests since container start.
- **Requests Over Time sparkline** — historical OK/fail counts per sample window.
- **Test Breakdown table** — per-test attempt/OK/fail counts, success rate bar, and average duration. Click any row to expand HTTP status code details and response counts.
- **Live Events feed** — last 30 completed test results with timestamp, pass/fail indicator, and duration. Click an event row to expand code breakdown.

---

### Tests

Card grid showing every available test suite. Each card displays:

- Suite name and current status (RUNNING badge if active)
- Short description
- Attempt / OK / fail counts and success rate bar

Click any card to open a **Run Modal** where you can launch that specific suite with custom size, wait time, and loop settings — without restarting the container.

---

### Output

Live terminal-style log stream, identical to what `docker logs` shows. Features:

- **Level filters** — All / OK / Warn / Error / Debug buttons to hide noise
- **Test boundary separators** — a horizontal rule with the suite name is inserted each time the active test changes
- **Auto-scroll** toggle (on by default)
- **Clear** button
- **Pop Out** — opens the log in a separate browser window (`/log-view`)

Log lines are color-coded by level:

| Level | Color |
|-------|-------|
| OK    | Green |
| INFO  | Blue  |
| WARN  | Amber |
| ERROR | Red   |
| DEBUG | Dark grey |

---

### Health

Real-time container resource metrics sampled every 2 seconds from `/proc`:

| Widget | Source | Notes |
|--------|--------|-------|
| CPU gauge | `/proc/stat` | 270° arc speedometer; green < 65%, amber < 85%, red ≥ 85% |
| Memory gauge | `/proc/meminfo` | Shows used / total MB below the gauge |
| Load Average | `/proc/loadavg` | 1-minute · 5-minute · 15-minute |
| Disk I/O | `/proc/diskstats` | Read and write rate in KB/s or MB/s, horizontal bar chart |
| Network I/O | `/proc/net/dev` | Receive (green) and transmit (blue) with rolling sparkline |
| Top Processes | `/proc/[pid]/stat` | 12 processes sorted by CPU%, showing PID, name, CPU%, Mem%, RSS |

The Health tab starts polling the `/api/health` endpoint when opened and stops when you navigate away. The Network I/O widget on the Overview page runs continuously.

---

### About

Project information, links, quick-start commands, supported platforms, suite category table, and CLI flag reference.

---

## Settings Drawer

Click **⚙ Settings** in the sidebar or topbar to open the settings panel:

| Setting | Description |
|---------|-------------|
| Suite | Select which suite to run (`all` or a specific suite name) |
| Size | Traffic volume: XS / S / M / L / XL |
| Max Wait Between Tests | Seconds to pause between test completions (5–300) |
| Loop Mode | When enabled, cycles through suites indefinitely |
| No Wait | Skip all inter-test pauses |

Click **Apply & Restart** to write the new configuration. The generator picks it up at the next test boundary — the container does not restart.

---

## Pause and Stop

The topbar provides two control buttons:

| Button | Behavior |
|--------|----------|
| ⏸ Pause | Sends a pause signal. The current test runs to completion, then traffic generation halts. The status pill turns amber. Click again (now ▶) to resume. |
| ⏹ Stop | Sends a stop signal. After the current test finishes, the generator exits. Restart the container to resume. |

The green **● LIVE** pill in the topbar is also clickable — it acts as a shortcut to stop all tests. It turns red and shows **⏹ STOPPED** when halted.

---

## Security Notes

- The dashboard binds to `0.0.0.0:7777` inside the container. Restrict access with firewall rules or a reverse proxy if needed.
- The self-signed TLS certificate is generated fresh on each container start and stored in `/tmp/`.
- The API (`/api/control`) validates all inputs server-side. Suite names are checked against the live suite list; size must be one of XS/S/M/L/XL; wait time is clamped to 5–300 seconds.
- Standard security headers are applied to all responses (CSP, X-Frame-Options, HSTS, etc.).

---

## API Endpoints

The dashboard exposes a small HTTP API for automation:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/state` | GET | Full generator state as JSON |
| `/api/health` | GET | Container resource metrics (CPU, mem, disk, net, processes) |
| `/api/control` | POST | Change settings or send pause/resume/stop signals |
| `/events` | GET | SSE stream of state updates (used by the dashboard) |
| `/log` | GET | SSE stream of log lines (used by the Output tab) |

### POST /api/control — change settings

```json
{
  "suite": "dns",
  "size": "M",
  "max_wait_secs": 15,
  "loop": true,
  "nowait": false
}
```

### POST /api/control — send a signal

```json
{ "action": "pause" }
{ "action": "resume" }
{ "action": "stop" }
```

Responses are `{"ok": true}` on success or `{"error": "..."}` with a 4xx status on failure.
