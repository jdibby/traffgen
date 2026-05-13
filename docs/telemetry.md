# Telemetry — what's collected, why, and how to opt out

Traffgen can optionally send anonymous usage counters back to a public
Cloudflare Worker.  These numbers power the "Project Activity" tile on the
dashboard and let the project show that it's actively used.

**Telemetry is OPT-IN.**  It is **off by default**.  Nothing is sent unless
you explicitly enable it.  This page exists so you can review exactly what
would be sent before turning it on.

---

## How to enable / disable

**Enable on the CLI:**
```bash
docker run ... jdibby/traffgen:latest --suite=all --size=S --loop --telemetry
```

**Enable via environment variable** (useful with `--restart` and orchestrators):
```bash
docker run -e TRAFFGEN_TELEMETRY=1 ... jdibby/traffgen:latest ...
```

**Disable** (default): omit the flag, or set `TRAFFGEN_TELEMETRY=0`.

**Enable from the web dashboard:** *Settings → Telemetry → Enable.*  This
restarts the container with `--telemetry`.

---

## What's collected

Two endpoints receive data, both over HTTPS:

### 1. `POST /v1/install` — sent **once** per container at startup

```json
{
  "install_id": "550e8400-e29b-41d4-a716-446655440000",
  "version":    "3.9.3",
  "arch":       "amd64",
  "os":         "ubuntu"
}
```

| Field | Source | Notes |
|---|---|---|
| `install_id` | Generated once on first run, persisted to `/var/lib/traffgen/install_id` | Random UUIDv4. Not derived from hostname, MAC, IP, or anything identifying. Delete the file to reset. |
| `version`    | `VERSION` constant in `generator.py` | e.g. `3.9.3` |
| `arch`       | `uname -m` mapped to `amd64`/`arm64`/`arm/v7`/`other` | — |
| `os`         | Detected from `/etc/os-release` ID field | One of `ubuntu`, `debian`, `rocky`, `rpi`, `alpine`, `other` |

### 2. `POST /v1/heartbeat` — sent every ~5 minutes while running

```json
{
  "install_id":              "550e8400-e29b-41d4-a716-446655440000",
  "version":                 "3.9.3",
  "tests_run_delta":         12,
  "runtime_seconds_delta":   298,
  "by_suite":                { "dns": 4, "https": 3, "icmp": 5 }
}
```

| Field | Notes |
|---|---|
| `tests_run_delta` | Number of suite tests completed since the previous heartbeat |
| `runtime_seconds_delta` | Wall-clock seconds the container has been running since the previous heartbeat |
| `by_suite` | Per-suite test counts since the previous heartbeat |

That's it.  **No probe results, no target URLs, no response codes, no test
output, no configuration flags (size, max-wait, etc.), no IP addresses,
no hostnames, no network info, no credentials, no logs.**

---

## What the server stores

Cloudflare automatically logs the source IP at the edge.  The Worker:

- **Never stores raw IPs in the database.**
- For abuse-rate-limiting only, the IP is SHA-256 hashed with a salt that
  rotates every 24 hours.  The hash is stored in a per-day counter row that
  is wiped daily by the cron job.  After 24 hours the hash is meaningless
  even to the server.
- Records `cf.country` (ISO-3166-1 alpha-2, e.g. `US`, `DE`) — country
  only, no city, no geo coords.

The full server-side schema is in
[`worker/schema.sql`](../worker/schema.sql) — it's a few dozen lines of
SQLite.  You can read every column it stores.

---

## What gets shown publicly

`GET https://traffgen-stats.<account>.workers.dev/v1/stats` returns
aggregated, non-identifying JSON.  Example:

```json
{
  "generated_at": 1715000000,
  "live_since":   "2026-05-13",
  "project": { "started_at": "2023-01-15", "age_days": 1200, "releases": 42, "commits": 1500 },
  "docker":  { "pulls": 38201, "pulls_24h_delta": 120 },
  "installs":{ "lifetime": 1247, "active_24h": 83, "active_7d": 210, "active_30d": 450, "running_now": 31 },
  "tests":   { "ran_total": 4203412 },
  "runtime": { "total_seconds": 98765432, "human": "3.1 years" },
  "versions":[ { "version": "3.9.3", "count": 220, "pct": 71 } ]
}
```

These are the only numbers any visitor sees.  Individual install_ids are
**never** exposed.

---

## Failure modes are silent

Telemetry must **never** affect the container's actual job (generating
traffic).  The client:

- Uses a 2-second connect and 2-second read timeout.
- Runs every HTTP call in a background daemon thread.
- Catches every exception and drops the failure silently.
- Performs no retries.

If the Worker is down, slow, blocked by a firewall, or misconfigured, the
container behaves exactly as if telemetry were disabled.

---

## Reset / forget an install

The install_id lives at `/var/lib/traffgen/install_id` inside the
container.  Delete the file (or the volume) and you'll get a fresh UUID
on the next run.  The previous row stays in the server's `installs`
table but is uncorrelated with the new one and will age out of the
`active_30d` window after 30 days.

---

## Where the code lives

- **Client (Python):** the `_telemetry` block in
  [`generator.py`](../generator.py).
- **Server (Cloudflare Worker, TypeScript):** [`worker/src/index.ts`](../worker/src/index.ts).
- **D1 schema (SQLite):** [`worker/schema.sql`](../worker/schema.sql).

Pull requests welcome if you spot anything that should be tightened.
