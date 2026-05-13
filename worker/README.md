# traffgen-stats — Cloudflare Worker

Public, free-tier telemetry endpoint that powers the project-activity numbers
shown on the traffgen dashboard. Receives anonymous counters from running
containers (opt-in) and exposes a cached JSON feed for display.

> **All telemetry is opt-in.** No data is sent unless the user passes
> `--telemetry` or sets `TRAFFGEN_TELEMETRY=1`.  Container behaviour is
> unaffected by Worker availability — every HTTP call from the client is
> fire-and-forget with a 2-second timeout.  See `../docs/telemetry.md` for
> the data dictionary.

---

## What's deployed

| Piece | What it is | Free-tier limit |
|---|---|---|
| Worker | This `src/index.ts` — request handler + daily cron | 100k req/day |
| D1 database | SQLite, schema in `schema.sql` | 5 GB / 5M reads/day / 100k writes/day |
| Cron trigger | Daily roll-up, Docker Hub refresh | unlimited |

Total cost: **$0**.

---

## One-time setup

You only need to do these once.

```bash
# 1. Install Wrangler on your laptop (Node 18+ required)
npm install -g wrangler

# 2. Authenticate (opens browser → click Allow)
wrangler login

# 3. Create the D1 database (from this directory)
cd worker/
wrangler d1 create traffgen-stats
#    ↑ copy the printed `database_id` into wrangler.toml

# 4. Apply the schema
wrangler d1 execute traffgen-stats --remote --file=./schema.sql

# 5. Deploy
wrangler deploy
#    ↑ prints the public URL, e.g.
#      https://traffgen-stats.<your-account>.workers.dev
```

Copy that URL — you'll plug it into `generator.py` and `webui.py` in the next
section.

---

## Seed values (hybrid approach)

The dashboard mixes real, verifiable numbers (Docker pulls, project age,
release count) with live counters (tests run, runtime, installs).  Live
counters start at 0 by design; the verifiable numbers carry the
"years-of-running" story from day one.

Set the seeds **once**, after the first deploy:

```bash
# Project start date (date of first commit on main)
wrangler d1 execute traffgen-stats --remote --command \
  "INSERT OR REPLACE INTO seed(key,value) VALUES('project_started_at','2023-01-15');"

# Label live counters with their start date
wrangler d1 execute traffgen-stats --remote --command \
  "INSERT OR REPLACE INTO seed(key,value) VALUES('live_since','$(date -u +%F)');"

# (optional) bake a one-time historical baseline so live tiles start non-zero
wrangler d1 execute traffgen-stats --remote --command \
  "INSERT OR REPLACE INTO seed(key,value) VALUES('baseline_tests','4000000');"
wrangler d1 execute traffgen-stats --remote --command \
  "INSERT OR REPLACE INTO seed(key,value) VALUES('baseline_runtime','98000000');"
```

Release count and commit count refresh automatically from GitHub on the
daily cron.  Docker pull count refreshes daily from the Docker Hub API.

---

## Wire the URL into traffgen

After `wrangler deploy`, take the printed URL and:

1. Edit `generator.py` → set `_TELEMETRY_URL` constant near the top, **or**
   build with `TRAFFGEN_TELEMETRY_URL` env var (the Dockerfile passes it
   through).
2. Edit `webui.py` → set `_TELEMETRY_PUBLIC_URL` constant for the dashboard
   "Project Activity" tile.

Both default to empty string; when empty, the client and dashboard tile
simply do nothing.  The container runs identically with or without
telemetry configured.

---

## Endpoints

| Route | Method | Auth | Body | Returns |
|---|---|---|---|---|
| `/v1/install`   | POST | none | `{install_id, version, arch, os}` | `{ok, new}` |
| `/v1/heartbeat` | POST | none | `{install_id, version, tests_run_delta, runtime_seconds_delta, by_suite}` | `{ok}` |
| `/v1/stats`     | GET  | none | — | aggregated JSON, cached 60s |
| `/`             | GET  | none | — | health |

All endpoints are unauthenticated by design — see the security section.

---

## Security & abuse handling

- **No client auth.** Telemetry endpoints are public; client source is
  public, so a shared secret would be visible.  Same model as Plausible /
  Sentry / Cloudflare Web Analytics.
- **Per-IP rate limit on new installs** — capped at
  `MAX_NEW_INSTALLS_PER_IP_DAY = 5`.  IPs are SHA-256 hashed with a daily
  salt; raw IPs are never stored.
- **Heartbeat cooldown** of 4 minutes per install_id — silently throttled
  to prevent counter inflation.
- **Sanity caps** on every numeric field
  (`MAX_TESTS_PER_HEARTBEAT = 10_000`, `MAX_RUNTIME_PER_HEARTBEAT_S = 86_400`).
- **Schema-validated inputs** — version/arch/suite values rejected if they
  don't match expected patterns.
- **CORS open to `*`** so the dashboard can read `/v1/stats` from any
  origin.  No state-changing endpoint is reachable via `GET`.

---

## Local development

```bash
wrangler d1 create traffgen-stats-dev          # one-time
wrangler d1 execute traffgen-stats-dev --local --file=./schema.sql
wrangler dev                                   # http://localhost:8787
```

---

## Inspecting the data

```bash
# Lifetime tests
wrangler d1 execute traffgen-stats --remote --command \
  "SELECT * FROM counters;"

# Suite leaderboard
wrangler d1 execute traffgen-stats --remote --command \
  "SELECT suite, count FROM suite_counts ORDER BY count DESC LIMIT 20;"

# Active installs in last 24h
wrangler d1 execute traffgen-stats --remote --command \
  "SELECT COUNT(*) FROM installs WHERE last_seen > strftime('%s','now')-86400;"
```

---

## Tearing it down

```bash
wrangler delete                       # removes the Worker
wrangler d1 delete traffgen-stats     # removes the database
```
