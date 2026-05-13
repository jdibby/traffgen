/**
 * traffgen-stats — Cloudflare Worker
 *
 * Public, unauthenticated telemetry endpoint for the traffgen project.
 * Containers POST anonymous counters; visitors GET aggregated marketing stats.
 *
 *  POST /v1/install    one-shot identification at container start
 *  POST /v1/heartbeat  every ~5 min: liveness + batched test/runtime counters
 *  GET  /v1/stats      cached JSON for the dashboard / README badges
 *
 * Cron (daily): refresh Docker Hub pull count, recompute version + country
 * tallies, regenerate the /v1/stats cache, reset per-IP abuse counters.
 */

export interface Env {
  DB: D1Database;
  PROJECT_STARTED_AT: string;
  DOCKER_HUB_REPO: string;
  GITHUB_REPO: string;
  DOCKER_PULLS_SEED: string;
  RELEASES_SEED: string;
  COMMITS_SEED: string;
  BASELINE_TESTS: string;
  BASELINE_RUNTIME: string;
  CORS_ALLOW_ORIGIN: string;
}

// ── Limits / sanity caps ─────────────────────────────────────────────────────
const MAX_TESTS_PER_HEARTBEAT     = 10_000;
const MAX_RUNTIME_PER_HEARTBEAT_S = 86_400;     // 24h
const HEARTBEAT_MIN_INTERVAL_S    = 240;        // 4 min — clients send every 5
const MAX_NEW_INSTALLS_PER_IP_DAY = 5;
const STATS_CACHE_TTL_S           = 60;         // /v1/stats freshness
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VERSION_RE = /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/;
const ARCH_RE    = /^(amd64|arm64|arm\/v7|i386|other)$/;
const OS_RE      = /^[a-z0-9_-]{1,16}$/;
const SUITE_RE   = /^[a-z0-9_-]{1,32}$/;

// ── HTTP helpers ─────────────────────────────────────────────────────────────
function corsHeaders(env: Env): Record<string, string> {
  return {
    "access-control-allow-origin":  env.CORS_ALLOW_ORIGIN || "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age":       "86400",
  };
}

function json(body: unknown, status = 200, env?: Env, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...(env ? corsHeaders(env) : {}),
      ...extra,
    },
  });
}

function noContent(env: Env): Response {
  return new Response(null, { status: 204, headers: corsHeaders(env) });
}

// ── Crypto helpers ───────────────────────────────────────────────────────────
async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function todayUTC(): string {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
}

async function hashIp(ip: string): Promise<string> {
  // Daily-rotating salt makes the hash useless across days for re-identification.
  return (await sha256Hex(`${todayUTC()}:${ip}`)).slice(0, 32);
}

// ── Validation ───────────────────────────────────────────────────────────────
function clampInt(v: unknown, min: number, max: number): number {
  const n = typeof v === "number" ? v : parseInt(String(v), 10);
  if (!Number.isFinite(n) || isNaN(n)) return min;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

function safeStr(v: unknown, re: RegExp, fallback = ""): string {
  if (typeof v !== "string") return fallback;
  return re.test(v) ? v : fallback;
}

// ── Abuse caps ───────────────────────────────────────────────────────────────
async function consumeInstallSlot(env: Env, ipHash: string): Promise<boolean> {
  const today = todayUTC();
  const row = await env.DB.prepare(
    "SELECT count, date FROM abuse_installs_today WHERE ip_hash = ?",
  ).bind(ipHash).first<{ count: number; date: string }>();

  if (!row || row.date !== today) {
    await env.DB.prepare(
      "INSERT OR REPLACE INTO abuse_installs_today(ip_hash, count, date) VALUES(?, 1, ?)",
    ).bind(ipHash, today).run();
    return true;
  }
  if (row.count >= MAX_NEW_INSTALLS_PER_IP_DAY) return false;
  await env.DB.prepare(
    "UPDATE abuse_installs_today SET count = count + 1 WHERE ip_hash = ?",
  ).bind(ipHash).run();
  return true;
}

// ── POST /v1/install ─────────────────────────────────────────────────────────
async function handleInstall(req: Request, env: Env): Promise<Response> {
  let body: any;
  try { body = await req.json(); } catch { return json({ error: "bad_json" }, 400, env); }

  const id      = safeStr(body?.install_id, UUID_RE);
  if (!id)        return json({ error: "bad_install_id" }, 400, env);
  const version = safeStr(body?.version, VERSION_RE);
  const arch    = safeStr(body?.arch, ARCH_RE, "other");
  const osFam   = safeStr(body?.os, OS_RE, "other");
  const country = (req.cf as any)?.country ?? "";
  const now     = Math.floor(Date.now() / 1000);

  const existing = await env.DB.prepare("SELECT id FROM installs WHERE id = ?").bind(id).first();
  if (existing) {
    await env.DB.prepare(
      "UPDATE installs SET last_seen = ?, version = ?, arch = ?, os_family = ?, country = ? WHERE id = ?",
    ).bind(now, version, arch, osFam, country, id).run();
    return json({ ok: true, new: false }, 200, env);
  }

  // New install — apply per-IP abuse cap.
  const ip      = req.headers.get("cf-connecting-ip") ?? "";
  const ipHash  = await hashIp(ip);
  if (!(await consumeInstallSlot(env, ipHash))) {
    return json({ error: "rate_limited" }, 429, env);
  }

  await env.DB.prepare(
    `INSERT INTO installs(id, first_seen, last_seen, version, arch, os_family, country, created_ip_hash)
     VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(id, now, now, version, arch, osFam, country, ipHash).run();

  return json({ ok: true, new: true }, 200, env);
}

// ── POST /v1/heartbeat ───────────────────────────────────────────────────────
async function handleHeartbeat(req: Request, env: Env): Promise<Response> {
  let body: any;
  try { body = await req.json(); } catch { return json({ error: "bad_json" }, 400, env); }

  const id = safeStr(body?.install_id, UUID_RE);
  if (!id) return json({ error: "bad_install_id" }, 400, env);

  const version       = safeStr(body?.version, VERSION_RE);
  const testsDelta    = clampInt(body?.tests_run_delta,    0, MAX_TESTS_PER_HEARTBEAT);
  const runtimeDelta  = clampInt(body?.runtime_seconds_delta, 0, MAX_RUNTIME_PER_HEARTBEAT_S);
  const bySuite       = body?.by_suite && typeof body.by_suite === "object" ? body.by_suite : {};
  const now           = Math.floor(Date.now() / 1000);

  const inst = await env.DB.prepare(
    "SELECT last_seen FROM installs WHERE id = ?",
  ).bind(id).first<{ last_seen: number }>();

  if (!inst) {
    // Heartbeat without a prior install — be lenient: create the install row.
    const country = (req.cf as any)?.country ?? "";
    const ip      = req.headers.get("cf-connecting-ip") ?? "";
    const ipHash  = await hashIp(ip);
    if (!(await consumeInstallSlot(env, ipHash))) {
      return json({ error: "rate_limited" }, 429, env);
    }
    await env.DB.prepare(
      `INSERT INTO installs(id, first_seen, last_seen, version, arch, os_family, country, created_ip_hash)
       VALUES(?, ?, ?, ?, 'other', 'other', ?, ?)`,
    ).bind(id, now, now, version, country, ipHash).run();
  } else if (now - inst.last_seen < HEARTBEAT_MIN_INTERVAL_S) {
    // Cooldown: silently accept, don't apply counter deltas.
    return json({ ok: true, throttled: true }, 200, env);
  } else {
    await env.DB.prepare(
      "UPDATE installs SET last_seen = ?, version = COALESCE(NULLIF(?, ''), version) WHERE id = ?",
    ).bind(now, version, id).run();
  }

  if (testsDelta > 0 || runtimeDelta > 0) {
    await env.DB.prepare(
      `UPDATE counters
         SET tests_run       = tests_run + ?,
             runtime_seconds = runtime_seconds + ?,
             updated_at      = ?
       WHERE id = 1`,
    ).bind(testsDelta, runtimeDelta, now).run();
  }

  // Per-suite rollup.  Cap entries to prevent payload bloat.
  const suiteEntries = Object.entries(bySuite).slice(0, 64);
  for (const [rawSuite, rawCount] of suiteEntries) {
    const suite = safeStr(rawSuite, SUITE_RE);
    if (!suite) continue;
    const inc = clampInt(rawCount, 0, MAX_TESTS_PER_HEARTBEAT);
    if (inc === 0) continue;
    await env.DB.prepare(
      `INSERT INTO suite_counts(suite, count) VALUES(?, ?)
       ON CONFLICT(suite) DO UPDATE SET count = count + excluded.count`,
    ).bind(suite, inc).run();
  }

  return json({ ok: true }, 200, env);
}

// ── GET /v1/stats ────────────────────────────────────────────────────────────
async function readSeed(env: Env, key: string): Promise<string> {
  const row = await env.DB.prepare("SELECT value FROM seed WHERE key = ?").bind(key).first<{ value: string }>();
  return row?.value ?? "";
}

async function buildStats(env: Env): Promise<any> {
  const now = Math.floor(Date.now() / 1000);

  const counters = await env.DB.prepare(
    "SELECT tests_run, runtime_seconds FROM counters WHERE id = 1",
  ).first<{ tests_run: number; runtime_seconds: number }>();

  const installsLifetime = (await env.DB.prepare(
    "SELECT COUNT(*) AS c FROM installs",
  ).first<{ c: number }>())?.c ?? 0;

  const runningNow = (await env.DB.prepare(
    "SELECT COUNT(*) AS c FROM installs WHERE last_seen > ?",
  ).bind(now - 600).first<{ c: number }>())?.c ?? 0;

  const active24 = (await env.DB.prepare(
    "SELECT COUNT(*) AS c FROM installs WHERE last_seen > ?",
  ).bind(now - 86_400).first<{ c: number }>())?.c ?? 0;

  const active7d = (await env.DB.prepare(
    "SELECT COUNT(*) AS c FROM installs WHERE last_seen > ?",
  ).bind(now - 7 * 86_400).first<{ c: number }>())?.c ?? 0;

  const active30 = (await env.DB.prepare(
    "SELECT COUNT(*) AS c FROM installs WHERE last_seen > ?",
  ).bind(now - 30 * 86_400).first<{ c: number }>())?.c ?? 0;

  // Version mix among active-24h installs.
  const versionRows = (await env.DB.prepare(
    `SELECT version, COUNT(*) AS c FROM installs
      WHERE last_seen > ? AND version IS NOT NULL AND version <> ''
      GROUP BY version ORDER BY c DESC LIMIT 10`,
  ).bind(now - 86_400).all<{ version: string; c: number }>()).results ?? [];
  const versionTotal = versionRows.reduce((a, r) => a + r.c, 0) || 1;
  const versions = versionRows.map(r => ({
    version: r.version, count: r.c, pct: Math.round((r.c / versionTotal) * 100),
  }));

  // Docker Hub pulls — latest snapshot from docker_pulls (cron-populated).
  const dpRow = await env.DB.prepare(
    "SELECT pulls FROM docker_pulls ORDER BY date DESC LIMIT 1",
  ).first<{ pulls: number }>();
  const dpYesterday = await env.DB.prepare(
    "SELECT pulls FROM docker_pulls ORDER BY date DESC LIMIT 1 OFFSET 1",
  ).first<{ pulls: number }>();
  const dockerPulls = dpRow?.pulls ?? clampInt(env.DOCKER_PULLS_SEED || "0", 0, 1e12);
  const dockerPulls24h = (dpRow && dpYesterday) ? Math.max(0, dpRow.pulls - dpYesterday.pulls) : 0;

  // Project age from seed key (preferred) or env.
  const projStart = (await readSeed(env, "project_started_at")) || env.PROJECT_STARTED_AT || "";
  let ageDays = 0;
  if (projStart) {
    const t = Date.parse(projStart);
    if (!isNaN(t)) ageDays = Math.max(0, Math.floor((Date.now() - t) / 86_400_000));
  }

  const releases = parseInt(
    (await readSeed(env, "releases_count_snapshot")) || env.RELEASES_SEED || "0",
    10,
  ) || 0;
  const commits = parseInt(
    (await readSeed(env, "commits_snapshot")) || env.COMMITS_SEED || "0",
    10,
  ) || 0;

  // Hybrid: live counters + optional one-time baseline.
  const baselineTests   = parseInt((await readSeed(env, "baseline_tests"))   || env.BASELINE_TESTS   || "0", 10) || 0;
  const baselineRuntime = parseInt((await readSeed(env, "baseline_runtime")) || env.BASELINE_RUNTIME || "0", 10) || 0;
  const testsRan        = (counters?.tests_run       ?? 0) + baselineTests;
  const runtimeSeconds  = (counters?.runtime_seconds ?? 0) + baselineRuntime;

  const liveSince = (await readSeed(env, "live_since")) || ""; // set on first deploy

  return {
    generated_at: now,
    live_since:   liveSince,
    project: {
      started_at: projStart || null,
      age_days:   ageDays,
      releases,
      commits,
      github_repo: env.GITHUB_REPO || "jdibby/traffgen",
    },
    docker: {
      pulls: dockerPulls,
      pulls_24h_delta: dockerPulls24h,
    },
    installs: {
      lifetime:    installsLifetime,
      active_24h:  active24,
      active_7d:   active7d,
      active_30d:  active30,
      running_now: runningNow,
    },
    tests: {
      ran_total: testsRan,
    },
    runtime: {
      total_seconds: runtimeSeconds,
      human:         humanDuration(runtimeSeconds),
    },
    versions,
  };
}

function humanDuration(seconds: number): string {
  if (seconds <= 0) return "0";
  const y = Math.floor(seconds / (365 * 86400));
  if (y >= 1) return `${(seconds / (365 * 86400)).toFixed(1)} years`;
  const d = Math.floor(seconds / 86400);
  if (d >= 1) return `${d} days`;
  const h = Math.floor(seconds / 3600);
  if (h >= 1) return `${h} hours`;
  return `${Math.floor(seconds / 60)} minutes`;
}

async function handleStats(env: Env): Promise<Response> {
  const now = Math.floor(Date.now() / 1000);
  const cached = await env.DB.prepare(
    "SELECT payload, generated_at FROM stats_cache WHERE id = 1",
  ).first<{ payload: string; generated_at: number }>();

  if (cached && now - cached.generated_at < STATS_CACHE_TTL_S) {
    return new Response(cached.payload, {
      status: 200,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": `public, max-age=${STATS_CACHE_TTL_S}`,
        ...corsHeaders(env),
      },
    });
  }

  const fresh = await buildStats(env);
  const payload = JSON.stringify(fresh);
  await env.DB.prepare(
    "INSERT OR REPLACE INTO stats_cache(id, payload, generated_at) VALUES(1, ?, ?)",
  ).bind(payload, now).run();

  return new Response(payload, {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": `public, max-age=${STATS_CACHE_TTL_S}`,
      ...corsHeaders(env),
    },
  });
}

// ── Cron: refresh Docker Hub pull count, recompute version mix, clear abuse rows ─
async function refreshDockerPulls(env: Env): Promise<void> {
  const repo = env.DOCKER_HUB_REPO || "jdibby/traffgen";
  try {
    const r = await fetch(`https://hub.docker.com/v2/repositories/${repo}/`, {
      headers: { "user-agent": "traffgen-stats-worker" },
    });
    if (!r.ok) return;
    const j = await r.json<any>();
    const pulls = parseInt(String(j.pull_count ?? 0), 10) || 0;
    if (pulls > 0) {
      await env.DB.prepare(
        "INSERT OR REPLACE INTO docker_pulls(date, pulls) VALUES(?, ?)",
      ).bind(todayUTC(), pulls).run();
    }
  } catch {
    // Network blip — leave previous snapshot in place.
  }
}

async function refreshGithubFacts(env: Env): Promise<void> {
  const repo = env.GITHUB_REPO || "jdibby/traffgen";
  try {
    const releases = await fetch(`https://api.github.com/repos/${repo}/releases?per_page=1`, {
      headers: { "user-agent": "traffgen-stats-worker", "accept": "application/vnd.github+json" },
    });
    if (releases.ok) {
      const linkHdr = releases.headers.get("link") || "";
      // Parse "last" page number from Link header for total releases.
      const m = linkHdr.match(/<[^>]*[?&]page=(\d+)[^>]*>;\s*rel="last"/);
      if (m) {
        await env.DB.prepare(
          "INSERT OR REPLACE INTO seed(key, value) VALUES('releases_count_snapshot', ?)",
        ).bind(m[1]).run();
      } else {
        const arr = await releases.json<any[]>();
        if (Array.isArray(arr)) {
          await env.DB.prepare(
            "INSERT OR REPLACE INTO seed(key, value) VALUES('releases_count_snapshot', ?)",
          ).bind(String(arr.length)).run();
        }
      }
    }
  } catch {
    // ignore
  }
}

async function clearStaleAbuseRows(env: Env): Promise<void> {
  await env.DB.prepare(
    "DELETE FROM abuse_installs_today WHERE date <> ?",
  ).bind(todayUTC()).run();
}

async function regenerateStatsCache(env: Env): Promise<void> {
  const fresh = await buildStats(env);
  await env.DB.prepare(
    "INSERT OR REPLACE INTO stats_cache(id, payload, generated_at) VALUES(1, ?, ?)",
  ).bind(JSON.stringify(fresh), Math.floor(Date.now() / 1000)).run();
}

// ── Router ───────────────────────────────────────────────────────────────────
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === "OPTIONS") return noContent(env);

    const url = new URL(req.url);
    try {
      if (req.method === "POST" && url.pathname === "/v1/install")   return await handleInstall(req, env);
      if (req.method === "POST" && url.pathname === "/v1/heartbeat") return await handleHeartbeat(req, env);
      if (req.method === "GET"  && url.pathname === "/v1/stats")     return await handleStats(env);
      if (req.method === "GET"  && url.pathname === "/")             return json({ service: "traffgen-stats", ok: true }, 200, env);
    } catch (e: any) {
      return json({ error: "internal", detail: String(e?.message || e) }, 500, env);
    }
    return json({ error: "not_found" }, 404, env);
  },

  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil((async () => {
      await refreshDockerPulls(env);
      await refreshGithubFacts(env);
      await clearStaleAbuseRows(env);
      await regenerateStatsCache(env);
    })());
  },
};
