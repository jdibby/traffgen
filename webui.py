#!/usr/bin/env python3
"""
webui.py — HTTPS monitoring dashboard for traffgen on port 7777.

No configuration needed. Reads /tmp/traffgen_state.json for live data.
Accepts validated control commands via POST /api/control to reconfigure
the generator without restarting the container.

Generates a self-signed TLS certificate on first start (stored in /tmp/).
"""

import json
import logging
import os
import ssl
import subprocess
import time
import threading

logging.getLogger("werkzeug").setLevel(logging.ERROR)

from flask import Flask, Response, jsonify, request  # noqa: E402

# ── Constants ──────────────────────────────────────────────────────────────────
_STATE_FILE  = "/tmp/traffgen_state.json"
_LOG_FILE    = "/tmp/traffgen_log.jsonl"
_CMD_FILE    = "/tmp/traffgen_cmd.json"
_CERT        = "/tmp/webui.crt"
_KEY         = "/tmp/webui.key"
PORT         = 7777
MAX_SSE      = 30
_VALID_SIZES = {"XS", "S", "M", "L", "XL"}

# ── Flask ──────────────────────────────────────────────────────────────────────
app = Flask(__name__)

_sse_count = 0
_sse_lock  = threading.Lock()

_SEC_HEADERS = {
    "X-Content-Type-Options":    "nosniff",
    "X-Frame-Options":           "SAMEORIGIN",
    "X-XSS-Protection":          "1; mode=block",
    "Referrer-Policy":           "no-referrer",
    "Cache-Control":             "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; "
        "style-src 'unsafe-inline'; "
        "script-src 'unsafe-inline'; "
        "connect-src 'self'"
    ),
    "Strict-Transport-Security": "max-age=31536000",
    "Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
}


@app.after_request
def _add_sec(resp):
    for k, v in _SEC_HEADERS.items():
        resp.headers[k] = v
    return resp


# ── Helpers ────────────────────────────────────────────────────────────────────
def _read_state() -> dict:
    try:
        with open(_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {
            "version": "—", "started_at": time.time(), "suite": "all",
            "size": "XS", "loop": True, "max_wait_secs": 20,
            "current_test": "starting…", "iteration": 0,
            "tests": {}, "suites": [],
            "totals": {"attempts": 0, "ok": 0, "fail": 0},
            "history": [], "events": [],
        }


def _sse_wrap(gen_fn):
    """Apply SSE connection limit and correct headers around a generator."""
    global _sse_count
    with _sse_lock:
        if _sse_count >= MAX_SSE:
            return Response("Too many connections", status=429)
        _sse_count += 1

    def _guarded():
        global _sse_count
        try:
            yield from gen_fn()
        finally:
            with _sse_lock:
                _sse_count -= 1

    return Response(
        _guarded(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return Response(_HTML, mimetype="text/html")


@app.route("/log-view")
def log_view():
    return Response(_LOG_HTML, mimetype="text/html")


@app.route("/api/state")
def api_state():
    return jsonify(_read_state())


@app.route("/api/control", methods=["POST"])
def api_control():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    d    = request.get_json(silent=True) or {}
    st   = _read_state()
    known = {s["name"] for s in st.get("suites", [])} | {"all"}

    suite = str(d.get("suite", "all"))
    if suite not in known:
        return jsonify({"error": f"Unknown suite: {suite}"}), 400

    size = str(d.get("size", "XS"))
    if size not in _VALID_SIZES:
        return jsonify({"error": f"Invalid size: {size}"}), 400

    try:
        wait = max(5, min(300, int(d.get("max_wait_secs", 20))))
    except (TypeError, ValueError):
        return jsonify({"error": "max_wait_secs must be an integer 5-300"}), 400

    cmd = {
        "suite":         suite,
        "size":          size,
        "max_wait_secs": wait,
        "loop":          bool(d.get("loop", True)),
        "nowait":        bool(d.get("nowait", False)),
    }
    try:
        tmp = _CMD_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cmd, f)
        os.replace(tmp, _CMD_FILE)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"ok": True, "applied": cmd})


@app.route("/events")
def sse_state():
    def _gen():
        while True:
            yield f"data: {json.dumps(_read_state(), separators=(',', ':'))}\n\n"
            time.sleep(2)
    return _sse_wrap(_gen)


@app.route("/log")
def sse_log():
    def _gen():
        # Seed the client with the last 100 lines already in the file
        try:
            with open(_LOG_FILE) as f:
                seed = f.readlines()[-100:]
            for ln in seed:
                ln = ln.strip()
                if ln:
                    yield f"data: {ln}\n\n"
        except FileNotFoundError:
            pass

        # Now tail from the current end
        pos = 0
        try:
            with open(_LOG_FILE) as f:
                f.seek(0, 2)
                pos = f.tell()
        except FileNotFoundError:
            pass

        while True:
            try:
                with open(_LOG_FILE) as f:
                    f.seek(pos)
                    new = f.readlines()
                    pos = f.tell()
                for ln in new:
                    ln = ln.strip()
                    if ln:
                        yield f"data: {ln}\n\n"
            except FileNotFoundError:
                pass
            time.sleep(1)

    return _sse_wrap(_gen)


# ── TLS certificate ────────────────────────────────────────────────────────────
def _ensure_cert() -> ssl.SSLContext:
    if not (os.path.exists(_CERT) and os.path.exists(_KEY)):
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", _KEY, "-out", _CERT,
                "-days", "3650", "-nodes",
                "-subj", "/CN=traffgen-dashboard/O=traffgen",
            ],
            check=True,
            capture_output=True,
        )
        os.chmod(_KEY, 0o600)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(_CERT, _KEY)
    return ctx


# ── Dashboard HTML ─────────────────────────────────────────────────────────────
_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>traffgen</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--surf:#161b22;--surf2:#1c2230;--border:#30363d;
  --blue:#58a6ff;--green:#3fb950;--red:#f85149;--amber:#d29922;--purple:#bc8cff;
  --text:#e6edf3;--muted:#8b949e;--dim:#484f58;--r:8px;
}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.5;min-height:100vh}
.hdr{position:sticky;top:0;z-index:200;display:flex;align-items:center;gap:10px;padding:0 20px;height:52px;background:var(--surf);border-bottom:1px solid var(--border)}
.logo{display:flex;align-items:center;gap:8px;font-weight:700;font-size:15px;letter-spacing:-.3px;white-space:nowrap}
.logo-ico{width:26px;height:26px;background:linear-gradient(135deg,var(--blue),var(--purple));border-radius:6px;display:grid;place-items:center;font-size:14px}
.tabs{display:flex;gap:2px;margin-left:8px}
.tab{padding:5px 14px;border-radius:6px;border:none;background:none;color:var(--muted);font-size:13px;cursor:pointer;transition:all .15s}
.tab:hover{background:var(--surf2);color:var(--text)}
.tab.active{background:var(--surf2);color:var(--blue);font-weight:600}
.hdr-r{display:flex;align-items:center;gap:8px;margin-left:auto}
.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:500;border:1px solid var(--border);background:var(--bg);color:var(--muted);white-space:nowrap}
.pill.live{border-color:var(--green);color:var(--green)}
.pill.warn{border-color:var(--amber);color:var(--amber)}
.pulse{width:7px;height:7px;background:var(--green);border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.ico-btn{width:32px;height:32px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--muted);cursor:pointer;display:grid;place-items:center;font-size:16px;transition:all .15s}
.ico-btn:hover{border-color:var(--blue);color:var(--blue)}
.mono{font-family:'SF Mono',Consolas,monospace;font-size:11px}
/* Panels */
.panel{display:none;padding:20px;max-width:1400px;margin:0 auto;flex-direction:column;gap:16px}
.panel.active{display:flex}
/* Cards */
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}}
.card{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);padding:18px;display:flex;flex-direction:column;gap:5px;transition:border-color .2s}
.card:hover{border-color:var(--blue)}
.card.hi{border-color:var(--blue);background:linear-gradient(135deg,rgba(88,166,255,.06),var(--surf))}
.clbl{font-size:10px;font-weight:600;letter-spacing:.6px;text-transform:uppercase;color:var(--muted)}
.cval{font-size:26px;font-weight:700;letter-spacing:-.5px;font-family:'SF Mono',Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.csub{font-size:11px;color:var(--muted)}
.c-blue{color:var(--blue)}.c-green{color:var(--green)}.c-amber{color:var(--amber)}.c-red{color:var(--red)}.c-mut{color:var(--muted)}
/* Charts */
.charts{display:grid;grid-template-columns:260px 1fr;gap:14px}
@media(max-width:800px){.charts{grid-template-columns:1fr}}
.cc{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);padding:18px}
.ctitle{font-size:10px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted);margin-bottom:14px;display:flex;justify-content:space-between;align-items:center}
.donut-wrap{display:flex;flex-direction:column;align-items:center;gap:12px}
.legend{display:flex;gap:14px;font-size:12px}
.leg{display:flex;align-items:center;gap:5px}
.leg-dot{width:8px;height:8px;border-radius:50%}
/* Table */
.tcard{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.thdr{padding:13px 18px 9px;font-size:10px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:12px}
thead th{padding:8px 18px;text-align:left;font-size:10px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted);background:var(--surf2);border-bottom:1px solid var(--border)}
th.r,td.r{text-align:right}
tbody tr{border-bottom:1px solid var(--border);transition:background .1s}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--surf2)}
tbody td{padding:8px 18px;font-family:'SF Mono',Consolas,monospace;font-size:11px}
td.nm{font-family:inherit;font-weight:500}
.rw{display:flex;align-items:center;justify-content:flex-end;gap:7px}
.bt{width:50px;height:3px;background:var(--border);border-radius:2px;overflow:hidden}
.bf{height:100%;border-radius:2px;transition:width .4s}
/* Events */
.ecard{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.ehdr{padding:13px 18px 9px;font-size:10px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);display:flex;justify-content:space-between}
.ebody{height:210px;overflow-y:auto}
.erow{display:grid;grid-template-columns:72px 1fr 58px 60px;gap:10px;padding:6px 18px;border-bottom:1px solid rgba(48,54,61,.45);font-size:11px;font-family:'SF Mono',Consolas,monospace;align-items:center}
.erow:last-child{border-bottom:none}
.et{color:var(--dim)}.eok{color:var(--green);text-align:right}.efail{color:var(--red);text-align:right}.edur{color:var(--muted);text-align:right}
/* Tests tab */
.tgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}
.tcard2{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);padding:16px;display:flex;flex-direction:column;gap:8px;transition:border-color .2s}
.tcard2:hover{border-color:var(--blue)}
.tcard2.run{border-color:var(--blue);background:linear-gradient(135deg,rgba(88,166,255,.06),var(--surf))}
.tcn{font-weight:600;font-size:13px;display:flex;align-items:center;gap:6px}
.badge{font-size:9px;padding:2px 6px;border-radius:10px;background:rgba(88,166,255,.15);color:var(--blue);border:1px solid rgba(88,166,255,.3)}
.tcd{font-size:12px;color:var(--muted);line-height:1.45}
.tcs{display:flex;gap:12px;font-size:11px;font-family:'SF Mono',Consolas,monospace}
.tc-bar{width:100%;height:2px;background:var(--border);border-radius:1px;overflow:hidden}
.tc-bf{height:100%;border-radius:1px;transition:width .4s}
/* Output tab */
.otb{display:flex;gap:8px;padding:10px 16px;background:var(--surf);border-bottom:1px solid var(--border);align-items:center;border-radius:var(--r) var(--r) 0 0}
.otlbl{font-size:10px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted);margin-right:auto}
.btn{padding:4px 12px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--muted);font-size:11px;cursor:pointer;transition:all .15s}
.btn:hover{border-color:var(--blue);color:var(--blue)}
.obody{height:calc(100vh - 200px);overflow-y:auto;font-family:'SF Mono',Consolas,monospace;font-size:12px;background:var(--bg);border:1px solid var(--border);border-top:none;border-radius:0 0 var(--r) var(--r)}
.ll{padding:3px 16px;display:grid;grid-template-columns:72px 48px 1fr;gap:8px;white-space:pre-wrap;word-break:break-all}
.ll:hover{background:var(--surf2)}
.llt{color:var(--dim)}.llv{font-weight:600}.llm{color:var(--text)}
.ll.info .llv{color:var(--blue)}.ll.ok .llv{color:var(--green)}.ll.warn .llv{color:var(--amber)}.ll.error .llv{color:var(--red)}.ll.debug .llv{color:var(--dim)}
/* Drawer */
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:299}
.overlay.open{display:block}
.drawer{position:fixed;top:0;right:-390px;width:370px;height:100vh;background:var(--surf);border-left:1px solid var(--border);z-index:300;transition:right .25s ease;display:flex;flex-direction:column;overflow-y:auto}
.drawer.open{right:0}
.dhdr{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--border)}
.dtitle{font-weight:600;font-size:14px}
.dbody{padding:20px;display:flex;flex-direction:column;gap:18px;flex:1}
.field{display:flex;flex-direction:column;gap:6px}
.field label{font-size:10px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted)}
.field select{width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;outline:none}
.field select:focus{border-color:var(--blue)}
.rngw{display:flex;align-items:center;gap:10px}
.field input[type=range]{flex:1;accent-color:var(--blue)}
.rngv{font-family:'SF Mono',Consolas,monospace;font-size:12px;color:var(--text);min-width:38px;text-align:right}
.togrow{display:flex;align-items:center;justify-content:space-between}
.toglbl{font-size:13px;color:var(--text)}
.tog{position:relative;width:40px;height:22px}
.tog input{opacity:0;width:0;height:0}
.tslider{position:absolute;inset:0;background:var(--border);border-radius:22px;transition:.2s;cursor:pointer}
.tslider:before{content:"";position:absolute;width:16px;height:16px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s}
input:checked+.tslider{background:var(--blue)}
input:checked+.tslider:before{transform:translateX(18px)}
.btn-p{width:100%;padding:10px;background:var(--blue);color:#fff;border:none;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;transition:opacity .15s}
.btn-p:hover{opacity:.85}
.fnote{font-size:11px;color:var(--muted);text-align:center;line-height:1.4}
/* Toast */
.toast{position:fixed;bottom:20px;right:20px;padding:10px 18px;border-radius:8px;font-size:13px;font-weight:500;z-index:400;display:none}
.toast.ok{background:rgba(63,185,80,.15);border:1px solid var(--green);color:var(--green)}
.toast.err{background:rgba(248,81,73,.15);border:1px solid var(--red);color:var(--red)}
/* Misc */
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
.empty{padding:32px;text-align:center;color:var(--muted);font-size:13px}
.footer{text-align:center;padding:14px;font-size:11px;color:var(--dim);border-top:1px solid var(--border);margin-top:8px}
</style>
</head>
<body>

<header class="hdr">
  <div class="logo"><div class="logo-ico">&#9889;</div>traffgen</div>
  <div class="tabs">
    <button class="tab active" data-tab="overview" onclick="showTab(this)">Overview</button>
    <button class="tab" data-tab="tests" onclick="showTab(this)">Tests</button>
    <button class="tab" data-tab="output" onclick="showTab(this)">Output</button>
  </div>
  <div class="hdr-r">
    <button class="ico-btn" onclick="openDrawer()" title="Settings">&#9881;</button>
    <span id="pill-live" class="pill live"><span class="pulse"></span>LIVE</span>
    <span id="pill-up" class="pill mono">&#8212;</span>
  </div>
</header>

<!-- Overview -->
<div id="tab-overview" class="panel active">
  <div class="cards">
    <div class="card"><div class="clbl">Total Requests</div><div class="cval c-blue" id="v-total">&#8212;</div><div class="csub" id="s-total">&#8212;</div></div>
    <div class="card"><div class="clbl">Success Rate</div><div class="cval" id="v-rate">&#8212;</div><div class="csub" id="s-rate">&#8212;</div></div>
    <div class="card hi"><div class="clbl">Active Test</div><div class="cval c-blue" id="v-test" style="font-size:17px">&#8212;</div><div class="csub" id="s-test">&#8212;</div></div>
    <div class="card"><div class="clbl">Iteration</div><div class="cval c-amber" id="v-iter">&#8212;</div><div class="csub" id="s-iter">&#8212;</div></div>
  </div>
  <div class="charts">
    <div class="cc"><div class="ctitle">Success / Failure</div>
      <div class="donut-wrap">
        <canvas id="donut" width="180" height="180"></canvas>
        <div class="legend">
          <div class="leg"><div class="leg-dot" style="background:var(--green)"></div><span id="leg-ok">&#8212;</span></div>
          <div class="leg"><div class="leg-dot" style="background:var(--red)"></div><span id="leg-fail">&#8212;</span></div>
        </div>
      </div>
    </div>
    <div class="cc">
      <div class="ctitle">Requests Over Time <span id="hist-info" style="font-weight:400;letter-spacing:0;text-transform:none;font-size:10px;color:var(--dim)"></span></div>
      <canvas id="spark" style="width:100%;height:178px"></canvas>
    </div>
  </div>
  <div class="tcard">
    <div class="thdr">Test Breakdown</div>
    <table><thead><tr><th>Test</th><th class="r">Attempts</th><th class="r">OK</th><th class="r">Fail</th><th class="r">Rate</th><th class="r">Last Run</th></tr></thead>
    <tbody id="tbl-body"><tr><td colspan="6" class="empty">Waiting for data&#8230;</td></tr></tbody></table>
  </div>
  <div class="ecard">
    <div class="ehdr">Live Events <span id="ev-cnt" style="color:var(--dim);font-weight:400;letter-spacing:0;text-transform:none"></span></div>
    <div class="ebody" id="ev-body"><div class="empty">Waiting&#8230;</div></div>
  </div>
</div>

<!-- Tests -->
<div id="tab-tests" class="panel">
  <div class="tgrid" id="test-grid"><div class="empty">Waiting for data&#8230;</div></div>
</div>

<!-- Output -->
<div id="tab-output" class="panel" style="padding:0;gap:0">
  <div class="otb">
    <span class="otlbl">Live Output</span>
    <button class="btn" onclick="$('obody').innerHTML=''">Clear</button>
    <button class="btn" onclick="window.open('/log-view','tg-log','width=920,height=620,scrollbars=yes')">Pop Out &#8599;</button>
    <button class="btn" id="btn-as" onclick="toggleAS()">Auto-scroll &#10003;</button>
  </div>
  <div class="obody" id="obody"></div>
</div>

<!-- Settings drawer -->
<div class="overlay" id="overlay" onclick="closeDrawer()"></div>
<div class="drawer" id="drawer">
  <div class="dhdr">
    <span class="dtitle">Settings</span>
    <button class="ico-btn" onclick="closeDrawer()">&#10005;</button>
  </div>
  <div class="dbody">
    <div class="field"><label>Suite</label>
      <select id="cfg-suite"><option value="all">all &#8212; run everything</option></select>
    </div>
    <div class="field"><label>Size</label>
      <select id="cfg-size">
        <option value="XS">XS &#8212; Extra Small (minimal, very slow)</option>
        <option value="S">S &#8212; Small</option>
        <option value="M">M &#8212; Medium</option>
        <option value="L">L &#8212; Large</option>
        <option value="XL">XL &#8212; Extra Large</option>
      </select>
    </div>
    <div class="field"><label>Max Wait Between Tests</label>
      <div class="rngw">
        <input type="range" id="cfg-wait" min="5" max="300" step="5" value="20"
               oninput="$('wait-val').textContent=this.value+'s'">
        <span class="rngv" id="wait-val">20s</span>
      </div>
    </div>
    <div class="field">
      <div class="togrow"><span class="toglbl">Loop Mode</span>
        <label class="tog"><input type="checkbox" id="cfg-loop" checked><span class="tslider"></span></label>
      </div>
    </div>
    <div class="field">
      <div class="togrow"><span class="toglbl">No Wait (skip all pauses)</span>
        <label class="tog"><input type="checkbox" id="cfg-nowait"><span class="tslider"></span></label>
      </div>
    </div>
    <button class="btn-p" onclick="applySettings()">Apply &amp; Restart</button>
    <p class="fnote">Applying writes new settings and restarts the generator at the next test boundary.</p>
  </div>
</div>

<div class="toast" id="toast"></div>
<div class="footer">traffgen dashboard &middot; HTTPS :7777 &middot; <span id="ver"></span></div>

<script>
const $ = id => document.getElementById(id);
const N = n => n.toLocaleString();
const Tc = ts => new Date(ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});
const Ts = ts => new Date(ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
const Dur = ms => ms < 1000 ? ms+'ms' : (ms/1000).toFixed(1)+'s';
const RC = p => p>=90?'var(--green)':p>=70?'var(--amber)':'var(--red)';
const H = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

let _start=null, _uptimer=null, _autoScroll=true, _lastState=null, _logEs=null;

function uptime(t){
  const s=Math.floor(Date.now()/1000-t);
  return [Math.floor(s/3600),Math.floor((s%3600)/60),s%60].map(v=>String(v).padStart(2,'0')).join(':');
}

// ── Tabs ──────────────────────────────────────────────────────────────────────
function showTab(btn){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  btn.classList.add('active');
  $('tab-'+btn.dataset.tab).classList.add('active');
  if(btn.dataset.tab==='output') connectLog();
}

// ── Charts ────────────────────────────────────────────────────────────────────
function drawDonut(ok,fail){
  const c=$('donut'),ctx=c.getContext('2d'),W=c.width,H=c.height,cx=W/2,cy=H/2,r=72,ri=50;
  const total=ok+fail;
  ctx.clearRect(0,0,W,H);
  if(!total){
    ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.arc(cx,cy,ri,0,Math.PI*2,true);
    ctx.fillStyle='#30363d';ctx.fill();
    ctx.fillStyle='#8b949e';ctx.font='12px system-ui';ctx.textAlign='center';ctx.textBaseline='middle';
    ctx.fillText('No data',cx,cy);return;
  }
  const okA=(ok/total)*Math.PI*2,s=-Math.PI/2;
  ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,s,s+okA);ctx.arc(cx,cy,ri,s+okA,s,true);ctx.fillStyle='#3fb950';ctx.fill();
  if(fail>0){
    ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,s+okA,s+okA+(fail/total)*Math.PI*2);
    ctx.arc(cx,cy,ri,s+okA+(fail/total)*Math.PI*2,s+okA,true);ctx.fillStyle='#f85149';ctx.fill();
  }
  ctx.fillStyle='#e6edf3';ctx.font='bold 19px SF Mono,Consolas,monospace';ctx.textAlign='center';ctx.textBaseline='middle';
  ctx.fillText(((ok/total)*100).toFixed(1)+'%',cx,cy-7);
  ctx.fillStyle='#8b949e';ctx.font='10px system-ui';ctx.fillText('success',cx,cy+10);
}

function drawSpark(history){
  const c=$('spark'),rect=c.getBoundingClientRect();
  c.width=Math.floor(rect.width)||500;c.height=Math.floor(rect.height)||178;
  const ctx=c.getContext('2d'),W=c.width,H=c.height,P={t:14,r:14,b:26,l:40};
  const IW=W-P.l-P.r,IH=H-P.t-P.b;
  ctx.clearRect(0,0,W,H);
  if(!history||history.length<2){
    ctx.fillStyle='#8b949e';ctx.font='12px system-ui';ctx.textAlign='center';ctx.textBaseline='middle';
    ctx.fillText('Accumulating data…',W/2,H/2);return;
  }
  const okV=history.map(p=>p.ok||0),failV=history.map(p=>p.fail||0),mx=Math.max(...okV,...failV,1);
  const xOf=i=>P.l+(i/(history.length-1))*IW,yOf=v=>P.t+IH-(v/mx)*IH;
  ctx.strokeStyle='#30363d';ctx.lineWidth=1;
  for(let i=0;i<=4;i++){const y=P.t+(i/4)*IH;ctx.beginPath();ctx.moveTo(P.l,y);ctx.lineTo(P.l+IW,y);ctx.stroke();
    ctx.fillStyle='#484f58';ctx.font='9px SF Mono,Consolas,monospace';ctx.textAlign='right';
    ctx.fillText(Math.round(mx*(1-i/4)),P.l-5,y+3);}
  ctx.beginPath();history.forEach((p,i)=>{const x=xOf(i),y=yOf(p.ok||0);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y)});
  ctx.lineTo(xOf(history.length-1),P.t+IH);ctx.lineTo(xOf(0),P.t+IH);ctx.closePath();
  const g=ctx.createLinearGradient(0,P.t,0,P.t+IH);g.addColorStop(0,'rgba(63,185,80,.28)');g.addColorStop(1,'rgba(63,185,80,.02)');
  ctx.fillStyle=g;ctx.fill();
  ctx.beginPath();history.forEach((p,i)=>{const x=xOf(i),y=yOf(p.ok||0);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y)});
  ctx.strokeStyle='#3fb950';ctx.lineWidth=2;ctx.lineJoin='round';ctx.stroke();
  if(failV.some(v=>v>0)){
    ctx.beginPath();history.forEach((p,i)=>{const x=xOf(i),y=yOf(p.fail||0);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y)});
    ctx.strokeStyle='#f85149';ctx.lineWidth=1.5;ctx.setLineDash([4,3]);ctx.stroke();ctx.setLineDash([]);
  }
  ctx.fillStyle='#484f58';ctx.font='9px SF Mono,Consolas,monospace';
  ctx.textAlign='left';ctx.fillText(Ts(history[0].t),P.l,H-5);
  ctx.textAlign='right';ctx.fillText(Ts(history[history.length-1].t),P.l+IW,H-5);
}

// ── State rendering ───────────────────────────────────────────────────────────
function apply(s){
  _lastState=s;
  $('ver').textContent='v'+(s.version||'—');
  if(s.started_at&&!_start){
    _start=s.started_at;clearInterval(_uptimer);
    _uptimer=setInterval(()=>$('pill-up').textContent='Up '+uptime(_start),1000);
  }
  const tot=s.totals||{},ok=tot.ok||0,fail=tot.fail||0,att=tot.attempts||0,pct=att?ok/att*100:0;
  $('v-total').textContent=N(att);$('s-total').textContent=N(ok)+' ok · '+N(fail)+' fail';
  $('v-rate').textContent=att?pct.toFixed(1)+'%':'—';
  $('v-rate').style.color=att?RC(pct):'var(--muted)';
  $('s-rate').textContent=att?N(att)+' total requests':'No data yet';
  const cur=s.current_test||'—';
  $('v-test').textContent=cur;$('s-test').textContent=s.loop?'Loop mode':'Single-run';
  $('v-iter').textContent=s.iteration?'#'+N(s.iteration):'—';
  $('s-iter').textContent=s.loop?'Iterations':'Tests completed';
  drawDonut(ok,fail);
  $('leg-ok').textContent=N(ok)+' OK';$('leg-fail').textContent=N(fail)+' Fail';
  const hist=s.history||[];drawSpark(hist);
  if(hist.length>1)$('hist-info').textContent=hist.length+' samples';
  // Table
  const tests=s.tests||{},names=Object.keys(tests).sort(),tb=$('tbl-body');
  if(!names.length){tb.innerHTML='<tr><td colspan="6" class="empty">Waiting…</td></tr>';}
  else tb.innerHTML=names.map(n=>{
    const t=tests[n],ta=t.attempts||0,tok=t.ok||0,tf=t.fail||0,tp=ta?tok/ta*100:0;
    const bc=RC(tp),lr=t.last_run_at?Tc(t.last_run_at):'—',act=n===cur;
    return`<tr style="${act?'background:rgba(88,166,255,.06)':''}">
      <td class="nm">${act?'▶ ':''}${H(n.replace(/_/g,' '))}</td>
      <td class="r">${N(ta)}</td><td class="r" style="color:var(--green)">${N(tok)}</td>
      <td class="r" style="color:${tf?'var(--red)':'var(--muted)'}">${N(tf)}</td>
      <td class="r"><div class="rw"><span style="color:${bc}">${ta?tp.toFixed(1)+'%':'—'}</span>
        <div class="bt"><div class="bf" style="width:${tp}%;background:${bc}"></div></div></div></td>
      <td class="r" style="color:var(--muted)">${lr}</td></tr>`;
  }).join('');
  // Events
  const evs=(s.events||[]).slice().reverse(),eb=$('ev-body');
  $('ev-cnt').textContent=evs.length?' · '+evs.length+' events':'';
  eb.innerHTML=!evs.length?'<div class="empty">Waiting…</div>':evs.map(e=>
    `<div class="erow"><span class="et">${Tc(e.t)}</span>
    <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${H((e.test||'').replace(/_/g,' '))}</span>
    <span class="${e.ok?'eok':'efail'}">${e.ok?'✓ OK':'✗ FAIL'}</span>
    <span class="edur">${e.dur_ms!=null?Dur(e.dur_ms):'—'}</span></div>`).join('');
  // Tests tab
  const suites=s.suites||[],tg=$('test-grid');
  if(!suites.length){tg.innerHTML='<div class="empty">Waiting for data…</div>';}
  else tg.innerHTML=suites.map(su=>{
    const td=tests[su.name]||{},ta=td.attempts||0,tok=td.ok||0,tf=td.fail||0,tp=ta?tok/ta*100:0;
    const bc=RC(tp),act=su.name===cur;
    return`<div class="tcard2${act?' run':''}">
      <div class="tcn">${H(su.name.replace(/_/g,' '))}${act?'<span class="badge">RUNNING</span>':''}</div>
      <div class="tcd">${H(su.description||'—')}</div>
      <div class="tcs">
        <span style="color:var(--muted)">${N(ta)} attempts</span>
        <span style="color:var(--green)">${N(tok)} ok</span>
        <span style="color:${tf?'var(--red)':'var(--muted)'}">${N(tf)} fail</span>
      </div>
      ${ta?`<div class="tc-bar"><div class="tc-bf" style="width:${tp}%;background:${bc}"></div></div>`:''}
    </div>`;
  }).join('');
  // Sync settings drawer (once suites available)
  const sel=$('cfg-suite');
  if(sel.options.length<=1&&suites.length){
    suites.forEach(su=>{
      const o=document.createElement('option');
      o.value=su.name;o.textContent=su.name+' — '+su.description;
      sel.appendChild(o);
    });
  }
  sel.value=s.suite||'all';
  $('cfg-size').value=s.size||'XS';
  $('cfg-wait').value=s.max_wait_secs||20;
  $('wait-val').textContent=(s.max_wait_secs||20)+'s';
  $('cfg-loop').checked=!!s.loop;
}

// ── State SSE ─────────────────────────────────────────────────────────────────
function connect(){
  const es=new EventSource('/events');
  es.onmessage=ev=>{try{apply(JSON.parse(ev.data))}catch(e){}};
  es.onerror=()=>{
    es.close();
    $('pill-live').className='pill warn';
    $('pill-live').innerHTML='⚠ RECONNECTING';
    setTimeout(connect,3000);
  };
  es.onopen=()=>{
    $('pill-live').className='pill live';
    $('pill-live').innerHTML='<span class="pulse"></span>LIVE';
  };
}

// ── Log SSE ───────────────────────────────────────────────────────────────────
function connectLog(){
  if(_logEs)return;
  _logEs=new EventSource('/log');
  _logEs.onmessage=ev=>{try{appendLog(JSON.parse(ev.data))}catch(e){}};
  _logEs.onerror=()=>{_logEs.close();_logEs=null;setTimeout(connectLog,3000);};
}
function appendLog(d){
  const b=$('obody'),div=document.createElement('div');
  div.className='ll '+(d.level||'info');
  div.innerHTML=`<span class="llt">${Tc(d.t||Date.now()/1000)}</span><span class="llv">${H((d.level||'info').toUpperCase().slice(0,5).padEnd(5))}</span><span class="llm">${H(d.msg||'')}</span>`;
  b.appendChild(div);
  if(_autoScroll)b.scrollTop=b.scrollHeight;
  while(b.children.length>500)b.removeChild(b.firstChild);
}
function toggleAS(){_autoScroll=!_autoScroll;$('btn-as').textContent='Auto-scroll '+(_autoScroll?'✓':'✗');}

// ── Settings drawer ───────────────────────────────────────────────────────────
function openDrawer(){$('drawer').classList.add('open');$('overlay').classList.add('open');}
function closeDrawer(){$('drawer').classList.remove('open');$('overlay').classList.remove('open');}
function toast(msg,ok){
  const t=$('toast');t.textContent=msg;t.className='toast '+(ok?'ok':'err');t.style.display='block';
  setTimeout(()=>t.style.display='none',3500);
}
function applySettings(){
  const body={suite:$('cfg-suite').value,size:$('cfg-size').value,
    max_wait_secs:parseInt($('cfg-wait').value),loop:$('cfg-loop').checked,nowait:$('cfg-nowait').checked};
  fetch('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(r=>r.json())
    .then(d=>{if(d.ok){toast('Settings applied — generator restarting…',true);closeDrawer();}
              else toast('Error: '+d.error,false);})
    .catch(()=>toast('Request failed — is the generator running?',false));
}

window.addEventListener('resize',()=>{if(_lastState)drawSpark(_lastState.history||[])});
connect();
</script>
</body></html>"""

# ── Standalone log viewer (popout window) ─────────────────────────────────────
_LOG_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>traffgen &middot; Output</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0d1117;--surf:#161b22;--border:#30363d;--green:#3fb950;--red:#f85149;--amber:#d29922;--blue:#58a6ff;--text:#e6edf3;--muted:#8b949e;--dim:#484f58}
body{background:var(--bg);color:var(--text);font-family:'SF Mono',Consolas,monospace;font-size:12px;height:100vh;display:flex;flex-direction:column}
.hdr{display:flex;align-items:center;gap:10px;padding:8px 14px;background:var(--surf);border-bottom:1px solid var(--border);flex-shrink:0}
.title{font-weight:700;font-size:13px;margin-right:auto}
.btn{padding:3px 10px;border-radius:5px;border:1px solid var(--border);background:var(--bg);color:var(--muted);font-size:11px;cursor:pointer}
.btn:hover{border-color:var(--blue);color:var(--blue)}
.body{flex:1;overflow-y:auto;padding:4px 0}
.ll{padding:3px 14px;display:grid;grid-template-columns:72px 48px 1fr;gap:8px;white-space:pre-wrap;word-break:break-all}
.ll:hover{background:var(--surf)}
.llt{color:var(--dim)}.llv{font-weight:600}.llm{color:var(--text)}
.ll.info .llv{color:var(--blue)}.ll.ok .llv{color:var(--green)}.ll.warn .llv{color:var(--amber)}.ll.error .llv{color:var(--red)}.ll.debug .llv{color:var(--dim)}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
</style>
</head>
<body>
<div class="hdr">
  <span class="title">&#9889; traffgen &middot; Live Output</span>
  <button class="btn" onclick="document.querySelector('.body').innerHTML=''">Clear</button>
  <button class="btn" id="bas" onclick="as=!as;this.textContent='Auto-scroll '+(as?'✓':'✗')">Auto-scroll &#10003;</button>
</div>
<div class="body" id="body"></div>
<script>
let as=true;
const H=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const Tc=ts=>new Date(ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});
const b=document.getElementById('body');
const es=new EventSource('/log');
es.onmessage=ev=>{
  try{const d=JSON.parse(ev.data),div=document.createElement('div');
    div.className='ll '+(d.level||'info');
    div.innerHTML=`<span class="llt">${Tc(d.t||Date.now()/1000)}</span><span class="llv">${H((d.level||'info').toUpperCase().slice(0,5).padEnd(5))}</span><span class="llm">${H(d.msg||'')}</span>`;
    b.appendChild(div);if(as)b.scrollTop=b.scrollHeight;
    while(b.children.length>1000)b.removeChild(b.firstChild);
  }catch(e){}
};
</script>
</body>
</html>"""

# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ctx = _ensure_cert()
    print(f"[webui] Dashboard: https://0.0.0.0:{PORT}", flush=True)
    app.run(
        host="0.0.0.0",
        port=PORT,
        ssl_context=ctx,
        threaded=True,
        use_reloader=False,
    )
