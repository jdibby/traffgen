#!/usr/bin/env python3
"""
webui.py — HTTPS monitoring dashboard for traffgen on port 7777.

No configuration needed. Reads /tmp/traffgen_state.json for live data.
Accepts validated control commands via POST /api/control.
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
_PAUSE_FILE  = "/tmp/traffgen_pause"
_STOP_FILE   = "/tmp/traffgen_stop"
_CERT        = "/tmp/webui.crt"
_KEY         = "/tmp/webui.key"
PORT         = 7777
MAX_SSE      = 30
_VALID_SIZES = {"XS", "S", "M", "L", "XL"}

# ── Flask ──────────────────────────────────────────────────────────────────────
app = Flask(__name__)

_sse_count = 0
_sse_lock  = threading.Lock()

# ── Health monitoring ──────────────────────────────────────────────────────────
_health_cache: dict = {}
_health_lock2 = threading.Lock()


def _sample_health() -> None:
    """Background daemon: sample /proc metrics every 2 s and cache results."""
    prev_cpu   = None
    prev_disk  = None
    prev_procs: dict = {}
    prev_ts    = 0.0

    while True:
        time.sleep(2)
        try:
            now  = time.time()
            data: dict = {}

            # CPU
            try:
                with open("/proc/stat") as f:
                    raw = f.readline().split()
                total = sum(int(x) for x in raw[1:8])
                idle  = int(raw[4]) + int(raw[5])   # idle + iowait
                cur_c = (total, idle)
                if prev_cpu:
                    dt = cur_c[0] - prev_cpu[0]
                    di = cur_c[1] - prev_cpu[1]
                    data["cpu_pct"] = round((1 - di / dt) * 100, 1) if dt > 0 else 0.0
                else:
                    data["cpu_pct"] = 0.0
                prev_cpu = cur_c
            except Exception:
                data["cpu_pct"] = 0.0

            # Memory
            total_kb = 0
            try:
                mem_kb: dict = {}
                with open("/proc/meminfo") as f:
                    for line in f:
                        p = line.split()
                        if len(p) >= 2:
                            mem_kb[p[0].rstrip(":")] = int(p[1])
                total_kb = mem_kb.get("MemTotal", 0)
                avail_kb = mem_kb.get("MemAvailable", mem_kb.get("MemFree", 0))
                used_kb  = total_kb - avail_kb
                data["mem_total_mb"] = round(total_kb / 1024, 1)
                data["mem_used_mb"]  = round(used_kb  / 1024, 1)
                data["mem_pct"]      = round(used_kb / total_kb * 100, 1) if total_kb > 0 else 0.0
            except Exception:
                data.update({"mem_total_mb": 0, "mem_used_mb": 0, "mem_pct": 0.0})

            # Disk I/O
            try:
                rd = wr = 0
                with open("/proc/diskstats") as f:
                    for line in f:
                        p = line.split()
                        if len(p) < 14:
                            continue
                        nm = p[2]
                        # Skip partitions (sda1, vda1) but keep nvme0n1, mmcblk0
                        if nm[-1].isdigit() and not (nm.startswith("nvme") or nm.startswith("mmcblk")):
                            continue
                        rd += int(p[5]);  wr += int(p[9])
                cur_d = (rd, wr, now)
                if prev_disk:
                    dt2 = now - prev_disk[2]
                    if dt2 > 0:
                        data["disk_read_kbps"]  = round(max(0, (rd - prev_disk[0]) * 512 / 1024 / dt2), 1)
                        data["disk_write_kbps"] = round(max(0, (wr - prev_disk[1]) * 512 / 1024 / dt2), 1)
                    else:
                        data["disk_read_kbps"] = data["disk_write_kbps"] = 0.0
                else:
                    data["disk_read_kbps"] = data["disk_write_kbps"] = 0.0
                prev_disk = cur_d
            except Exception:
                data["disk_read_kbps"] = data["disk_write_kbps"] = 0.0

            # Load average
            try:
                with open("/proc/loadavg") as f:
                    p = f.read().split()
                data["load_avg"] = [float(p[0]), float(p[1]), float(p[2])]
            except Exception:
                data["load_avg"] = [0.0, 0.0, 0.0]

            # Top processes by CPU
            try:
                hz = 100
                try:
                    hz = os.sysconf("SC_CLK_TCK")
                except Exception:
                    pass
                procs = []
                for pid_s in os.listdir("/proc"):
                    if not pid_s.isdigit():
                        continue
                    pid = int(pid_s)
                    try:
                        with open(f"/proc/{pid}/stat") as f:
                            st = f.read().split()
                        name  = st[1].strip("()")
                        cpu_t = int(st[13]) + int(st[14])
                        vmrss = 0
                        with open(f"/proc/{pid}/status") as f:
                            for ln in f:
                                if ln.startswith("VmRSS:"):
                                    vmrss = int(ln.split()[1])
                                    break
                        procs.append({"pid": pid, "name": name, "cpu_t": cpu_t,
                                      "mem_mb": round(vmrss / 1024, 1)})
                    except Exception:
                        continue

                dt3 = now - prev_ts if prev_ts else 2.0
                for p in procs:
                    prev_t   = prev_procs.get(p["pid"], p["cpu_t"])
                    delta    = p["cpu_t"] - prev_t
                    p["cpu_pct"] = round(delta / hz / dt3 * 100, 1) if dt3 > 0 else 0.0
                    p["mem_pct"] = round(p["mem_mb"] * 1024 / total_kb * 100, 1) if total_kb > 0 else 0.0

                prev_procs = {p["pid"]: p["cpu_t"] for p in procs}
                for p in procs:
                    del p["cpu_t"]
                procs.sort(key=lambda x: (-x["cpu_pct"], -x["mem_mb"]))
                data["processes"] = procs[:12]
            except Exception:
                data["processes"] = []

            # Network I/O — read /proc/net/dev, sum across non-loopback interfaces
            try:
                net_rx = net_tx = 0
                with open("/proc/net/dev") as f:
                    for line in f:
                        p = line.split()
                        if len(p) < 10 or ":" not in p[0]:
                            continue
                        iface = p[0].rstrip(":")
                        if iface == "lo":
                            continue
                        net_rx += int(p[1])   # bytes received
                        net_tx += int(p[9])   # bytes transmitted
                cur_net = (net_rx, net_tx, now)
                prev_net = _health_cache.get("_net_raw")
                if prev_net:
                    dt4 = now - prev_net[2]
                    if dt4 > 0:
                        data["net_rx_kbps"] = round(max(0, (net_rx - prev_net[0]) / 1024 / dt4), 1)
                        data["net_tx_kbps"] = round(max(0, (net_tx - prev_net[1]) / 1024 / dt4), 1)
                    else:
                        data["net_rx_kbps"] = data["net_tx_kbps"] = 0.0
                else:
                    data["net_rx_kbps"] = data["net_tx_kbps"] = 0.0
                data["_net_raw"] = cur_net
            except Exception:
                data["net_rx_kbps"] = data["net_tx_kbps"] = 0.0

            prev_ts = now
            with _health_lock2:
                _health_cache.update(data)
        except Exception:
            pass

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
            "current_test": "", "iteration": 0,
            "status": "starting", "test_started_at": 0.0,
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


@app.route("/api/health")
def api_health():
    with _health_lock2:
        out = {k: v for k, v in _health_cache.items() if not k.startswith("_")}
    return jsonify(out)


@app.route("/api/control", methods=["POST"])
def api_control():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    d = request.get_json(silent=True) or {}

    # ── Action commands (pause / resume / stop) ────────────────────────────────
    action = d.get("action")
    if action:
        if action == "pause":
            try:
                open(_PAUSE_FILE, "w").close()
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            return jsonify({"ok": True, "action": "pause"})

        elif action == "resume":
            try:
                if os.path.exists(_PAUSE_FILE):
                    os.remove(_PAUSE_FILE)
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            return jsonify({"ok": True, "action": "resume"})

        elif action == "stop":
            try:
                open(_STOP_FILE, "w").close()
                if os.path.exists(_PAUSE_FILE):
                    os.remove(_PAUSE_FILE)
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            return jsonify({"ok": True, "action": "stop"})

        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400

    # ── Settings change ────────────────────────────────────────────────────────
    st    = _read_state()
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
        yield "retry: 2000\n\n"
        last_ka = time.time()
        while True:
            yield f"data: {json.dumps(_read_state(), separators=(',', ':'))}\n\n"
            time.sleep(2)
            # keepalive comment so proxies/browsers don't close idle connections
            if time.time() - last_ka > 15:
                yield ": ka\n\n"
                last_ka = time.time()
    return _sse_wrap(_gen)


@app.route("/log")
def sse_log():
    def _gen():
        yield "retry: 2000\n\n"
        try:
            with open(_LOG_FILE) as f:
                seed = f.readlines()[-100:]
            for ln in seed:
                ln = ln.strip()
                if ln:
                    yield f"data: {ln}\n\n"
        except FileNotFoundError:
            pass

        pos = 0
        try:
            with open(_LOG_FILE) as f:
                f.seek(0, 2)
                pos = f.tell()
        except FileNotFoundError:
            pass

        last_ka = time.time()
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
                        last_ka = time.time()
            except FileNotFoundError:
                pass
            # keepalive when log is quiet
            if time.time() - last_ka > 15:
                yield ": ka\n\n"
                last_ka = time.time()
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


# ── HTML placeholders (filled below) ──────────────────────────────────────────
_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>traffgen</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--sidebar:#0f1923;--surf:#161b22;--surf2:#1c2230;
  --border:#1e2d3d;--border2:#30363d;
  --green:#22c55e;--gdim:rgba(34,197,94,.1);
  --red:#f85149;--amber:#f59e0b;--blue:#58a6ff;
  --text:#e2e8f0;--muted:#64748b;--dim:#374151;--r:6px;--sw:220px;
}
html,body{height:100%;overflow:hidden}
body{display:flex;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:13px;line-height:1.5}
.sidebar{width:var(--sw);background:var(--sidebar);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;height:100vh;overflow-y:auto}
.sb-logo{display:flex;align-items:center;gap:10px;padding:13px 16px;border-bottom:1px solid var(--border)}
.logo-name{font-weight:700;font-size:15px;letter-spacing:-.3px;color:var(--text)}
.nav-lbl{padding:14px 16px 4px;font-size:9px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:var(--muted)}
.nav-item{display:flex;align-items:center;gap:9px;padding:7px 16px 7px 13px;color:var(--muted);cursor:pointer;border:none;background:none;width:100%;text-align:left;font-size:13px;border-left:3px solid transparent;transition:all .12s}
.nav-item:hover{color:var(--text);background:rgba(255,255,255,.04)}
.nav-item.active{color:var(--green);background:var(--gdim);border-left-color:var(--green);font-weight:500}
.nav-ico{width:16px;text-align:center;font-size:13px;opacity:.75}
.sb-foot{margin-top:auto;padding:12px 16px;border-top:1px solid var(--border)}
.sb-foot div{font-size:10px;color:var(--dim);margin-top:2px}
.main{flex:1;display:flex;flex-direction:column;min-width:0;height:100vh;overflow:hidden}
.topbar{height:48px;display:flex;align-items:center;gap:8px;padding:0 18px;border-bottom:1px solid var(--border);background:var(--sidebar);flex-shrink:0}
.pg-title{font-size:14px;font-weight:700;color:var(--text);letter-spacing:-.2px;margin-right:auto}
.tp-pill{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:20px;font-size:11px;font-weight:500;border:1px solid;white-space:nowrap}
.tp-running{border-color:var(--green);color:var(--green)}
.tp-paused{border-color:var(--amber);color:var(--amber)}
.tp-stopped{border-color:var(--red);color:var(--red)}
.tp-dim{border-color:var(--muted);color:var(--muted)}
.pulse{width:6px;height:6px;border-radius:50%;background:currentColor;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.ico-btn{width:30px;height:30px;border-radius:var(--r);border:1px solid var(--border2);background:var(--surf);color:var(--muted);cursor:pointer;display:grid;place-items:center;font-size:14px;transition:all .12s;flex-shrink:0}
.ico-btn:hover{border-color:var(--green);color:var(--green)}
.ico-btn.danger:hover{border-color:var(--red);color:var(--red)}
.content{flex:1;min-height:0;overflow:hidden;display:flex;flex-direction:column}
.panel{display:none;flex-direction:column;gap:14px;flex:1;overflow-y:auto;padding:18px}
.panel.active{display:flex}
#tab-output.panel{padding:0;gap:0;overflow:hidden}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
@media(max-width:1000px){.cards{grid-template-columns:repeat(2,1fr)}}
.card{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);padding:14px;display:flex;flex-direction:column;gap:3px;transition:border-color .15s}
.card:hover{border-color:var(--border2)}
.card.hi{border-color:rgba(34,197,94,.3);background:var(--gdim)}
.clbl{font-size:10px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted)}
.cval{font-size:22px;font-weight:700;font-family:'SF Mono',Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:2px}
.csub{font-size:11px;color:var(--muted);margin-top:1px}
.c-green{color:var(--green)}.c-red{color:var(--red)}.c-amber{color:var(--amber)}.c-blue{color:var(--blue)}.c-mut{color:var(--muted)}
.charts{display:grid;grid-template-columns:230px 1fr;gap:12px}
@media(max-width:860px){.charts{grid-template-columns:1fr}}
.cc{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);padding:14px}
.ctitle{font-size:10px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted);margin-bottom:10px;display:flex;justify-content:space-between;align-items:center}
.donut-wrap{display:flex;flex-direction:column;align-items:center;gap:10px}
.legend{display:flex;gap:12px;font-size:11px}
.leg{display:flex;align-items:center;gap:5px}
.leg-dot{width:7px;height:7px;border-radius:50%}
.tcard{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.thdr{padding:10px 14px 8px;font-size:10px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
table{width:100%;border-collapse:collapse;font-size:12px}
thead th{padding:6px 12px;text-align:left;font-size:10px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted);background:var(--surf2);border-bottom:1px solid var(--border)}
th.r,td.r{text-align:right}
tbody tr.mrow{border-bottom:1px solid var(--border);transition:background .1s;cursor:pointer}
tbody tr.mrow:hover{background:var(--surf2)}
tbody td{padding:6px 12px;font-family:'SF Mono',Consolas,monospace;font-size:11px}
td.nm{font-family:inherit;font-weight:500;font-size:12px}
.rw{display:flex;align-items:center;justify-content:flex-end;gap:5px}
.bt{width:40px;height:3px;background:var(--border2);border-radius:2px;overflow:hidden}
.bf{height:100%;border-radius:2px;transition:width .4s}
.xrow{display:none}
.xrow.open{display:table-row}
.xcell{padding:7px 12px 9px 26px;background:var(--surf2);font-size:11px;font-family:'SF Mono',Consolas,monospace;border-bottom:1px solid var(--border)}
.xinner{display:flex;flex-wrap:wrap;gap:14px}
.xi{display:flex;flex-direction:column;gap:2px}
.xl{font-size:9px;letter-spacing:.6px;text-transform:uppercase;color:var(--dim)}
.ctags{display:flex;flex-wrap:wrap;gap:4px;margin-top:2px}
.ctag{padding:1px 6px;border-radius:4px;font-size:10px;background:var(--surf);border:1px solid var(--border2);color:var(--muted)}
.chev{font-size:10px;color:var(--muted);transition:transform .15s;display:inline-block}
.chev.open{transform:rotate(90deg)}
.ecard{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.ehdr{padding:10px 14px 8px;font-size:10px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);display:flex;justify-content:space-between}
.ebody{max-height:200px;overflow-y:auto}
.ev-wrap{border-bottom:1px solid rgba(30,45,61,.6);cursor:pointer}
.ev-wrap:last-child{border-bottom:none}
.evrow{display:grid;grid-template-columns:78px 1fr 60px 58px 14px;gap:8px;padding:5px 12px;font-size:11px;font-family:'SF Mono',Consolas,monospace;align-items:center}
.evrow:hover{background:var(--surf2)}
.et{color:var(--muted)}.eok{color:var(--green)}.efail{color:var(--red)}.edur{color:var(--muted);text-align:right}
.echev{color:var(--dim);font-size:10px;transition:transform .15s}
.echev.open{transform:rotate(90deg)}
.evdet{display:none;padding:5px 12px 7px 24px;background:var(--surf2);font-size:11px;font-family:'SF Mono',Consolas,monospace;color:var(--muted)}
.evdet.open{display:block}
.tgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:12px}
.tcard2{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);padding:14px;display:flex;flex-direction:column;gap:7px;cursor:pointer;transition:border-color .15s,background .15s}
.tcard2:hover{border-color:var(--green);background:var(--gdim)}
.tcard2.running{border-color:rgba(34,197,94,.4);background:var(--gdim)}
.tcn{font-weight:600;font-size:13px;display:flex;align-items:center;gap:6px}
.badge{font-size:9px;padding:1px 6px;border-radius:10px;background:var(--gdim);color:var(--green);border:1px solid rgba(34,197,94,.3)}
.tcd{font-size:12px;color:var(--muted);line-height:1.4}
.tcs{display:flex;gap:10px;font-size:11px;font-family:'SF Mono',Consolas,monospace}
.tcbar{width:100%;height:2px;background:var(--border2);border-radius:1px;overflow:hidden;margin-top:1px}
.tcbf{height:100%;border-radius:1px;transition:width .4s}
.otb{display:flex;gap:6px;padding:8px 12px;background:var(--surf);border-bottom:1px solid var(--border);align-items:center;flex-shrink:0;flex-wrap:wrap}
.otlbl{font-size:10px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted);margin-right:auto}
.btn{padding:3px 10px;border-radius:var(--r);border:1px solid var(--border2);background:var(--surf2);color:var(--muted);font-size:11px;cursor:pointer;transition:all .12s}
.btn:hover{border-color:var(--green);color:var(--green)}
.btn.af{border-color:var(--green);color:var(--green);background:var(--gdim)}
.fgrp{display:flex;gap:4px}
.obody{flex:1;overflow-y:auto;min-height:0;font-family:'SF Mono',Consolas,monospace;font-size:12px;line-height:1.65;background:#080c10}
.ll{padding:1px 14px;display:flex;align-items:baseline;gap:0;white-space:pre-wrap;word-break:break-all}
.ll:hover{background:rgba(255,255,255,.025)}
.ll-sep{padding:5px 0;display:flex;align-items:center}
.sep-line{flex:1;height:1px;background:var(--dim);opacity:.35}
.sep-txt{padding:0 10px;font-size:10px;letter-spacing:.5px;color:var(--dim);white-space:nowrap}
.llt{color:#374151;margin-right:8px;flex-shrink:0;font-size:11px}
.llv{font-weight:700;margin-right:8px;flex-shrink:0;width:40px;font-size:11px}
.llm{color:#c9d1d9;flex:1}
.ll.info .llv{color:#60a5fa}.ll.ok .llv{color:#22c55e}
.ll.warn .llv{color:#f59e0b}.ll.error .llv{color:#f85149}.ll.debug .llv{color:#374151}
.a-hero{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);padding:22px;display:flex;align-items:center;gap:18px}
.a-title{font-size:20px;font-weight:700;letter-spacing:-.4px}
.a-ver{font-size:11px;color:var(--green);font-weight:600;margin-top:3px}
.a-sub{color:var(--muted);font-size:12px;margin-top:6px;line-height:1.55}
.a-section{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);padding:18px}
.a-h{font-size:10px;font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--green);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.lk-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px}
.lk{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid var(--border);border-radius:var(--r);background:var(--surf2);text-decoration:none;color:var(--text);transition:border-color .15s}
.lk:hover{border-color:var(--green)}
.lk-ico{font-size:18px;flex-shrink:0}
.lk-name{font-weight:600;font-size:13px}
.lk-url{font-size:10px;color:var(--muted);font-family:'SF Mono',Consolas,monospace}
.cmd-blk{background:#080c10;border:1px solid var(--border);border-radius:var(--r);padding:12px 14px;font-family:'SF Mono',Consolas,monospace;font-size:11px;line-height:1.85;color:#c9d1d9;white-space:pre-wrap;word-break:break-all}
.cmd-blk .cmt{color:#374151}.cmd-blk .flg{color:#60a5fa}
.pg-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:8px}
.pg-badge{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--surf2);border:1px solid var(--border);border-radius:var(--r);font-size:12px}
.st-table{width:100%;border-collapse:collapse;font-size:12px}
.st-table th{padding:5px 10px;text-align:left;font-size:10px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted)}
.st-table td{padding:5px 10px;border-top:1px solid var(--border);color:var(--muted)}
.st-table td:first-child{font-weight:500;color:var(--text);font-family:'SF Mono',Consolas,monospace;font-size:11px;white-space:nowrap}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:299}
.overlay.open{display:block}
.drawer{position:fixed;top:0;right:-380px;width:360px;height:100vh;background:var(--surf);border-left:1px solid var(--border);z-index:300;transition:right .22s;display:flex;flex-direction:column}
.drawer.open{right:0}
.dhdr{display:flex;align-items:center;justify-content:space-between;padding:13px 16px;border-bottom:1px solid var(--border)}
.dtitle{font-weight:600;font-size:14px}
.dbody{padding:16px;display:flex;flex-direction:column;gap:14px;flex:1;overflow-y:auto}
.field{display:flex;flex-direction:column;gap:5px}
.field label{font-size:10px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted)}
.field select{width:100%;padding:7px 10px;background:var(--bg);border:1px solid var(--border2);border-radius:var(--r);color:var(--text);font-size:12px;outline:none}
.field select:focus{border-color:var(--green)}
.rngw{display:flex;align-items:center;gap:10px}
.field input[type=range]{flex:1;accent-color:var(--green)}
.rngv{font-family:'SF Mono',Consolas,monospace;font-size:12px;color:var(--text);min-width:36px;text-align:right}
.togrow{display:flex;align-items:center;justify-content:space-between}
.toglbl{font-size:13px;color:var(--text)}
.tog{position:relative;width:38px;height:21px}
.tog input{opacity:0;width:0;height:0}
.tslider{position:absolute;inset:0;background:var(--dim);border-radius:21px;transition:.18s;cursor:pointer}
.tslider:before{content:"";position:absolute;width:15px;height:15px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.18s}
input:checked+.tslider{background:var(--green)}
input:checked+.tslider:before{transform:translateX(17px)}
.btn-p{width:100%;padding:9px;background:var(--green);color:#080c10;border:none;border-radius:var(--r);font-size:13px;font-weight:700;cursor:pointer;transition:opacity .12s}
.btn-p:hover{opacity:.85}
.fnote{font-size:11px;color:var(--muted);text-align:center;line-height:1.4}
.cur-cfg{display:flex;gap:5px;flex-wrap:wrap}
.cfg-chip{padding:2px 7px;border-radius:4px;font-size:10px;font-family:'SF Mono',Consolas,monospace;background:var(--surf2);border:1px solid var(--border2);color:var(--muted)}
.modal-ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:400;align-items:center;justify-content:center}
.modal-ov.open{display:flex}
.modal{background:var(--surf);border:1px solid var(--border2);border-radius:8px;width:min(480px,95vw);max-height:85vh;display:flex;flex-direction:column;overflow:hidden}
.modal-hdr{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--border)}
.modal-title{font-weight:700;font-size:14px}
.modal-body{padding:16px 18px;overflow-y:auto;display:flex;flex-direction:column;gap:12px}
.modal-desc{font-size:12px;color:var(--muted);line-height:1.5;padding:9px 11px;background:var(--surf2);border-radius:var(--r);border-left:3px solid var(--green)}
.mstats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.mstat{padding:8px 10px;background:var(--surf2);border-radius:var(--r);display:flex;flex-direction:column;gap:2px}
.mstat-lbl{font-size:9px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted)}
.mstat-val{font-size:16px;font-weight:700;font-family:'SF Mono',Consolas,monospace}
.modal-sep{font-size:10px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted);padding-bottom:4px;border-bottom:1px solid var(--border)}
.modal-ftr{padding:12px 18px;border-top:1px solid var(--border);display:flex;gap:8px}
.btn-run{flex:1;padding:9px;background:var(--green);color:#080c10;border:none;border-radius:var(--r);font-size:13px;font-weight:700;cursor:pointer;transition:opacity .12s}
.btn-run:hover{opacity:.85}
.btn-cancel{padding:9px 14px;border:1px solid var(--border2);background:var(--surf2);color:var(--muted);border-radius:var(--r);font-size:13px;cursor:pointer}
.toast{position:fixed;bottom:18px;right:18px;padding:9px 14px;border-radius:8px;font-size:12px;font-weight:500;z-index:500;display:none;pointer-events:none}
.toast.ok{background:rgba(34,197,94,.12);border:1px solid var(--green);color:var(--green)}
.toast.err{background:rgba(248,81,73,.12);border:1px solid var(--red);color:var(--red)}
.footer{padding:8px 18px;font-size:10px;color:var(--dim);border-top:1px solid var(--border);text-align:center;flex-shrink:0}
.footer a{color:var(--dim);text-decoration:none}.footer a:hover{color:var(--muted)}
.empty{padding:26px;text-align:center;color:var(--muted);font-size:12px}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--dim);border-radius:2px}
.mono{font-family:'SF Mono',Consolas,monospace;font-size:11px}
.h-gauges{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.h-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:700px){.h-gauges,.h-row{grid-template-columns:1fr}}
.gauge-wrap{display:flex;flex-direction:column;align-items:center;padding-top:4px}
.net-widget{display:flex;gap:16px;padding:6px 0;font-family:'SF Mono',Consolas,monospace;font-size:13px;align-items:center}
.net-dir{display:flex;flex-direction:column;gap:1px}
.net-lbl{font-size:9px;font-weight:600;letter-spacing:.6px;text-transform:uppercase;color:var(--muted)}
.net-val{font-size:15px;font-weight:700}
</style>
</head>
<body>
<!-- Sidebar -->
<aside class="sidebar">
  <div class="sb-logo">
    <svg viewBox="0 0 20 34" width="20" height="34" style="flex-shrink:0">
      <rect x="1" y=".5" width="18" height="33" rx="4" fill="#1e293b" stroke="#334155" stroke-width="1"/>
      <circle cx="10" cy="8" r="5.5" fill="#ef4444" opacity=".9"/>
      <circle cx="10" cy="17" r="5.5" fill="#f59e0b" opacity=".8"/>
      <circle cx="10" cy="26" r="5.5" fill="#22c55e" opacity=".9"/>
      <path d="M12 3.5L7 15h4.5L9 30.5l7-16h-4.5Z" fill="rgba(255,255,255,.88)" stroke="rgba(0,0,0,.15)" stroke-width=".5"/>
    </svg>
    <span class="logo-name">traffgen</span>
  </div>
  <div class="nav-lbl">Monitor</div>
  <button class="nav-item active" data-tab="overview" onclick="showTab(this)"><span class="nav-ico">◈</span>Overview</button>
  <button class="nav-item" data-tab="tests" onclick="showTab(this)"><span class="nav-ico">⚗</span>Tests</button>
  <button class="nav-item" data-tab="output" onclick="showTab(this)"><span class="nav-ico">⬛</span>Output</button>
  <div class="nav-lbl">System</div>
  <button class="nav-item" data-tab="health" onclick="showTab(this)"><span class="nav-ico">&#9889;</span>Health</button>
  <div class="nav-lbl">Info</div>
  <button class="nav-item" data-tab="about" onclick="showTab(this)"><span class="nav-ico">◎</span>About</button>
  <div class="nav-lbl">Control</div>
  <button class="nav-item" onclick="openDrawer()"><span class="nav-ico">⚙</span>Settings</button>
  <div class="sb-foot">
    <div>version <span id="s-ver">—</span></div>
    <div id="s-uptime">—</div>
  </div>
</aside>
<!-- Main -->
<div class="main">
  <div class="topbar">
    <span class="pg-title" id="pg-title">Overview</span>
    <span id="cfg-s-pill" class="mono" style="color:var(--muted)">—</span>
    <span id="cfg-z-pill" class="mono" style="color:var(--muted)">—</span>
    <span id="status-pill" class="tp-pill tp-dim"><span class="pulse"></span>Starting</span>
    <button id="btn-pause" class="ico-btn" onclick="togglePause()" title="Pause / Resume">&#9208;</button>
    <button class="ico-btn danger" onclick="stopTests()" title="Stop all tests">&#9209;</button>
    <button class="ico-btn" onclick="openDrawer()" title="Settings">&#9881;</button>
    <span id="pill-live" class="tp-pill tp-running" style="cursor:pointer" onclick="handleLiveClick()" title="Click to stop all tests"><span class="pulse"></span>LIVE</span>
  </div>
  <div class="content">
    <!-- Overview -->
    <div id="tab-overview" class="panel active">
      <div class="cards">
        <div class="card"><div class="clbl">Total Requests</div><div class="cval c-blue" id="v-total">&#8212;</div><div class="csub" id="s-total">&#8212;</div></div>
        <div class="card"><div class="clbl">Success Rate</div><div class="cval" id="v-rate">&#8212;</div><div class="csub" id="s-rate">&#8212;</div></div>
        <div class="card hi"><div class="clbl">Active Test</div><div class="cval c-green" id="v-test" style="font-size:15px">&#8212;</div><div class="csub" id="s-test">&#8212;</div></div>
        <div class="card"><div class="clbl">Iteration</div><div class="cval c-amber" id="v-iter">&#8212;</div><div class="csub" id="s-iter">&#8212;</div></div>
      </div>
      <div class="cc" style="display:flex;flex-direction:column;gap:10px">
        <div class="ctitle">Network I/O <span id="net-iface" style="font-weight:400;letter-spacing:0;text-transform:none;color:var(--dim);font-size:10px"></span></div>
        <div class="net-widget">
          <div class="net-dir"><div class="net-lbl">&#9650; TX</div><div class="net-val c-blue" id="ov-tx">&#8212;</div></div>
          <div style="width:1px;background:var(--border);align-self:stretch"></div>
          <div class="net-dir"><div class="net-lbl">&#9660; RX</div><div class="net-val c-green" id="ov-rx">&#8212;</div></div>
        </div>
        <canvas id="net-spark" style="width:100%;height:50px"></canvas>
      </div>
      <div class="charts">
        <div class="cc"><div class="ctitle">Success / Failure</div>
          <div class="donut-wrap">
            <canvas id="donut" width="170" height="170"></canvas>
            <div class="legend">
              <div class="leg"><div class="leg-dot" style="background:var(--green)"></div><span id="leg-ok">&#8212;</span></div>
              <div class="leg"><div class="leg-dot" style="background:var(--red)"></div><span id="leg-fail">&#8212;</span></div>
            </div>
          </div>
        </div>
        <div class="cc">
          <div class="ctitle">Requests Over Time <span id="hist-info" style="font-weight:400;letter-spacing:0;text-transform:none;font-size:10px;color:var(--dim)"></span></div>
          <canvas id="spark" style="width:100%;height:160px"></canvas>
        </div>
      </div>
      <div class="tcard">
        <div class="thdr">Test Breakdown <span style="color:var(--dim);font-weight:400;letter-spacing:0;text-transform:none;font-size:10px">&#8250; click row to expand</span></div>
        <table><thead><tr><th></th><th>Test</th><th class="r">Attempts</th><th class="r">OK</th><th class="r">Fail</th><th class="r">Rate</th><th class="r">Avg</th><th class="r">Last Run</th></tr></thead>
        <tbody id="tbl-body"><tr><td colspan="8" class="empty">Waiting for data&#8230;</td></tr></tbody></table>
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
    <div id="tab-output" class="panel">
      <div class="otb">
        <span class="otlbl">Live Output</span>
        <div class="fgrp">
          <button class="btn af" data-lvl="all" onclick="setFilter(this,'all')">All</button>
          <button class="btn" data-lvl="ok" onclick="setFilter(this,'ok')">OK</button>
          <button class="btn" data-lvl="warn" onclick="setFilter(this,'warn')">Warn</button>
          <button class="btn" data-lvl="error" onclick="setFilter(this,'error')">Error</button>
          <button class="btn" data-lvl="debug" onclick="setFilter(this,'debug')">Debug</button>
        </div>
        <button class="btn" onclick="$('obody').innerHTML='';_lastTest=null">Clear</button>
        <button class="btn" onclick="window.open('/log-view','tg-log','width=960,height=680,scrollbars=yes')">Pop Out &#8599;</button>
        <button class="btn" id="btn-as" onclick="toggleAS()">Auto-scroll &#10003;</button>
      </div>
      <div class="obody" id="obody"></div>
    </div>
    <!-- Health -->
    <div id="tab-health" class="panel">
      <div class="h-gauges">
        <div class="cc"><div class="ctitle">CPU Usage</div>
          <div class="gauge-wrap"><canvas id="cpu-gauge" width="200" height="130"></canvas></div>
        </div>
        <div class="cc"><div class="ctitle">Memory Usage</div>
          <div class="gauge-wrap">
            <canvas id="mem-gauge" width="200" height="130"></canvas>
            <div id="mem-detail" style="font-size:11px;color:var(--muted);margin-top:4px">&#8212; MB / &#8212; MB used</div>
          </div>
        </div>
      </div>
      <div class="h-row">
        <div class="cc">
          <div class="ctitle">Load Average <span style="font-weight:400;letter-spacing:0;text-transform:none;color:var(--dim)">1m &middot; 5m &middot; 15m</span></div>
          <div id="h-load" style="font-family:'SF Mono',Consolas,monospace;font-size:18px;color:var(--green);padding:8px 0 4px">&#8212; &middot; &#8212; &middot; &#8212;</div>
        </div>
        <div class="cc">
          <div class="ctitle">Disk I/O</div>
          <div style="display:flex;gap:16px;margin-bottom:8px;font-family:'SF Mono',Consolas,monospace;font-size:12px">
            <span><span style="color:var(--muted)">Read: </span><span id="disk-read" style="color:var(--green)">&#8212;</span></span>
            <span><span style="color:var(--muted)">Write: </span><span id="disk-write" style="color:var(--blue)">&#8212;</span></span>
          </div>
          <canvas id="disk-bars" width="300" height="58" style="width:100%"></canvas>
        </div>
      </div>
      <div class="cc">
        <div class="ctitle">Network I/O <span id="h-net-iface" style="font-weight:400;letter-spacing:0;text-transform:none;color:var(--dim)"></span></div>
        <div style="display:flex;gap:24px;font-family:'SF Mono',Consolas,monospace;font-size:13px;margin-top:6px">
          <div><div style="font-size:9px;font-weight:600;letter-spacing:.6px;text-transform:uppercase;color:var(--muted)">&#9660; Receive</div><div id="h-rx" class="c-green" style="font-size:20px;font-weight:700;margin-top:3px">&#8212;</div></div>
          <div><div style="font-size:9px;font-weight:600;letter-spacing:.6px;text-transform:uppercase;color:var(--muted)">&#9650; Transmit</div><div id="h-tx" class="c-blue" style="font-size:20px;font-weight:700;margin-top:3px">&#8212;</div></div>
        </div>
        <canvas id="h-net-spark" width="600" height="60" style="width:100%;margin-top:10px"></canvas>
      </div>
      <div class="tcard">
        <div class="thdr">Top Processes <span style="color:var(--dim);font-weight:400;letter-spacing:0;text-transform:none;font-size:10px">sorted by CPU</span></div>
        <table><thead><tr><th class="r">PID</th><th>Name</th><th class="r">CPU%</th><th class="r">Mem%</th><th class="r">RSS</th></tr></thead>
        <tbody id="proc-body"><tr><td colspan="5" class="empty">Loading&#8230;</td></tr></tbody></table>
      </div>
    </div>
    <!-- About -->
    <div id="tab-about" class="panel">
      <div class="a-hero">
        <svg viewBox="0 0 20 34" width="44" height="74" style="flex-shrink:0">
          <rect x="1" y=".5" width="18" height="33" rx="4" fill="#1e293b" stroke="#334155" stroke-width="1"/>
          <circle cx="10" cy="8" r="5.5" fill="#ef4444" opacity=".9"/>
          <circle cx="10" cy="17" r="5.5" fill="#f59e0b" opacity=".8"/>
          <circle cx="10" cy="26" r="5.5" fill="#22c55e" opacity=".9"/>
          <path d="M12 3.5L7 15h4.5L9 30.5l7-16h-4.5Z" fill="rgba(255,255,255,.88)" stroke="rgba(0,0,0,.15)" stroke-width=".5"/>
        </svg>
        <div>
          <div class="a-title">traffgen</div>
          <div class="a-ver">v<span id="about-ver">&#8212;</span> &middot; Multi-Protocol Network Traffic Generator</div>
          <div class="a-sub">Simulates realistic network traffic across 47+ test suites &#8212; DNS, HTTP/S, BGP, SSH, C2 beacons, DLP, Metasploit checks, and more.<br>Purpose-built to stress-test firewalls, IDS/IPS, URL filters, DLP engines, CASB platforms, and SIEM pipelines.</div>
        </div>
      </div>
      <div class="a-section">
        <div class="a-h">Links &amp; Resources</div>
        <div class="lk-grid">
          <a class="lk" href="https://github.com/jdibby/traffgen" target="_blank" rel="noopener"><span class="lk-ico">&#9415;</span><div><div class="lk-name">GitHub Repository</div><div class="lk-url">github.com/jdibby/traffgen</div></div></a>
          <a class="lk" href="https://hub.docker.com/r/jdibby/traffgen" target="_blank" rel="noopener"><span class="lk-ico">&#127987;</span><div><div class="lk-name">Docker Hub</div><div class="lk-url">hub.docker.com/r/jdibby/traffgen</div></div></a>
        </div>
      </div>
      <div class="a-section">
        <div class="a-h">Quick Start</div>
        <div class="cmd-blk"><span class="cmt"># Run all suites in a continuous loop with web dashboard</span>
docker run --pull=always --detach --restart unless-stopped \
  <span class="flg">-p 7777:7777</span> --name traffgen jdibby/traffgen:latest \
  --suite=all --size=XS --max-wait-secs=20 --loop

<span class="cmt"># One-command install on fresh host (Ubuntu / Debian / Rocky / Raspberry Pi)</span>
sudo bash &lt; &lt;(curl -s https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh)

<span class="cmt"># Run a specific suite once</span>
docker run --pull=always -it jdibby/traffgen:latest --suite=dns --size=L</div>
      </div>
      <div class="a-section">
        <div class="a-h">Supported Platforms</div>
        <div class="pg-grid">
          <div class="pg-badge">&#128421; linux/amd64 (x86-64)</div>
          <div class="pg-badge">&#127822; linux/arm64 (Apple Silicon, AWS Graviton)</div>
          <div class="pg-badge">&#127823; linux/arm/v7 (Raspberry Pi 4)</div>
        </div>
      </div>
      <div class="a-section">
        <div class="a-h">Test Suite Categories</div>
        <table class="st-table">
          <tr><th>Category</th><th>Suites</th></tr>
          <tr><td>Connectivity</td><td style="color:var(--text)">dns &middot; icmp &middot; bgp &middot; ntp &middot; ssh</td></tr>
          <tr><td>Web &amp; HTTP</td><td style="color:var(--text)">https_random &middot; crawl &middot; ftp &middot; web_scanning</td></tr>
          <tr><td>Threat Simulation</td><td style="color:var(--text)">c2_beacons &middot; malware_download &middot; ransomware_sim &middot; phishing_probes</td></tr>
          <tr><td>Data Exfiltration</td><td style="color:var(--text)">dns_exfil &middot; dns_tunneling &middot; doh &middot; dot</td></tr>
          <tr><td>DLP / AI</td><td style="color:var(--text)">ai_llm_dlp &middot; dlp_http</td></tr>
          <tr><td>Security Tools</td><td style="color:var(--text)">nmap &middot; metasploit &middot; nikto &middot; snmp</td></tr>
          <tr><td>all</td><td style="color:var(--text)">Shuffled rotation of every suite</td></tr>
        </table>
      </div>
      <div class="a-section">
        <div class="a-h">CLI Reference</div>
        <table class="st-table">
          <tr><th>Flag</th><th>Values</th><th>Default</th><th>Description</th></tr>
          <tr><td>--suite</td><td style="color:var(--text)">any suite name</td><td>all</td><td>Test suite to run</td></tr>
          <tr><td>--size</td><td style="color:var(--text)">XS S M L XL</td><td>XS</td><td>Traffic volume / intensity</td></tr>
          <tr><td>--loop</td><td style="color:var(--text)">flag</td><td>off</td><td>Loop forever, random suite each iteration</td></tr>
          <tr><td>--max-wait-secs</td><td style="color:var(--text)">integer</td><td>20</td><td>Max pause between iterations</td></tr>
          <tr><td>--nowait</td><td style="color:var(--text)">flag</td><td>off</td><td>Skip all inter-test pauses</td></tr>
        </table>
      </div>
      <div class="a-section">
        <div class="a-h">Web Dashboard</div>
        <div style="color:var(--muted);font-size:12px;line-height:1.6">
          Runs on HTTPS port 7777. Uses a self-signed TLS certificate &#8212; your browser will show a certificate warning the first time; this is expected and safe.<br><br>
          Use <strong style="color:var(--text)">Settings</strong> to change suite, size, and wait times. Changes apply at the next test boundary without restarting the container.
          Use <strong style="color:var(--text)">&#9208; Pause</strong> to temporarily halt traffic and <strong style="color:var(--text)">&#9209; Stop</strong> to halt all tests.
          Click the <strong style="color:var(--green)">&#9679; LIVE</strong> indicator in the top-right as a shortcut to stop all tests.
        </div>
      </div>
    </div>
  </div><!-- /.content -->
  <div class="footer">traffgen &middot; HTTPS :7777 &middot; <a href="https://github.com/jdibby/traffgen" target="_blank" rel="noopener">github.com/jdibby/traffgen</a> &middot; <a href="https://hub.docker.com/r/jdibby/traffgen" target="_blank" rel="noopener">hub.docker.com/r/jdibby/traffgen</a></div>
</div><!-- /.main -->
<!-- Settings Drawer -->
<div class="overlay" id="overlay" onclick="closeDrawer()"></div>
<div class="drawer" id="drawer">
  <div class="dhdr"><span class="dtitle">Settings</span><button class="ico-btn" onclick="closeDrawer()">&#10005;</button></div>
  <div class="dbody">
    <div style="font-size:10px;color:var(--muted)">Current configuration:</div>
    <div class="cur-cfg" id="cur-cfg">&#8212;</div>
    <div class="field"><label>Suite</label><select id="cfg-suite"><option value="all">all &#8212; run everything</option></select></div>
    <div class="field"><label>Size</label>
      <select id="cfg-size">
        <option value="XS">XS &#8212; Extra Small (minimal)</option>
        <option value="S">S &#8212; Small</option>
        <option value="M">M &#8212; Medium</option>
        <option value="L">L &#8212; Large</option>
        <option value="XL">XL &#8212; Extra Large</option>
      </select>
    </div>
    <div class="field"><label>Max Wait Between Tests</label>
      <div class="rngw"><input type="range" id="cfg-wait" min="5" max="300" step="5" value="20" oninput="$('wait-val').textContent=this.value+'s'"><span class="rngv" id="wait-val">20s</span></div>
    </div>
    <div class="field"><div class="togrow"><span class="toglbl">Loop Mode</span><label class="tog"><input type="checkbox" id="cfg-loop" checked><span class="tslider"></span></label></div></div>
    <div class="field"><div class="togrow"><span class="toglbl">No Wait (skip pauses)</span><label class="tog"><input type="checkbox" id="cfg-nowait"><span class="tslider"></span></label></div></div>
    <button class="btn-p" onclick="applySettings()">Apply &amp; Restart</button>
    <p class="fnote">New settings apply at the next test boundary without restarting the container.</p>
  </div>
</div>
<!-- Test Modal -->
<div class="modal-ov" id="modal-ov" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="modal-hdr"><span class="modal-title" id="modal-name">Test</span><button class="ico-btn" onclick="closeModal()">&#10005;</button></div>
    <div class="modal-body">
      <div class="modal-desc" id="modal-desc">&#8212;</div>
      <div>
        <div class="modal-sep" style="margin-bottom:10px">Statistics</div>
        <div class="mstats">
          <div class="mstat"><div class="mstat-lbl">Attempts</div><div class="mstat-val c-mut" id="ms-att">&#8212;</div></div>
          <div class="mstat"><div class="mstat-lbl">OK</div><div class="mstat-val c-green" id="ms-ok">&#8212;</div></div>
          <div class="mstat"><div class="mstat-lbl">Fail</div><div class="mstat-val c-red" id="ms-fail">&#8212;</div></div>
        </div>
      </div>
      <div>
        <div class="modal-sep" style="margin-bottom:10px">Run Configuration</div>
        <div class="field" style="margin-bottom:10px"><label>Size</label>
          <select id="modal-size"><option value="XS">XS</option><option value="S">S</option><option value="M">M</option><option value="L">L</option><option value="XL">XL</option></select>
        </div>
        <div class="field" style="margin-bottom:10px"><label>Max Wait</label>
          <div class="rngw"><input type="range" id="modal-wait" min="5" max="300" step="5" value="20" oninput="$('modal-wv').textContent=this.value+'s'"><span class="rngv" id="modal-wv">20s</span></div>
        </div>
        <div class="field"><div class="togrow"><span class="toglbl">Loop Mode</span><label class="tog"><input type="checkbox" id="modal-loop"><span class="tslider"></span></label></div></div>
      </div>
    </div>
    <div class="modal-ftr">
      <button class="btn-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-run" onclick="runFromModal()">&#9654; Run This Test</button>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
const $=id=>document.getElementById(id);
const H=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const N=n=>Number(n).toLocaleString();
const Tc=ts=>new Date(ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});
const Ts=ts=>new Date(ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
const Dur=ms=>ms<1000?ms+'ms':(ms/1000).toFixed(1)+'s';
const RC=p=>p>=90?'var(--green)':p>=70?'var(--amber)':'var(--red)';
let _start=null,_uptimer=null,_elTimer=null,_autoScroll=true;
let _lastState=null,_logEs=null,_logFilter='all';
let _xRows=new Set(),_xEvs=new Set(),_modalSuite=null,_isPaused=false,_lastTest=null;
let _healthTimer=null,_lastHealth=null,_netHist=[],_hNetHist=[];
function uptime(t){const s=Math.floor(Date.now()/1000-t);return[Math.floor(s/3600),Math.floor((s%3600)/60),s%60].map(v=>String(v).padStart(2,'0')).join(':');}
function elapsed(t){if(!t)return'';const s=Math.floor(Date.now()/1000-t);if(s<60)return s+'s elapsed';if(s<3600)return Math.floor(s/60)+'m '+(s%60)+'s elapsed';return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m elapsed';}
const PAGE_TITLES={overview:'Overview',tests:'Tests',output:'Output',health:'Health',about:'About'};
function showTab(btn){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  btn.classList.add('active');
  $('tab-'+btn.dataset.tab).classList.add('active');
  $('pg-title').textContent=PAGE_TITLES[btn.dataset.tab]||btn.dataset.tab;
  if(btn.dataset.tab==='output')connectLog();
  clearInterval(_healthTimer);_healthTimer=null;
  if(btn.dataset.tab==='health'){pollHealth();_healthTimer=setInterval(pollHealth,2500);}
}
function drawDonut(ok,fail){
  const c=$('donut'),ctx=c.getContext('2d'),W=c.width,H2=c.height,cx=W/2,cy=H2/2,r=66,ri=46;
  const tot=ok+fail;ctx.clearRect(0,0,W,H2);
  if(!tot){ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.arc(cx,cy,ri,0,Math.PI*2,true);ctx.fillStyle='#1e2d3d';ctx.fill('evenodd');ctx.fillStyle='#64748b';ctx.font='11px system-ui';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText('No data',cx,cy);return;}
  const okA=(ok/tot)*Math.PI*2,s=-Math.PI/2;
  ctx.beginPath();ctx.arc(cx,cy,r,s,s+okA);ctx.arc(cx,cy,ri,s+okA,s,true);ctx.fillStyle='#22c55e';ctx.fill();
  if(fail>0){ctx.beginPath();ctx.arc(cx,cy,r,s+okA,s+Math.PI*2);ctx.arc(cx,cy,ri,s+Math.PI*2,s+okA,true);ctx.fillStyle='#f85149';ctx.fill();}
  ctx.fillStyle='#e2e8f0';ctx.font='bold 17px SF Mono,Consolas,monospace';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(((ok/tot)*100).toFixed(1)+'%',cx,cy-6);
  ctx.fillStyle='#64748b';ctx.font='10px system-ui';ctx.fillText('success',cx,cy+9);
}
function drawSpark(history){
  const c=$('spark'),rect=c.getBoundingClientRect();c.width=Math.floor(rect.width)||500;c.height=Math.floor(rect.height)||160;
  const ctx=c.getContext('2d'),W=c.width,H2=c.height,P={t:10,r:10,b:22,l:36},IW=W-P.l-P.r,IH=H2-P.t-P.b;
  ctx.clearRect(0,0,W,H2);
  if(!history||history.length<2){ctx.fillStyle='#64748b';ctx.font='11px system-ui';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText('Accumulating data…',W/2,H2/2);return;}
  const okV=history.map(p=>p.ok||0),failV=history.map(p=>p.fail||0),mx=Math.max(...okV,...failV,1);
  const xOf=i=>P.l+(i/(history.length-1))*IW,yOf=v=>P.t+IH-(v/mx)*IH;
  ctx.strokeStyle='#1e2d3d';ctx.lineWidth=1;
  for(let i=0;i<=4;i++){const y=P.t+(i/4)*IH;ctx.beginPath();ctx.moveTo(P.l,y);ctx.lineTo(P.l+IW,y);ctx.stroke();ctx.fillStyle='#374151';ctx.font='9px SF Mono,Consolas,monospace';ctx.textAlign='right';ctx.fillText(Math.round(mx*(1-i/4)),P.l-4,y+3);}
  ctx.beginPath();history.forEach((p,i)=>{const x=xOf(i),y=yOf(p.ok||0);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y)});
  ctx.lineTo(xOf(history.length-1),P.t+IH);ctx.lineTo(xOf(0),P.t+IH);ctx.closePath();
  const g=ctx.createLinearGradient(0,P.t,0,P.t+IH);g.addColorStop(0,'rgba(34,197,94,.22)');g.addColorStop(1,'rgba(34,197,94,.01)');ctx.fillStyle=g;ctx.fill();
  ctx.beginPath();history.forEach((p,i)=>{const x=xOf(i),y=yOf(p.ok||0);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y)});
  ctx.strokeStyle='#22c55e';ctx.lineWidth=2;ctx.lineJoin='round';ctx.stroke();
  if(failV.some(v=>v>0)){ctx.beginPath();history.forEach((p,i)=>{const x=xOf(i),y=yOf(p.fail||0);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y)});ctx.strokeStyle='#f85149';ctx.lineWidth=1.5;ctx.setLineDash([4,3]);ctx.stroke();ctx.setLineDash([]);}
  ctx.fillStyle='#374151';ctx.font='9px SF Mono,Consolas,monospace';ctx.textAlign='left';ctx.fillText(Ts(history[0].t),P.l,H2-3);ctx.textAlign='right';ctx.fillText(Ts(history[history.length-1].t),P.l+IW,H2-3);
}
const ST_CLS={running:'tp-running',between_tests:'tp-dim',paused:'tp-paused',stopped:'tp-stopped',starting:'tp-dim'};
const ST_LBL={running:'Running',between_tests:'Between Tests',paused:'Paused',stopped:'Stopped',starting:'Starting'};
function apply(s){
  _lastState=s;
  const ver=s.version||'—';
  $('s-ver').textContent=ver;$('about-ver').textContent=ver;
  if(s.started_at&&!_start){_start=s.started_at;clearInterval(_uptimer);_uptimer=setInterval(()=>$('s-uptime').textContent='up '+uptime(_start),1000);}
  const st=s.status||'starting';
  const pill=$('status-pill');pill.className='tp-pill '+(ST_CLS[st]||'tp-dim');
  const dot=st==='running'||st==='starting';pill.innerHTML=(dot?'<span class="pulse"></span>':'')+(ST_LBL[st]||st);
  _isPaused=(st==='paused');$('btn-pause').innerHTML=_isPaused?'&#9654;':'&#9208;';$('btn-pause').title=_isPaused?'Resume tests':'Pause tests';
  const lp=$('pill-live');if(st==='stopped'){lp.className='tp-pill tp-stopped';lp.innerHTML='&#9209; STOPPED';}else{lp.className='tp-pill tp-running';lp.innerHTML='<span class="pulse"></span>LIVE';}
  $('cfg-s-pill').textContent='suite:'+(s.suite||'—');$('cfg-z-pill').textContent='size:'+(s.size||'—');
  const tot=s.totals||{},ok=tot.ok||0,fail=tot.fail||0,att=tot.attempts||0,p=att?ok/att*100:0;
  $('v-total').textContent=N(att);$('s-total').textContent=N(ok)+' ok \xb7 '+N(fail)+' fail';
  $('v-rate').textContent=att?p.toFixed(1)+'%':'—';$('v-rate').style.color=att?RC(p):'var(--muted)';$('s-rate').textContent=att?N(att)+' total requests':'No data yet';
  const cur=s.current_test||'',tsa=s.test_started_at||0;
  $('v-test').textContent=cur?cur.replace(/_/g,' '):'—';
  if(tsa&&cur){clearInterval(_elTimer);const upEl=()=>$('s-test').textContent=elapsed(tsa);upEl();_elTimer=setInterval(upEl,1000);}
  else{clearInterval(_elTimer);$('s-test').textContent=s.loop?'Loop mode':'Single-run';}
  $('v-iter').textContent=s.iteration?'#'+N(s.iteration):'—';$('s-iter').textContent='Suite: '+(s.suite||'—')+' \xb7 Size: '+(s.size||'—');
  drawDonut(ok,fail);$('leg-ok').textContent=N(ok)+' OK';$('leg-fail').textContent=N(fail)+' Fail';
  const hist=s.history||[];drawSpark(hist);if(hist.length>1)$('hist-info').textContent=hist.length+' samples';
  const tests=s.tests||{},names=Object.keys(tests).sort(),tb=$('tbl-body');
  if(!names.length){tb.innerHTML='<tr><td colspan="8" class="empty">Waiting…</td></tr>';}
  else tb.innerHTML=names.map(n=>{
    const t=tests[n],ta=t.attempts||0,tok=t.ok||0,tf=t.fail||0,tp=ta?tok/ta*100:0;
    const bc=RC(tp),lr=t.last_run_at?Tc(t.last_run_at):'—',act=n===cur,exp=_xRows.has(n);
    const codes=t.codes||{};
    const ctags=Object.entries(codes).sort().map(([k,v])=>`<span class="ctag">${H(k)}: ${N(v)}</span>`).join('');
    return`<tr class="mrow${act?' style="background:rgba(34,197,94,.04)"':''}" onclick="toggleRow('${n}')">
      <td><span class="chev${exp?' open':''}">&#8250;</span></td>
      <td class="nm">${act?'<span style="color:var(--green)">&#9654; </span>':''}${H(n.replace(/_/g,' '))}</td>
      <td class="r">${N(ta)}</td><td class="r" style="color:var(--green)">${N(tok)}</td>
      <td class="r" style="color:${tf?'var(--red)':'var(--muted)'}">${N(tf)}</td>
      <td class="r"><div class="rw"><span style="color:${bc}">${ta?tp.toFixed(1)+'%':'—'}</span><div class="bt"><div class="bf" style="width:${tp}%;background:${bc}"></div></div></div></td>
      <td class="r">${t.avg_dur_ms?Dur(t.avg_dur_ms):'—'}</td>
      <td class="r" style="color:var(--muted)">${lr}</td>
    </tr>
    <tr class="xrow${exp?' open':''}"><td class="xcell" colspan="8"><div class="xinner">
      <div class="xi"><div class="xl">Last Dur</div>${t.last_dur_ms?Dur(t.last_dur_ms):'—'}</div>
      <div class="xi"><div class="xl">Avg Dur</div>${t.avg_dur_ms?Dur(t.avg_dur_ms):'—'}</div>
      <div class="xi"><div class="xl">Responses</div>${N(t.responses||0)}</div>
      <div class="xi"><div class="xl">HTTP Codes</div><div class="ctags">${ctags||'<span style="color:var(--dim)">none yet</span>'}</div></div>
    </div></td></tr>`;
  }).join('');
  const evs=(s.events||[]).slice().reverse().slice(0,30),eb=$('ev-body');
  $('ev-cnt').textContent=evs.length?' \xb7 '+evs.length+' events':'';
  eb.innerHTML=!evs.length?'<div class="empty">Waiting…</div>':evs.map((e,i)=>{
    const exp=_xEvs.has(i);
    const codes=e.codes&&Object.keys(e.codes).length?Object.entries(e.codes).sort().map(([k,v])=>k+':'+v).join(' \xb7 '):'';
    return`<div class="ev-wrap" onclick="toggleEv(${i})"><div class="evrow">
      <span class="et">${Tc(e.t)}</span>
      <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${H((e.test||'').replace(/_/g,' '))}</span>
      <span class="${e.ok?'eok':'efail'}">${e.ok?'✓ OK':'✗ FAIL'}</span>
      <span class="edur">${e.dur_ms!=null?Dur(e.dur_ms):'—'}</span>
      <span class="echev${exp?' open':''}">&#8250;</span>
    </div>
    <div class="evdet${exp?' open':''}">suite: ${H(e.test||'—')} \xb7 result: ${e.ok?'OK':'FAIL'} \xb7 dur: ${e.dur_ms!=null?Dur(e.dur_ms):'—'} \xb7 responses: ${e.responses||0}${codes?' \xb7 codes: '+H(codes):''}</div>
    </div>`;
  }).join('');
  const suites=s.suites||[],tg=$('test-grid');
  if(!suites.length){tg.innerHTML='<div class="empty">Waiting for data…</div>';}
  else tg.innerHTML=suites.map(su=>{
    const td=tests[su.name]||{},ta=td.attempts||0,tok=td.ok||0,tf=td.fail||0,tp=ta?tok/ta*100:0;
    const bc=RC(tp),act=su.name===cur;
    return`<div class="tcard2${act?' running':''}" data-suite="${H(su.name)}" data-desc="${H(su.description||'')}" onclick="openModal(this.dataset.suite,this.dataset.desc)">
      <div class="tcn">${H(su.name.replace(/_/g,' '))}${act?'<span class="badge">RUNNING</span>':''}</div>
      <div class="tcd">${H(su.description||'—')}</div>
      <div class="tcs"><span style="color:var(--muted)">${N(ta)} attempts</span><span style="color:var(--green)">${N(tok)} ok</span><span style="color:${tf?'var(--red)':'var(--muted)'}">${N(tf)} fail</span>${ta?'<span style="color:'+bc+'">'+tp.toFixed(1)+'%</span>':''}</div>
      ${ta?`<div class="tcbar"><div class="tcbf" style="width:${tp}%;background:${bc}"></div></div>`:''}
    </div>`;
  }).join('');
  if(!$('drawer').classList.contains('open')){
    const sel=$('cfg-suite');
    if(sel.options.length<=1&&suites.length){suites.forEach(su=>{const o=document.createElement('option');o.value=su.name;o.textContent=su.name+' — '+su.description;sel.appendChild(o);});}
    sel.value=s.suite||'all';$('cfg-size').value=s.size||'XS';$('cfg-wait').value=s.max_wait_secs||20;$('wait-val').textContent=(s.max_wait_secs||20)+'s';$('cfg-loop').checked=!!s.loop;
  }
  $('cur-cfg').innerHTML=`<span class="cfg-chip">suite:${H(s.suite||'—')}</span><span class="cfg-chip">size:${H(s.size||'—')}</span><span class="cfg-chip">wait:${s.max_wait_secs||20}s</span><span class="cfg-chip">${s.loop?'loop':'single'}</span>`;
}
function toggleRow(n){if(_xRows.has(n))_xRows.delete(n);else _xRows.add(n);if(_lastState)apply(_lastState);}
function toggleEv(i){if(_xEvs.has(i))_xEvs.delete(i);else _xEvs.add(i);if(_lastState)apply(_lastState);}
function connect(){
  const es=new EventSource('/events');
  es.onmessage=ev=>{try{apply(JSON.parse(ev.data))}catch(e){}};
  es.onerror=()=>{es.close();$('pill-live').className='tp-pill tp-paused';$('pill-live').innerHTML='⚠ RECONNECT';setTimeout(connect,3000);};
}
function connectLog(){
  if(_logEs)return;
  _logEs=new EventSource('/log');
  _logEs.onmessage=ev=>{try{appendLog(JSON.parse(ev.data))}catch(e){}};
  _logEs.onerror=()=>{_logEs.close();_logEs=null;setTimeout(connectLog,3000);};
}
function setFilter(btn,lvl){
  _logFilter=lvl;
  document.querySelectorAll('.fgrp .btn').forEach(b=>b.classList.remove('af'));btn.classList.add('af');
  document.querySelectorAll('#obody .ll').forEach(el=>{if(el.classList.contains('ll-sep'))return;el.style.display=(lvl==='all'||el.classList.contains(lvl))?'':'none';});
}
function appendLog(d){
  const b=$('obody'),lvl=d.level||'info';
  if(_logFilter!=='all'&&lvl!==_logFilter)return;
  const test=d.test||'';
  if(test&&test!==_lastTest){
    _lastTest=test;
    const sep=document.createElement('div');sep.className='ll ll-sep';
    sep.innerHTML=`<div class="sep-line"></div><div class="sep-txt">${H(test.replace(/_/g,' '))}</div><div class="sep-line"></div>`;
    b.appendChild(sep);
  }
  const div=document.createElement('div');div.className='ll '+lvl;
  const ts=Tc(d.t||Date.now()/1000);
  div.innerHTML=`<span class="llt">${ts}</span><span class="llv">${H(lvl.toUpperCase().slice(0,5).padEnd(5))}</span><span class="llm">${H(d.msg||'')}</span>`;
  if(_logFilter!=='all'&&!div.classList.contains(_logFilter))div.style.display='none';
  b.appendChild(div);
  if(_autoScroll)b.scrollTop=b.scrollHeight;
  while(b.children.length>600)b.removeChild(b.firstChild);
}
function toggleAS(){_autoScroll=!_autoScroll;$('btn-as').innerHTML='Auto-scroll '+(_autoScroll?'&#10003;':'&#10007;');}
function openDrawer(){$('drawer').classList.add('open');$('overlay').classList.add('open');}
function closeDrawer(){$('drawer').classList.remove('open');$('overlay').classList.remove('open');}
function toast(msg,ok){const t=$('toast');t.textContent=msg;t.className='toast '+(ok?'ok':'err');t.style.display='block';setTimeout(()=>t.style.display='none',3500);}
function applySettings(){
  const body={suite:$('cfg-suite').value,size:$('cfg-size').value,max_wait_secs:parseInt($('cfg-wait').value),loop:$('cfg-loop').checked,nowait:$('cfg-nowait').checked};
  fetch('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(r=>r.json()).then(d=>{if(d.ok){toast('Settings applied — restarting at next boundary…',true);closeDrawer();}else toast('Error: '+d.error,false);})
    .catch(()=>toast('Request failed',false));
}
function togglePause(){
  const action=_isPaused?'resume':'pause';
  fetch('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})})
    .then(r=>r.json()).then(d=>{if(d.ok)toast(action==='pause'?'Tests paused — will stop after current test':'Tests resuming…',true);else toast('Error: '+d.error,false);})
    .catch(()=>toast('Request failed',false));
}
function stopTests(){
  if(!confirm('Stop all tests? Traffic generation will halt until the container is restarted.'))return;
  fetch('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'stop'})})
    .then(r=>r.json()).then(d=>{if(d.ok)toast('Stop signal sent — tests will halt after current test',true);else toast('Error: '+d.error,false);})
    .catch(()=>toast('Request failed',false));
}
function handleLiveClick(){if(_lastState&&_lastState.status==='stopped'){toast('Tests are already stopped',false);return;}stopTests();}
function openModal(name,desc){
  _modalSuite=name;$('modal-name').textContent=name.replace(/_/g,' ');$('modal-desc').textContent=desc||'No description available.';
  const td=(_lastState&&_lastState.tests&&_lastState.tests[name])||{};
  const ta=td.attempts||0,tok=td.ok||0,tf=td.fail||0;
  $('ms-att').textContent=ta?N(ta):'—';$('ms-ok').textContent=tok?N(tok):'—';$('ms-fail').textContent=tf?N(tf):'—';
  if(_lastState){$('modal-size').value=_lastState.size||'XS';$('modal-wait').value=_lastState.max_wait_secs||20;$('modal-wv').textContent=($('modal-wait').value)+'s';$('modal-loop').checked=!!_lastState.loop;}
  $('modal-ov').classList.add('open');
}
function closeModal(){$('modal-ov').classList.remove('open');_modalSuite=null;}
function runFromModal(){
  if(!_modalSuite)return;
  const body={suite:_modalSuite,size:$('modal-size').value,max_wait_secs:parseInt($('modal-wait').value),loop:$('modal-loop').checked,nowait:false};
  fetch('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(r=>r.json()).then(d=>{if(d.ok){toast('Running '+_modalSuite+' — generator restarting…',true);closeModal();}else toast('Error: '+d.error,false);})
    .catch(()=>toast('Request failed',false));
}
// ── Health / perf functions ────────────────────────────────────────────────────
function fmtIO(v){if(v<1)return'<1 KB/s';if(v<1024)return v.toFixed(1)+' KB/s';return(v/1024).toFixed(2)+' MB/s';}
function gaugeColor(p){return p>85?'var(--red)':p>65?'var(--amber)':'var(--green)';}
function drawGauge(cid,pct,label,color){
  const c=$(cid),ctx=c.getContext('2d'),W=c.width,H2=c.height,cx=W/2,cy=H2*0.72;
  const r=Math.min(W,H2)*0.4,sa=0.75*Math.PI,span=1.5*Math.PI;
  ctx.clearRect(0,0,W,H2);
  ctx.beginPath();ctx.arc(cx,cy,r,sa,sa+span);ctx.strokeStyle='#1e2d3d';ctx.lineWidth=10;ctx.lineCap='round';ctx.stroke();
  const va=sa+(Math.max(0,Math.min(100,pct))/100)*span;
  if(pct>0){ctx.beginPath();ctx.arc(cx,cy,r,sa,va);ctx.strokeStyle=color;ctx.lineWidth=10;ctx.lineCap='round';ctx.stroke();}
  ctx.fillStyle='#e2e8f0';ctx.font='bold 20px SF Mono,Consolas,monospace';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(pct.toFixed(1)+'%',cx,cy-6);
  ctx.fillStyle='#64748b';ctx.font='10px system-ui';ctx.fillText(label,cx,cy+10);
}
function drawDiskBars(r,w){
  const c=$('disk-bars'),rect=c.getBoundingClientRect();
  c.width=Math.floor(rect.width)||300;c.height=58;
  const ctx=c.getContext('2d'),W=c.width,bh=16,lw=48,gy=6;
  ctx.clearRect(0,0,W,58);
  const mx=Math.max(r,w,1);
  const drawBar=(y,v,col,lbl)=>{
    ctx.fillStyle='#64748b';ctx.font='9px SF Mono,Consolas,monospace';ctx.textAlign='right';ctx.textBaseline='middle';ctx.fillText(lbl,lw-4,y+bh/2);
    ctx.fillStyle='#1e2d3d';ctx.fillRect(lw,y,W-lw-gy,bh);
    const bw=Math.max(2,(v/mx)*(W-lw-gy));
    ctx.fillStyle=col;ctx.fillRect(lw,y,bw,bh);
    ctx.fillStyle='#e2e8f0';ctx.textAlign='left';ctx.font='9px SF Mono,Consolas,monospace';ctx.fillText(fmtIO(v),lw+bw+4,y+bh/2);
  };
  drawBar(4,r,'#22c55e','Read');drawBar(34,w,'#58a6ff','Write');
}
function drawNetSpark(cid,hist,rxColor,txColor){
  const c=$(cid),rect=c.getBoundingClientRect();
  c.width=Math.floor(rect.width)||400;c.height=Math.floor(rect.height)||60;
  const ctx=c.getContext('2d'),W=c.width,H2=c.height,P={t:4,r:6,b:16,l:10};
  const IW=W-P.l-P.r,IH=H2-P.t-P.b;
  ctx.clearRect(0,0,W,H2);
  if(!hist||hist.length<2){ctx.fillStyle='#374151';ctx.font='10px system-ui';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText('Accumulating…',W/2,H2/2);return;}
  const mx=Math.max(...hist.map(p=>Math.max(p.rx||0,p.tx||0)),1);
  const xOf=i=>P.l+(i/(hist.length-1))*IW,yOf=v=>P.t+IH-(v/mx)*IH;
  const drawLine=(key,col)=>{
    ctx.beginPath();hist.forEach((p,i)=>{const x=xOf(i),y=yOf(p[key]||0);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});
    ctx.strokeStyle=col;ctx.lineWidth=1.5;ctx.lineJoin='round';ctx.stroke();
  };
  drawLine('rx','#22c55e');drawLine('tx','#58a6ff');
  ctx.fillStyle='#374151';ctx.font='9px SF Mono,Consolas,monospace';ctx.textAlign='left';ctx.fillText(fmtIO(hist[hist.length-1].rx||0)+' rx',P.l,H2-3);
  ctx.textAlign='right';ctx.fillText(fmtIO(hist[hist.length-1].tx||0)+' tx',P.l+IW,H2-3);
}
function applyHealth(d){
  if(!d)return;
  _lastHealth=d;
  // Overview network widget
  const rx=d.net_rx_kbps||0,tx=d.net_tx_kbps||0;
  if($('ov-rx'))$('ov-rx').textContent=fmtIO(rx);
  if($('ov-tx'))$('ov-tx').textContent=fmtIO(tx);
  _netHist.push({rx,tx,t:Date.now()/1000});if(_netHist.length>60)_netHist.shift();
  drawNetSpark('net-spark',_netHist,'#22c55e','#58a6ff');
  // Health tab
  drawGauge('cpu-gauge',d.cpu_pct||0,'CPU',gaugeColor(d.cpu_pct||0));
  drawGauge('mem-gauge',d.mem_pct||0,'Memory',gaugeColor(d.mem_pct||0));
  if($('mem-detail'))$('mem-detail').textContent=(d.mem_used_mb||0).toFixed(0)+' MB / '+(d.mem_total_mb||0).toFixed(0)+' MB used';
  const la=d.load_avg||[0,0,0];
  if($('h-load'))$('h-load').textContent=la.map(v=>v.toFixed(2)).join('  \xb7  ');
  if($('disk-read'))$('disk-read').textContent=fmtIO(d.disk_read_kbps||0);
  if($('disk-write'))$('disk-write').textContent=fmtIO(d.disk_write_kbps||0);
  drawDiskBars(d.disk_read_kbps||0,d.disk_write_kbps||0);
  if($('h-rx'))$('h-rx').textContent=fmtIO(rx);
  if($('h-tx'))$('h-tx').textContent=fmtIO(tx);
  _hNetHist.push({rx,tx,t:Date.now()/1000});if(_hNetHist.length>60)_hNetHist.shift();
  drawNetSpark('h-net-spark',_hNetHist,'#22c55e','#58a6ff');
  const procs=d.processes||[];
  const tb=$('proc-body');
  if(tb)tb.innerHTML=!procs.length?'<tr><td colspan="5" class="empty">No data</td></tr>':
    procs.map(p=>{
      const cpuC=p.cpu_pct>50?'var(--red)':p.cpu_pct>20?'var(--amber)':'var(--green)';
      const memC=p.mem_pct>30?'var(--amber)':'var(--muted)';
      return`<tr class="mrow"><td class="r" style="color:var(--muted)">${p.pid}</td><td class="nm">${H(p.name)}</td><td class="r"><span style="color:${cpuC}">${p.cpu_pct.toFixed(1)}%</span></td><td class="r"><span style="color:${memC}">${p.mem_pct.toFixed(1)}%</span></td><td class="r" style="color:var(--muted)">${p.mem_mb.toFixed(0)} MB</td></tr>`;
    }).join('');
}
function pollHealth(){
  fetch('/api/health').then(r=>r.json()).then(d=>applyHealth(d)).catch(()=>{});
}
// Kick off overview network widget immediately and keep it live
setInterval(pollHealth,2500);
window.addEventListener('resize',()=>{
  if(_lastState)drawSpark(_lastState.history||[]);
  if(_lastHealth){drawDiskBars(_lastHealth.disk_read_kbps||0,_lastHealth.disk_write_kbps||0);drawNetSpark('net-spark',_netHist);drawNetSpark('h-net-spark',_hNetHist);}
});
connect();
</script>
</body></html>"""
_LOG_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>traffgen &middot; Live Output</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#080c10;--surf:#161b22;--border:#1e2d3d;--green:#22c55e;--red:#f85149;--amber:#f59e0b;--blue:#60a5fa;--text:#c9d1d9;--muted:#64748b;--dim:#374151}
html,body{height:100%;overflow:hidden}
body{background:var(--bg);color:var(--text);font-family:'SF Mono',Consolas,monospace;font-size:12px;display:flex;flex-direction:column}
.hdr{display:flex;align-items:center;gap:8px;padding:7px 12px;background:var(--surf);border-bottom:1px solid var(--border);flex-shrink:0}
.title{font-weight:700;font-size:13px;margin-right:auto;color:var(--text)}
.btn{padding:3px 10px;border-radius:5px;border:1px solid var(--border);background:var(--bg);color:var(--muted);font-size:11px;cursor:pointer}
.btn:hover{border-color:var(--green);color:var(--green)}
.btn.af{border-color:var(--green);color:var(--green)}
.fgrp{display:flex;gap:3px}
.body{flex:1;overflow-y:auto;padding:2px 0;min-height:0}
.ll{padding:1px 12px;display:flex;align-items:baseline;white-space:pre-wrap;word-break:break-all}
.ll:hover{background:rgba(255,255,255,.02)}
.ll-sep{padding:4px 0;display:flex;align-items:center}
.sep-line{flex:1;height:1px;background:var(--dim);opacity:.3}
.sep-txt{padding:0 10px;font-size:10px;letter-spacing:.5px;color:var(--dim);white-space:nowrap}
.llt{color:#374151;margin-right:8px;flex-shrink:0;font-size:11px}
.llv{font-weight:700;margin-right:8px;flex-shrink:0;width:40px;font-size:11px}
.llm{color:#c9d1d9;flex:1}
.ll.info .llv{color:#60a5fa}.ll.ok .llv{color:#22c55e}.ll.warn .llv{color:#f59e0b}.ll.error .llv{color:#f85149}.ll.debug .llv{color:#374151}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--dim);border-radius:2px}
</style>
</head>
<body>
<div class="hdr">
  <span class="title">&#9889; traffgen &middot; Live Output</span>
  <div class="fgrp">
    <button class="btn af" data-lvl="all" onclick="setF(this,'all')">All</button>
    <button class="btn" data-lvl="ok" onclick="setF(this,'ok')">OK</button>
    <button class="btn" data-lvl="warn" onclick="setF(this,'warn')">Warn</button>
    <button class="btn" data-lvl="error" onclick="setF(this,'error')">Error</button>
  </div>
  <button class="btn" onclick="b.innerHTML='';lt=null">Clear</button>
  <button class="btn" id="bas" onclick="as=!as;this.textContent='Auto-scroll '+(as?'\\u2713':'\\u2717')">Auto-scroll &#10003;</button>
</div>
<div class="body" id="body"></div>
<script>
let as=true,lf='all',lt=null;
const b=document.getElementById('body');
const H=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const Tc=ts=>new Date(ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});
function setF(btn,lvl){lf=lvl;document.querySelectorAll('.fgrp .btn').forEach(x=>x.classList.remove('af'));btn.classList.add('af');document.querySelectorAll('.ll').forEach(el=>{if(el.classList.contains('ll-sep'))return;el.style.display=(lvl==='all'||el.classList.contains(lvl))?'':'none';});}
const es=new EventSource('/log');
es.onmessage=ev=>{
  try{
    const d=JSON.parse(ev.data),lvl=d.level||'info';
    const test=d.test||'';
    if(test&&test!==lt){lt=test;const sep=document.createElement('div');sep.className='ll ll-sep';sep.innerHTML='<div class="sep-line"></div><div class="sep-txt">'+H(test.replace(/_/g,' '))+'</div><div class="sep-line"></div>';b.appendChild(sep);}
    const div=document.createElement('div');div.className='ll '+lvl;
    div.innerHTML='<span class="llt">'+Tc(d.t||Date.now()/1000)+'</span><span class="llv">'+H(lvl.toUpperCase().slice(0,5).padEnd(5))+'</span><span class="llm">'+H(d.msg||'')+'</span>';
    if(lf!=='all'&&!div.classList.contains(lf))div.style.display='none';
    b.appendChild(div);if(as)b.scrollTop=b.scrollHeight;
    while(b.children.length>1000)b.removeChild(b.firstChild);
  }catch(e){}
};
</script>
</body></html>"""

# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    threading.Thread(target=_sample_health, daemon=True, name="health-sampler").start()
    ctx = _ensure_cert()
    print(f"[webui] Dashboard: https://0.0.0.0:{PORT}", flush=True)
    app.run(
        host="0.0.0.0",
        port=PORT,
        ssl_context=ctx,
        threaded=True,
        use_reloader=False,
        debug=False,
    )
