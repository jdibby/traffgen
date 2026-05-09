#!/usr/bin/env python3
"""
webui.py — HTTPS monitoring dashboard for traffgen on port 7777.

No configuration needed. Reads /tmp/traffgen_state.json for live data.
Accepts validated control commands via POST /api/control.
Generates a self-signed TLS certificate on first start (stored in /tmp/).
"""

import fcntl
import json
import logging
import os
import socket as _socket
import ssl
import struct
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
ADMIN_TOKEN  = os.environ.get("TRAFFGEN_ADMIN_TOKEN", "")

# ── Flask ──────────────────────────────────────────────────────────────────────
app = Flask(__name__)

_sse_count = 0
_sse_lock  = threading.Lock()

# ── Exclusive-control session tracking ────────────────────────────────────────
# When ADMIN_TOKEN is not set, the first browser tab to open an SSE connection
# becomes the controller; all other tabs are read-only.  If the controller tab
# closes, its SSE stream ends and a 4-second timer starts.  If the same tab
# reconnects within the grace period it reclaims control; otherwise the slot
# opens for the next visitor.
_controller_id:    str                          = ""
_controller_lock:  threading.Lock               = threading.Lock()
_controller_timer: "threading.Timer | None"     = None
_controller_gen:   int                          = 0   # increments on every new claim


def _schedule_controller_release(sid: str, gen: int, delay: float = 4.0) -> None:
    global _controller_id, _controller_timer
    with _controller_lock:
        if _controller_timer is not None:
            _controller_timer.cancel()

        def _release():
            global _controller_id, _controller_timer, _controller_gen
            with _controller_lock:
                # Only release if no newer connection has since claimed control.
                if _controller_id == sid and _controller_gen == gen:
                    _controller_id = ""
                _controller_timer = None

        t = threading.Timer(delay, _release)
        t.daemon = True
        t.start()
        _controller_timer = t


def _cancel_controller_release() -> None:
    global _controller_timer
    with _controller_lock:
        if _controller_timer is not None:
            _controller_timer.cancel()
            _controller_timer = None

# ── Health monitoring ──────────────────────────────────────────────────────────
_health_cache: dict = {}
_health_lock2 = threading.Lock()
_net_info_cache: dict = {}
_net_info_lock = threading.Lock()


def _sample_health() -> None:
    """Background daemon: sample /proc metrics every 2 s and cache results."""
    prev_cpu   = None
    prev_disk  = None
    prev_procs: dict = {}
    prev_ts    = 0.0
    net_start:  tuple | None = None   # (rx_bytes, tx_bytes) at first sample
    disk_start: tuple | None = None   # (rd_sectors, wr_sectors) at first sample

    while True:
        time.sleep(2)
        try:
            now  = time.time()
            data: dict = {}

            # CPU (aggregate + per-core)
            try:
                with open("/proc/stat") as f:
                    stat_lines = [l for l in f if l.startswith("cpu")]
                def _parse_cpu(raw):
                    p = raw.split()
                    tot = sum(int(x) for x in p[1:8])
                    idle = int(p[4]) + int(p[5])
                    user = int(p[1]) + int(p[2])
                    sys_ = int(p[3]) + int(p[6])
                    return tot, idle, user, sys_
                agg = _parse_cpu(stat_lines[0])
                cores = [_parse_cpu(l) for l in stat_lines[1:] if l.split()[0] != "cpu"]
                cur_c = [agg] + cores
                if prev_cpu and len(prev_cpu) == len(cur_c):
                    def _pct(cur, prev):
                        dt = cur[0] - prev[0]
                        if dt <= 0:
                            return 0.0, 0.0, 0.0
                        di = cur[1] - prev[1]
                        du = cur[2] - prev[2]
                        ds = cur[3] - prev[3]
                        return round((1-di/dt)*100,1), round(du/dt*100,1), round(ds/dt*100,1)
                    tot_pct, usr_pct, sys_pct = _pct(cur_c[0], prev_cpu[0])
                    data["cpu_pct"] = tot_pct
                    data["cpu_user_pct"] = usr_pct
                    data["cpu_sys_pct"] = sys_pct
                    data["cpu_cores"] = [
                        {"idx": i, "total": _pct(cur_c[i+1], prev_cpu[i+1])[0],
                         "user": _pct(cur_c[i+1], prev_cpu[i+1])[1],
                         "sys": _pct(cur_c[i+1], prev_cpu[i+1])[2]}
                        for i in range(len(cores))
                    ]
                else:
                    data["cpu_pct"] = 0.0
                    data["cpu_user_pct"] = 0.0
                    data["cpu_sys_pct"] = 0.0
                    data["cpu_cores"] = []
                prev_cpu = cur_c
            except Exception:
                data["cpu_pct"] = 0.0
                data["cpu_user_pct"] = 0.0
                data["cpu_sys_pct"] = 0.0
                data["cpu_cores"] = []

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
                data["mem_total_mb"]   = round(total_kb / 1024, 1)
                data["mem_used_mb"]    = round(used_kb  / 1024, 1)
                data["mem_pct"]        = round(used_kb / total_kb * 100, 1) if total_kb > 0 else 0.0
                buf_kb    = mem_kb.get("Buffers", 0)
                cached_kb = mem_kb.get("Cached", 0) + mem_kb.get("SReclaimable", 0) - mem_kb.get("Shmem", 0)
                data["mem_buffers_mb"] = round(max(0, buf_kb) / 1024, 1)
                data["mem_cached_mb"]  = round(max(0, cached_kb) / 1024, 1)
                data["mem_free_mb"]    = round(avail_kb / 1024, 1)
                swap_total = mem_kb.get("SwapTotal", 0)
                swap_free  = mem_kb.get("SwapFree",  0)
                swap_used  = swap_total - swap_free
                data["swap_total_mb"] = round(swap_total / 1024, 1)
                data["swap_used_mb"]  = round(swap_used  / 1024, 1)
                data["swap_pct"]      = round(swap_used / swap_total * 100, 1) if swap_total > 0 else 0.0
            except Exception:
                data.update({"mem_total_mb": 0, "mem_used_mb": 0, "mem_pct": 0.0,
                             "swap_total_mb": 0, "swap_used_mb": 0, "swap_pct": 0.0})

            # Thread count + open FDs (self)
            try:
                with open("/proc/self/status") as f:
                    for ln in f:
                        if ln.startswith("Threads:"):
                            data["thread_count"] = int(ln.split()[1])
                            break
            except Exception:
                data["thread_count"] = 0
            try:
                data["fd_count"] = len(os.listdir("/proc/self/fd"))
            except Exception:
                data["fd_count"] = 0
            try:
                with open("/proc/self/limits") as f:
                    for ln in f:
                        if "Max open files" in ln:
                            parts = ln.split()
                            data["fd_limit"] = int(parts[3]) if parts[3].isdigit() else 0
                            break
                    else:
                        data["fd_limit"] = 0
            except Exception:
                data["fd_limit"] = 0

            # System uptime
            try:
                with open("/proc/uptime") as f:
                    data["uptime_secs"] = float(f.read().split()[0])
            except Exception:
                data["uptime_secs"] = 0.0

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
                if disk_start is None:
                    disk_start = (rd, wr)
                data["disk_rd_total_mb"] = round(max(0, (rd - disk_start[0]) * 512) / 1024 / 1024, 1)
                data["disk_wr_total_mb"] = round(max(0, (wr - disk_start[1]) * 512) / 1024 / 1024, 1)
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
                if net_start is None:
                    net_start = (net_rx, net_tx)
                data["net_rx_total_mb"] = round(max(0, net_rx - net_start[0]) / 1024 / 1024, 1)
                data["net_tx_total_mb"] = round(max(0, net_tx - net_start[1]) / 1024 / 1024, 1)
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


def _iface_ip4(iface: str) -> str:
    """Return the IPv4 address of an interface via SIOCGIFADDR, or ''."""
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        raw = fcntl.ioctl(s.fileno(), 0x8915,
                          struct.pack("256s", iface[:15].encode()))
        s.close()
        return _socket.inet_ntoa(raw[20:24])
    except Exception:
        return ""


def _fetch_public_ip() -> str:
    """Resolve the public/WAN IP using external lookup services."""
    for url in ("https://api.ipify.org",
                "https://checkip.amazonaws.com",
                "https://icanhazip.com"):
        try:
            r = subprocess.run(
                ["curl", "-s", "-4", "--max-time", "6", url],
                capture_output=True, text=True, timeout=8,
            )
            ip = r.stdout.strip()
            if ip and len(ip) <= 45:
                return ip
        except Exception:
            continue
    return "unavailable"


def _host_lan_ip() -> str:
    """Return the Docker host's LAN IP from the HOST_LAN_CIDR env var injected
    by stager.sh (e.g. '192.168.1.100/24' → '192.168.1.100'), or '' if unset."""
    cidr = os.environ.get("HOST_LAN_CIDR", "").strip()
    if cidr and "/" in cidr:
        ip = cidr.split("/")[0]
        import re as _re
        if _re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
            return ip
    return ""


def _sample_net_info() -> None:
    """Background daemon: gather interface metadata and public IP every 60 s."""
    public_ip = ""
    public_ip_ts = 0.0
    PUBLIC_IP_TTL = 300.0   # re-query WAN IP every 5 minutes

    while True:
        try:
            now = time.time()
            ifaces = _collect_ifaces()
            lan_ip = _host_lan_ip()

            # Push interfaces immediately so the widget has data before the
            # public IP curl completes (which can take several seconds).
            with _net_info_lock:
                _net_info_cache.update({
                    "interfaces": ifaces,
                    "public_ip":  public_ip or "resolving…",
                    "host_lan_ip": lan_ip,
                })

            # Refresh public IP on first run and every TTL seconds — done
            # after the cache update so it doesn't block interface display.
            if not public_ip or now - public_ip_ts >= PUBLIC_IP_TTL:
                public_ip    = _fetch_public_ip()
                public_ip_ts = now
                with _net_info_lock:
                    _net_info_cache["public_ip"] = public_ip
        except Exception:
            pass

        time.sleep(60)


_VIRTUAL_IFACE_PREFIXES = (
    "lo", "veth", "br-", "docker", "virbr", "vnet", "tap", "tun", "dummy",
    "flannel", "cni", "weave", "calico",
)


def _is_virtual_iface(name: str) -> bool:
    """Return True for loopback and known virtual/container bridge interfaces."""
    return any(name == p or name.startswith(p) for p in _VIRTUAL_IFACE_PREFIXES)


def _collect_ifaces() -> list:
    """Return a list of interface dicts, using 'ip -j addr' with /sys fallback.

    Virtual/overlay interfaces (veth*, br-*, docker*, etc.) are excluded so
    that --network=host deployments don't flood the table with internal bridges.
    """
    # Primary: ip -j addr produces reliable JSON without ioctl or file-permission issues
    try:
        r = subprocess.run(
            ["ip", "-j", "addr"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            result = []
            for iface in json.loads(r.stdout):
                name = iface.get("ifname", "")
                if not name or _is_virtual_iface(name):
                    continue
                ip4 = next(
                    (a.get("local", "") for a in iface.get("addr_info", [])
                     if a.get("family") == "inet"),
                    "",
                )
                flags = iface.get("flags", [])
                link  = "up" if "LOWER_UP" in flags else "down"
                try:
                    spd_raw = int(open(f"/sys/class/net/{name}/speed").read().strip() or "-1")
                    speed = f"{spd_raw} Mbps" if spd_raw > 0 else "unknown"
                except Exception:
                    speed = "unknown"
                result.append({
                    "name":  name,
                    "ip":    ip4,
                    "mac":   iface.get("address", ""),
                    "speed": speed,
                    "mtu":   iface.get("mtu", 0),
                    "link":  link,
                })
            return result
    except Exception:
        pass

    # Fallback: /sys/class/net + SIOCGIFADDR ioctl
    result = []
    for name in sorted(os.listdir("/sys/class/net")):
        if _is_virtual_iface(name):
            continue
        try:
            base = f"/sys/class/net/{name}"

            def _rd(path: str, _b=base) -> str:
                try:
                    return open(path).read().strip()
                except Exception:
                    return ""

            mac = _rd(f"{base}/address")
            mtu = _rd(f"{base}/mtu")
            try:
                spd_raw = int(_rd(f"{base}/speed") or "-1")
                speed = f"{spd_raw} Mbps" if spd_raw > 0 else "unknown"
            except Exception:
                speed = "unknown"
            try:
                link = "up" if int(_rd(f"{base}/carrier") or "0") else "down"
            except Exception:
                link = "unknown"
            result.append({
                "name":  name,
                "ip":    _iface_ip4(name),
                "mac":   mac,
                "speed": speed,
                "mtu":   int(mtu) if mtu.isdigit() else 0,
                "link":  link,
            })
        except Exception:
            continue
    return result



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
            "size": "S", "loop": True, "max_wait_secs": 20,
            "current_test": "", "iteration": 0,
            "status": "starting", "test_started_at": 0.0,
            "tests": {}, "suites": [],
            "totals": {"attempts": 0, "ok": 0, "fail": 0},
            "history": [], "events": [],
        }


def _sse_wrap(gen_fn, session_id: str = ""):
    """Apply SSE connection limit and correct headers around a generator.

    If session_id is provided and ADMIN_TOKEN is not set, the session-based
    exclusive-control logic runs: the first SSE connection claims the
    controller slot; when it drops a 10-second grace timer starts so a
    reconnect from the same tab reclaims control without a gap.
    """
    global _sse_count, _controller_id
    with _sse_lock:
        if _sse_count >= MAX_SSE:
            return Response("Too many connections", status=429)
        _sse_count += 1

    # Claim or renew the controller slot when no ADMIN_TOKEN is configured.
    my_gen = -1
    if not ADMIN_TOKEN and session_id:
        with _controller_lock:
            if not _controller_id:
                _controller_id = session_id
            is_ctrl = (_controller_id == session_id)
            if is_ctrl:
                global _controller_gen
                _controller_gen += 1
                my_gen = _controller_gen
        if is_ctrl:
            _cancel_controller_release()

    def _guarded():
        global _sse_count
        try:
            yield from gen_fn()
        finally:
            with _sse_lock:
                _sse_count -= 1
            # Only schedule release if this connection is still the active one.
            # my_gen ensures a delayed finally from an old connection doesn't
            # restart the timer after a newer connection already claimed control.
            if not ADMIN_TOKEN and session_id and my_gen >= 0:
                with _controller_lock:
                    was_ctrl = (_controller_id == session_id
                                and _controller_gen == my_gen)
                if was_ctrl:
                    _schedule_controller_release(session_id, my_gen)

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


@app.route("/api/netinfo")
def api_netinfo():
    with _net_info_lock:
        return jsonify(dict(_net_info_cache))


def _is_admin() -> bool:
    if ADMIN_TOKEN:
        return request.headers.get("X-Admin-Token", "") == ADMIN_TOKEN
    # Accept session ID from header OR query param — proxies may strip custom headers.
    sid = (request.headers.get("X-Session-ID", "")
           or request.args.get("sid", ""))
    if not sid:
        return False
    with _controller_lock:
        return _controller_id == sid


@app.route("/api/role")
def api_role():
    is_ctrl = _is_admin()
    has_ctrl = bool(_controller_id)
    return jsonify({
        "auth_required": bool(ADMIN_TOKEN),
        "session_mode":  not bool(ADMIN_TOKEN),
        "admin":         is_ctrl,
        "has_controller": has_ctrl,
    })


@app.route("/api/control", methods=["POST"])
def api_control():
    if not _is_admin():
        return jsonify({"error": "Admin access required"}), 401
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

    size = str(d.get("size", "S"))
    if size not in _VALID_SIZES:
        return jsonify({"error": f"Invalid size: {size}"}), 400

    try:
        wait = max(5, min(300, int(d.get("max_wait_secs", 20))))
    except (TypeError, ValueError):
        return jsonify({"error": "max_wait_secs must be an integer 5-300"}), 400

    # lateral_networks: list of CIDRs to filter lateral-movement targets
    lat_raw = d.get("lateral_networks", [])
    if isinstance(lat_raw, list):
        lat_nets = [str(n) for n in lat_raw if isinstance(n, str) and "/" in n]
    else:
        lat_nets = []

    cmd = {
        "suite":            suite,
        "size":             size,
        "max_wait_secs":    wait,
        "loop":             bool(d.get("loop", True)),
        "nowait":           bool(d.get("nowait", False)),
        "lateral_networks": lat_nets,
    }
    try:
        tmp = _CMD_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cmd, f)
        os.replace(tmp, _CMD_FILE)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"ok": True, "applied": cmd})


@app.route("/api/networks")
def api_networks():
    """Return available lateral-movement networks detected by the generator."""
    st = _read_state()
    return jsonify({
        "available": st.get("lateral_networks_available", []),
        "selected":  st.get("lateral_networks", []),
    })



_TARGET_RE = __import__('re').compile(r'^[a-zA-Z0-9._\-:]{1,253}$')

def _parse_hop(line):
    """Parse one traceroute output line into a hop dict, or return None."""
    import re
    m = re.match(r'^\s*(\d+)\s+(.*)', line)
    if not m:
        return None
    hop_num = int(m.group(1))
    rest = m.group(2).strip()
    rtts = [float(x) for x in re.findall(r'(\d+\.\d+)\s+ms', rest)]
    ip_m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]{0,4})', rest)
    ip = ip_m.group(1) if ip_m else None
    avg_rtt = round(sum(rtts) / len(rtts), 2) if rtts else None
    return {"hop": hop_num, "ip": ip, "rtts": rtts, "avg_rtt": avg_rtt,
            "timeout": not rtts, "raw": rest}


# Explicit allowlist maps for traceroute proto flags — keeps user input
# fully out of the command list; only these literal strings ever reach Popen.
_TR_PROTO_FLAGS: "dict[str, list[str]]" = {
    "tcp":  ["-T"],
    "udp":  [],
    "icmp": ["-I"],
}


@app.route("/api/traceroute")
def api_traceroute():
    def _sse_err(msg: str) -> "Response":
        return Response(
            f'data: {json.dumps({"error": msg})}\n\ndone: true\n\n',
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache"},
        )

    # ── Validate all inputs eagerly before touching the generator ──────────
    raw_target = request.args.get("target", "").strip()
    if not _TARGET_RE.match(raw_target):
        return _sse_err("Invalid target — use a hostname or IP address")

    raw_proto = request.args.get("proto", "tcp").lower()
    if raw_proto not in _TR_PROTO_FLAGS:
        return _sse_err("Invalid proto — use tcp, udp, or icmp")

    raw_port = request.args.get("port", "443")
    if not raw_port.isdigit() or not (1 <= int(raw_port) <= 65535):
        return _sse_err("Invalid port")

    # ── Only validated literals reach this point ───────────────────────────
    # Build the command from allowlisted values; raw user input is never
    # concatenated into the argument list.
    safe_target: str = raw_target                        # regex-validated
    safe_proto_flags: list = _TR_PROTO_FLAGS[raw_proto]  # allowlist lookup
    safe_port: str = str(int(raw_port))                  # re-serialised int

    def _gen():
        cmd = ["traceroute", "-n", "-q", "3", "-w", "1", "-m", "30"]
        cmd += safe_proto_flags
        if raw_proto == "tcp":
            cmd += ["-p", safe_port]
        cmd.append(safe_target)
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors="replace",
            )
            for line in proc.stdout:
                line = line.rstrip()
                if line.startswith("traceroute to"):
                    yield f'data: {json.dumps({"header": line})}\n\n'
                    continue
                hop = _parse_hop(line)
                if hop:
                    yield f'data: {json.dumps({"hop": hop})}\n\n'
            proc.wait()
            yield f'data: {json.dumps({"done": True, "code": proc.returncode})}\n\n'
        except FileNotFoundError:
            yield f'data: {json.dumps({"error": "traceroute not found on this system"})}\n\n'
        except Exception as exc:
            yield f'data: {json.dumps({"error": str(exc)})}\n\n'

    return Response(
        _gen(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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
    return _sse_wrap(_gen, request.args.get("sid", ""))


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
                    f.seek(0, 2)
                    size = f.tell()
                    if pos > size:
                        pos = size
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
body{display:flex;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:15px;line-height:1.5}
*{scrollbar-width:thin;scrollbar-color:var(--border2) transparent}
*::-webkit-scrollbar{width:6px;height:6px}
*::-webkit-scrollbar-track{background:transparent}
*::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
*::-webkit-scrollbar-thumb:hover{background:var(--muted)}
.sidebar{width:var(--sw);background:var(--sidebar);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;height:100vh;overflow-y:auto}
.sb-logo{display:flex;align-items:center;gap:10px;padding:13px 16px;border-bottom:1px solid var(--border)}
.logo-name{font-weight:700;font-size:19px;letter-spacing:-.3px;color:var(--text)}
.nav-lbl{padding:14px 16px 4px;font-size:15px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:var(--muted)}
.nav-item{display:flex;align-items:center;gap:9px;padding:8px 16px 8px 13px;color:var(--muted);cursor:pointer;border:none;background:none;width:100%;text-align:left;font-size:19px;border-left:3px solid transparent;transition:all .12s}
.nav-item:hover{color:var(--text);background:rgba(255,255,255,.04)}
.nav-item.active{color:var(--green);background:var(--gdim);border-left-color:var(--green);font-weight:500}
.nav-arr{font-size:12px;transition:transform .2s;display:inline-block;line-height:1;padding:4px 6px;margin:-4px -6px;border-radius:4px}.nav-arr:hover{background:rgba(255,255,255,.1)}
.nav-arr.open{transform:rotate(90deg)}
.nav-sub{max-height:0;overflow:hidden;transition:max-height .28s ease}
.nav-sub.open{max-height:500px}
.nav-sub-item{display:flex;align-items:center;gap:8px;padding:5px 16px 5px 36px;color:var(--dim);cursor:pointer;border:none;background:none;width:100%;text-align:left;font-size:14px;border-left:3px solid transparent;transition:all .12s}
.nav-sub-item:hover{color:var(--text);background:rgba(255,255,255,.04)}
.nav-sub-item.active{color:var(--green);border-left-color:var(--green);background:var(--gdim)}
.diag-tool{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px 20px;margin-bottom:14px}
.diag-tool-hdr{font-size:13px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--muted);margin-bottom:14px}
.diag-input-row{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.diag-input{flex:1;min-width:180px;background:var(--input-bg,rgba(255,255,255,.06));border:1px solid var(--border);border-radius:8px;padding:8px 12px;color:var(--text);font-size:14px;font-family:'SF Mono',Consolas,monospace;outline:none}
.diag-input:focus{border-color:var(--green);box-shadow:0 0 0 2px rgba(34,197,94,.15)}
.diag-btn{padding:8px 18px;background:var(--green);color:#0a0f1a;font-weight:700;font-size:14px;border:none;border-radius:8px;cursor:pointer;white-space:nowrap;transition:opacity .12s}
.diag-btn:hover{opacity:.85}
.diag-btn:disabled{opacity:.4;cursor:default}
.diag-btn.cancel{background:var(--amber)}
.tr-results{font-family:'SF Mono',Consolas,monospace;font-size:13px}
.tr-header{color:var(--muted);font-size:12px;margin-bottom:8px;padding:4px 0}
.tr-hop{display:grid;grid-template-columns:28px 160px 80px 1fr;align-items:center;gap:10px;padding:5px 6px;border-radius:6px}
.tr-hop:nth-child(even){background:rgba(255,255,255,.025)}
.tr-hop-num{color:var(--dim);text-align:right;font-size:11px}
.tr-hop-ip{color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tr-hop-ip.timeout{color:var(--muted);font-style:italic}
.tr-hop-rtt{text-align:right;font-size:12px;font-weight:600}
.tr-bar-wrap{height:6px;background:rgba(255,255,255,.07);border-radius:3px;overflow:hidden}
.tr-bar-fill{height:100%;border-radius:3px;transition:width .4s ease}
.tr-status{padding:10px 6px;color:var(--muted);font-style:italic;font-size:13px}
.tr-error{padding:10px 6px;color:var(--red,#ef4444);font-size:13px}

.nav-ico{width:18px;text-align:center;font-size:19px;opacity:.75}
.sb-foot{margin-top:auto;padding:12px 16px;border-top:1px solid var(--border)}
.sb-foot div{font-size:16px;color:var(--dim);margin-top:2px}
.main{flex:1;display:flex;flex-direction:column;min-width:0;height:100vh;overflow:hidden}
.topbar{height:52px;display:flex;align-items:center;padding:0 18px;border-bottom:1px solid var(--border);background:var(--sidebar);flex-shrink:0;box-shadow:0 2px 8px rgba(0,0,0,.35);position:sticky;top:0;z-index:10}
.tb-left{display:flex;align-items:center;gap:8px;flex:1;min-width:0}
.tb-center{display:flex;align-items:center;justify-content:center;flex:0 1 auto;padding:0 12px}
.tb-right{display:flex;align-items:center;gap:8px;flex:1;justify-content:flex-end;min-width:0}
.pg-title{font-size:20px;font-weight:700;color:var(--text);letter-spacing:-.2px}
.tb-test{display:none;align-items:center;gap:6px;background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.35);border-radius:20px;padding:3px 12px 3px 8px;min-width:0;overflow:hidden}
.tb-test.visible{display:inline-flex}
.tb-test-name{font-size:14px;font-weight:600;color:var(--green);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:260px;font-family:'SF Mono',Consolas,monospace;letter-spacing:.2px}
.tp-pill{display:inline-flex;align-items:center;gap:5px;padding:4px 11px;border-radius:20px;font-size:17px;font-weight:500;border:1px solid;white-space:nowrap}
.tp-running{border-color:var(--green);color:var(--green)}
.tp-paused{border-color:var(--amber);color:var(--amber)}
.tp-stopped{border-color:var(--red);color:var(--red)}
.tp-dim{border-color:var(--muted);color:var(--muted)}
.pulse{width:6px;height:6px;border-radius:50%;background:currentColor;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.ico-btn{width:33px;height:33px;border-radius:var(--r);border:1px solid var(--border2);background:var(--surf);color:var(--muted);cursor:pointer;display:grid;place-items:center;font-size:20px;transition:all .12s;flex-shrink:0}
.ico-btn:hover{border-color:var(--green);color:var(--green)}
.ico-btn.danger:hover{border-color:var(--red);color:var(--red)}
.ico-btn.ok{width:auto;padding:0 12px;font-size:14px;font-weight:600;color:var(--green);border-color:var(--green)}
.ico-btn.ok:hover{background:var(--green);color:#000}
.content{flex:1;display:flex;flex-direction:column;min-height:0;overflow:hidden}
.panel{display:none;flex-direction:column;gap:14px;padding:18px;flex:1;min-height:0;overflow-y:auto}
.panel.active{display:flex}
#tab-output.panel{padding:0;gap:0;overflow:hidden}
/* Widget grids: capped at 1400px, centered, full-height overflow-y */
#ov-grid,#sec-grid,#health-grid{display:flex;flex-direction:column;gap:14px;max-width:1400px;width:100%;margin:0 auto}
/* Max-width cap on other panel content (About, Tests, etc.) */
.panel>*:not(#ov-grid):not(#sec-grid):not(#health-grid){max-width:1400px;width:100%;box-sizing:border-box;align-self:center}
/* Stat cards: fully fluid, min 130px per card */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
.card{background:var(--surf);border:1px solid var(--border);border-radius:10px;padding:14px 16px;display:flex;flex-direction:column;gap:2px;transition:border-color .15s,box-shadow .15s;box-shadow:0 1px 4px rgba(0,0,0,.25)}
.card:hover{border-color:var(--border2);box-shadow:0 2px 8px rgba(0,0,0,.35)}
.card.hi{border-color:rgba(34,197,94,.3);background:var(--gdim)}
.clbl{font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--muted)}
.cval{font-size:26px;font-weight:700;font-family:'SF Mono',Consolas,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:4px;line-height:1.1}
.csub{font-size:12px;color:var(--muted);margin-top:3px;line-height:1.4;word-break:break-word}
.c-green{color:var(--green)}.c-red{color:var(--red)}.c-amber{color:var(--amber)}.c-blue{color:var(--blue)}.c-mut{color:var(--muted)}
.charts{display:grid;grid-template-columns:minmax(200px,240px) 1fr;gap:12px}
@media(max-width:760px){.charts{grid-template-columns:1fr}}
.cc{background:var(--surf);border:1px solid var(--border);border-radius:10px;padding:16px;box-shadow:0 1px 4px rgba(0,0,0,.25)}
.ctitle{font-size:14px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted);margin-bottom:10px;display:flex;justify-content:space-between;align-items:center}
.donut-wrap{display:flex;flex-direction:column;align-items:center;gap:10px}
.legend{display:flex;gap:12px;font-size:15px}
.leg{display:flex;align-items:center;gap:5px}
.leg-dot{width:7px;height:7px;border-radius:50%}
.sec-donut-wrap{display:flex;gap:18px;align-items:center;flex-wrap:wrap}
.sec-legend{display:flex;flex-direction:column;gap:8px;font-size:16px}
.sec-signals{display:flex;flex-wrap:wrap;gap:10px;padding:12px 14px}
.sec-sig{background:var(--surf2);border:1px solid var(--border);border-radius:6px;padding:8px 14px;font-family:'SF Mono',Consolas,monospace;font-size:16px;display:flex;flex-direction:column;gap:3px;min-width:120px}
.sec-sig-val{font-size:24px;font-weight:700}
.sec-sig-lbl{font-size:14px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px}
.tcard{background:var(--surf);border:1px solid var(--border);border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.25)}
.thdr{padding:12px 16px 10px;font-size:16px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
table{width:100%;border-collapse:collapse;font-size:16px}
thead th{padding:9px 14px;text-align:left;font-size:16px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted);background:var(--surf2);border-bottom:1px solid var(--border)}
th.r,td.r{text-align:right}
tbody tr.mrow{border-bottom:1px solid var(--border);transition:background .1s;cursor:pointer}
tbody tr.mrow:hover{background:var(--surf2)}
tbody td{padding:9px 14px;font-family:'SF Mono',Consolas,monospace;font-size:15px}
td.nm{font-family:inherit;font-weight:500;font-size:16px}
.rw{display:flex;align-items:center;justify-content:flex-end;gap:5px}
.bt{width:40px;height:3px;background:var(--border2);border-radius:2px;overflow:hidden}
.bf{height:100%;border-radius:2px;transition:width .4s}
.xrow{display:none}
.xrow.open{display:table-row}
.xcell{padding:7px 12px 9px 26px;background:var(--surf2);font-size:15px;font-family:'SF Mono',Consolas,monospace;border-bottom:1px solid var(--border)}
.xinner{display:flex;flex-wrap:wrap;gap:14px}
.xi{display:flex;flex-direction:column;gap:2px}
.xl{font-size:14px;letter-spacing:.6px;text-transform:uppercase;color:var(--dim)}
.ctags{display:flex;flex-wrap:wrap;gap:4px;margin-top:2px}
.ctag{padding:1px 6px;border-radius:4px;font-size:14px;background:var(--surf);border:1px solid var(--border2);color:var(--muted)}
.chev{font-size:14px;color:var(--muted);transition:transform .15s;display:inline-block}
.chev.open{transform:rotate(90deg)}
.ecard{background:var(--surf);border:1px solid var(--border);border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.25)}
.ehdr{padding:12px 16px 10px;font-size:16px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);display:flex;justify-content:space-between}
.ebody{overflow-y:visible}
.ev-wrap{border-bottom:1px solid rgba(30,45,61,.6);cursor:pointer}
.ev-wrap:last-child{border-bottom:none}
.evrow{display:grid;grid-template-columns:96px 1fr 66px 62px 14px;gap:6px;padding:5px 12px;font-size:15px;font-family:'SF Mono',Consolas,monospace;align-items:center}
.evrow:hover{background:var(--surf2)}
.et{color:var(--muted)}.eok{color:var(--green)}.efail{color:var(--red)}.edur{color:var(--muted);text-align:right}
.echev{color:var(--dim);font-size:12px;transition:transform .15s}
.echev.open{transform:rotate(90deg)}
.evdet{display:none;padding:5px 12px 7px 24px;background:var(--surf2);font-size:13px;font-family:'SF Mono',Consolas,monospace;color:var(--muted)}
.evdet.open{display:block}
.tgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:12px}
.tcat-hdr{grid-column:1/-1;display:flex;align-items:center;gap:7px;padding:8px 2px 4px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);margin-top:12px}
.tcat-hdr:first-child{margin-top:0}
.drag-handle{cursor:grab;opacity:.35;font-size:16px;padding:0 6px 0 0;user-select:none;flex-shrink:0}
.drag-handle:hover{opacity:.7}.drag-handle:active{cursor:grabbing}
.dragging{opacity:.45;outline:2px dashed var(--amber);border-radius:10px}
.drag-over{outline:2px dashed var(--amber);border-radius:10px;outline-offset:2px}

.tcard2{background:var(--surf);border:1px solid var(--border);border-radius:10px;padding:16px;display:flex;flex-direction:column;gap:7px;cursor:pointer;transition:border-color .15s,background .15s,box-shadow .15s;box-shadow:0 1px 4px rgba(0,0,0,.25);overflow:hidden;min-width:0}
.tcard2:hover{border-color:var(--green);background:var(--gdim)}
#suite-tip{position:fixed;z-index:9999;max-width:420px;background:#1a1f2e;border:1px solid rgba(34,197,94,.35);border-radius:10px;padding:14px 18px;box-shadow:0 8px 32px rgba(0,0,0,.6);pointer-events:none;opacity:0;transition:opacity .12s;font-size:13px;line-height:1.6;color:#c9d3e8}
#suite-tip.show{opacity:1}
#suite-tip .st-name{font-size:14px;font-weight:700;color:#e8eaf0;margin-bottom:6px;display:flex;align-items:center;gap:7px}
#suite-tip .st-body{color:#9aa3b8}
.tcard2.running{border-color:rgba(34,197,94,.4);background:var(--gdim)}
.tcn{font-weight:600;font-size:15px;display:flex;align-items:center;gap:6px;min-width:0}
.tcn-lbl{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.s-ico{font-style:normal;font-size:17px;line-height:1;flex-shrink:0}
.badge{font-size:12px;padding:1px 6px;border-radius:10px;background:var(--gdim);color:var(--green);border:1px solid rgba(34,197,94,.3);flex-shrink:0}
.tcd{font-size:13px;color:var(--muted);line-height:1.45;word-break:break-word;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.tcs{display:flex;gap:10px;font-size:13px;font-family:'SF Mono',Consolas,monospace}
.tcbar{width:100%;height:2px;background:var(--border2);border-radius:1px;overflow:hidden;margin-top:1px}
.tcbf{height:100%;border-radius:1px;transition:width .4s}
.otb{display:flex;gap:6px;padding:8px 12px;background:var(--surf);border-bottom:1px solid var(--border);align-items:center;flex-shrink:0;flex-wrap:wrap;position:sticky;top:0;z-index:5}
.otlbl{font-size:14px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted);margin-right:auto}
.btn{padding:5px 12px;border-radius:var(--r);border:1px solid var(--border2);background:var(--surf2);color:var(--muted);font-size:15px;cursor:pointer;transition:all .12s}
.btn:hover{border-color:var(--green);color:var(--green)}
.btn.af{border-color:var(--green);color:var(--green);background:var(--gdim)}
.fgrp{display:flex;gap:4px}
.obody{flex:1;min-height:0;overflow-y:auto;font-family:'SF Mono',Consolas,monospace;font-size:14px;line-height:1.65;background:#080c10}
.ll{padding:1px 14px;display:flex;align-items:baseline;gap:0;white-space:pre-wrap;word-break:break-all}
.ll:hover{background:rgba(255,255,255,.025)}
.ll-sep{padding:5px 0;display:flex;align-items:center}
.sep-line{flex:1;height:1px;background:var(--dim);opacity:.35}
.sep-txt{padding:0 10px;font-size:12px;letter-spacing:.5px;color:var(--dim);white-space:nowrap}
.llt{color:#374151;margin-right:8px;flex-shrink:0;font-size:13px}
.llv{font-weight:700;margin-right:8px;flex-shrink:0;width:40px;font-size:13px}
.llm{color:#c9d1d9;flex:1}
.ll.info .llv{color:#60a5fa}.ll.ok .llv{color:#22c55e}
.ll.warn .llv{color:#f59e0b}.ll.error .llv{color:#f85149}.ll.debug .llv{color:#374151}
.a-hero{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);padding:22px;display:flex;align-items:center;gap:18px}
.a-title{font-size:22px;font-weight:700;letter-spacing:-.4px}
.a-ver{font-size:13px;color:var(--green);font-weight:600;margin-top:3px}
.a-sub{color:var(--muted);font-size:14px;margin-top:6px;line-height:1.55}
.a-section{background:var(--surf);border:1px solid var(--border);border-radius:var(--r);padding:18px}
.a-h{font-size:14px;font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--green);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.cl-feat{display:inline-block;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:700;background:#1e3a5f;color:#60a5fa;letter-spacing:.4px}
.cl-fix{display:inline-block;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:700;background:#3d1f1f;color:#f87171;letter-spacing:.4px}
.cl-chg{display:inline-block;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:700;background:#2d2a1f;color:#fbbf24;letter-spacing:.4px}
.lk-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px}
.lk{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid var(--border);border-radius:var(--r);background:var(--surf2);text-decoration:none;color:var(--text);transition:border-color .15s;min-width:0}
.lk:hover{border-color:var(--green)}
.lk-ico{font-size:20px;flex-shrink:0}
.lk-body{min-width:0;flex:1}
.lk-name{font-weight:600;font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.lk-url{font-size:12px;color:var(--muted);font-family:'SF Mono',Consolas,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cmd-blk{background:#080c10;border:1px solid var(--border);border-radius:var(--r);padding:12px 14px;font-family:'SF Mono',Consolas,monospace;font-size:13px;line-height:1.85;color:#c9d1d9;white-space:pre-wrap;word-break:break-all}
.cmd-blk .cmt{color:#374151}.cmd-blk .flg{color:#60a5fa}
.pg-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:8px}
.pg-badge{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--surf2);border:1px solid var(--border);border-radius:var(--r);font-size:14px}
.st-table{width:100%;border-collapse:collapse;font-size:14px}
.st-table th{padding:5px 10px;text-align:left;font-size:12px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;color:var(--muted)}
.st-table td{padding:5px 10px;border-top:1px solid var(--border);color:var(--muted)}
.st-table td:first-child{font-weight:500;color:var(--text);font-family:'SF Mono',Consolas,monospace;font-size:13px;white-space:nowrap}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:299}
.overlay.open{display:block}
.drawer{position:fixed;top:0;right:-380px;width:360px;height:100vh;background:var(--surf);border-left:1px solid var(--border);z-index:300;transition:right .22s;display:flex;flex-direction:column}
.drawer.open{right:0}
.dhdr{display:flex;align-items:center;justify-content:space-between;padding:13px 16px;border-bottom:1px solid var(--border)}
.dtitle{font-weight:600;font-size:16px}
.dbody{padding:16px;display:flex;flex-direction:column;gap:14px;flex:1;overflow-y:auto}
.field{display:flex;flex-direction:column;gap:5px}
.field label{font-size:12px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted)}
.field select{width:100%;padding:7px 10px;background:var(--bg);border:1px solid var(--border2);border-radius:var(--r);color:var(--text);font-size:14px;outline:none}
.field select:focus{border-color:var(--green)}
.rngw{display:flex;align-items:center;gap:10px}
.field input[type=range]{flex:1;accent-color:var(--green)}
.rngv{font-family:'SF Mono',Consolas,monospace;font-size:14px;color:var(--text);min-width:36px;text-align:right}
.togrow{display:flex;align-items:center;justify-content:space-between}
.toglbl{font-size:15px;color:var(--text)}
.tog{position:relative;width:38px;height:21px}
.tog input{opacity:0;width:0;height:0}
.tslider{position:absolute;inset:0;background:var(--dim);border-radius:21px;transition:.18s;cursor:pointer}
.tslider:before{content:"";position:absolute;width:15px;height:15px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.18s}
input:checked+.tslider{background:var(--green)}
input:checked+.tslider:before{transform:translateX(17px)}
.btn-p{width:100%;padding:9px;background:var(--green);color:#080c10;border:none;border-radius:var(--r);font-size:15px;font-weight:700;cursor:pointer;transition:opacity .12s}
.btn-p:hover{opacity:.85}
.fnote{font-size:13px;color:var(--muted);text-align:center;line-height:1.4}
.cur-cfg{display:flex;gap:5px;flex-wrap:wrap}
.cfg-chip{padding:2px 7px;border-radius:4px;font-size:12px;font-family:'SF Mono',Consolas,monospace;background:var(--surf2);border:1px solid var(--border2);color:var(--muted)}
.modal-ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:400;align-items:center;justify-content:center}
.modal-ov.open{display:flex}
.modal{background:var(--surf);border:1px solid var(--border2);border-radius:14px;width:min(480px,95vw);max-height:85vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,.6)}
.modal-hdr{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--border)}
.modal-title{font-weight:700;font-size:16px}
.modal-body{padding:16px 18px;overflow-y:auto;display:flex;flex-direction:column;gap:12px}
.modal-desc{font-size:14px;color:var(--muted);line-height:1.5;padding:9px 11px;background:var(--surf2);border-radius:var(--r);border-left:3px solid var(--green)}
.mstats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.mstat{padding:8px 10px;background:var(--surf2);border-radius:var(--r);display:flex;flex-direction:column;gap:2px}
.mstat-lbl{font-size:12px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted)}
.mstat-val{font-size:18px;font-weight:700;font-family:'SF Mono',Consolas,monospace}
.modal-sep{font-size:12px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted);padding-bottom:4px;border-bottom:1px solid var(--border)}
.modal-ftr{padding:12px 18px;border-top:1px solid var(--border);display:flex;gap:8px}
.btn-run{flex:1;padding:9px;background:var(--green);color:#080c10;border:none;border-radius:var(--r);font-size:15px;font-weight:700;cursor:pointer;transition:opacity .12s}
.btn-run:hover{opacity:.85}
.btn-cancel{padding:9px 14px;border:1px solid var(--border2);background:var(--surf2);color:var(--muted);border-radius:var(--r);font-size:15px;cursor:pointer}
.toast{position:fixed;bottom:18px;right:18px;padding:9px 14px;border-radius:8px;font-size:14px;font-weight:500;z-index:500;display:none;pointer-events:none}
.toast.ok{background:rgba(34,197,94,.12);border:1px solid var(--green);color:var(--green)}
.toast.err{background:rgba(248,81,73,.12);border:1px solid var(--red);color:var(--red)}
.footer{padding:8px 18px;font-size:12px;color:var(--dim);border-top:1px solid var(--border);text-align:center;flex-shrink:0}
.footer a{color:var(--dim);text-decoration:none}.footer a:hover{color:var(--muted)}
.empty{padding:26px;text-align:center;color:var(--muted);font-size:14px}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--dim);border-radius:2px}
.mono{font-family:'SF Mono',Consolas,monospace;font-size:15px}
.ll.banner{padding:1px 14px}
.ll.banner .llm{color:#22c55e;white-space:pre;font-size:14px}
.ll.rule{padding:3px 0;gap:0}
.ll.summary{padding:3px 14px;border-left:2px solid var(--green);background:rgba(34,197,94,.04);margin:1px 0}
.ll.summary .llm{color:#c9d1d9;white-space:pre;font-size:14px}
.net-interval{background:var(--surf2);border:1px solid var(--border2);border-radius:4px;color:var(--muted);font-size:12px;padding:1px 4px;cursor:pointer;outline:none}
.net-interval:focus{border-color:var(--green)}
html.light{--bg:#f6f8fa;--sidebar:#eef1f5;--surf:#ffffff;--surf2:#f0f3f7;--border:#d0d7de;--border2:#8c959f;--text:#1f2328;--muted:#636e7b;--dim:#8c959f}
html.light .obody{background:#f0f4f8}html.light .obody .llm{color:#24292f}html.light .obody .llt{color:#8c959f}
html.light .obody .ll:hover{background:rgba(0,0,0,.04)}html.light .cmd-blk{background:#f0f4f8;color:#24292f}
.h-gauges{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.h-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:860px){.h-gauges,.h-row{grid-template-columns:1fr}}
.gauge-wrap{display:flex;flex-direction:column;align-items:center;padding-top:4px}
.net-widget{display:flex;gap:16px;padding:6px 0;font-family:'SF Mono',Consolas,monospace;font-size:15px;align-items:center}
.net-dir{display:flex;flex-direction:column;gap:1px}
.net-lbl{font-size:12px;font-weight:600;letter-spacing:.6px;text-transform:uppercase;color:var(--muted)}
.net-val{font-size:17px;font-weight:700}
.ro-banner{display:none;align-items:center;gap:10px;padding:7px 18px;background:rgba(245,158,11,.07);border-bottom:2px solid var(--amber);font-size:14px;color:var(--amber);flex-shrink:0}
.ro-banner strong{font-weight:700}
.ro-banner .ro-unlock{margin-left:auto;padding:2px 10px;border-radius:var(--r);border:1px solid var(--amber);background:transparent;color:var(--amber);font-size:13px;cursor:pointer}
.ro-banner .ro-unlock:hover{background:rgba(245,158,11,.12)}
body.ro-mode .ro-ctrl{opacity:.32;cursor:not-allowed}
.auth-ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:500;align-items:center;justify-content:center}
.auth-ov.open{display:flex}
.auth-box{background:var(--surf);border:1px solid var(--border2);border-radius:8px;width:min(340px,92vw);display:flex;flex-direction:column;overflow:hidden}
.auth-hdr{display:flex;align-items:center;justify-content:space-between;padding:13px 16px;border-bottom:1px solid var(--border)}
.auth-body{padding:16px;display:flex;flex-direction:column;gap:12px}
.auth-note{font-size:14px;color:var(--muted);line-height:1.5}
.auth-inp{width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--border2);border-radius:var(--r);color:var(--text);font-size:15px;font-family:'SF Mono',Consolas,monospace;outline:none}
.auth-inp:focus{border-color:var(--green)}
.auth-ftr{padding:12px 16px;border-top:1px solid var(--border);display:flex;gap:8px}
.tt{position:fixed;pointer-events:none;display:none;background:var(--surf2);border:1px solid var(--border2);border-radius:5px;padding:5px 9px;font-size:13px;font-family:'SF Mono',Consolas,monospace;line-height:1.8;z-index:200;color:var(--text);white-space:nowrap;box-shadow:0 2px 8px rgba(0,0,0,.4)}
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
  <button class="nav-item" data-tab="security" onclick="showTab(this)"><span class="nav-ico">&#128737;</span>Security</button>
  <button class="nav-item" id="nav-tests" data-tab="tests" onclick="toggleTestsNav(this)"><span class="nav-ico">⚗</span><span style="flex:1">Tests</span><span class="nav-arr" id="tests-arr" onclick="collapseTestsSub(event)" title="Collapse/expand">&#9656;</span></button>
  <div class="nav-sub" id="tests-sub">
    <button class="nav-sub-item active" onclick="setTestsCat(this,'all')">All Tests</button>
    <button class="nav-sub-item" onclick="setTestsCat(this,'Connectivity & Network')">🌐 Connectivity</button>
    <button class="nav-sub-item" onclick="setTestsCat(this,'Web & HTTP')">🌍 Web & HTTP</button>
    <button class="nav-sub-item" onclick="setTestsCat(this,'Encrypted & Modern Protocols')">🔐 Encrypted</button>
    <button class="nav-sub-item" onclick="setTestsCat(this,'Threat Detection & IDS/IPS')">🛡️ Threat Detection</button>
    <button class="nav-sub-item" onclick="setTestsCat(this,'Recon & Lateral Movement')">🕵️ Recon</button>
    <button class="nav-sub-item" onclick="setTestsCat(this,'Evasion & C2')">📡 Evasion & C2</button>
    <button class="nav-sub-item" onclick="setTestsCat(this,'UCaaS & Communications')">📞 UCaaS</button>
    <button class="nav-sub-item" onclick="setTestsCat(this,'Content Filtering')">🚧 Content Filtering</button>
  </div>
  <button class="nav-item" data-tab="output" onclick="showTab(this)"><span class="nav-ico">⬛</span>Live View</button>
  <button class="nav-item" data-tab="diagnostics" onclick="showTab(this)"><span class="nav-ico">&#128300;</span>Diagnostics</button>
  <div class="nav-lbl">System</div>
  <button class="nav-item" data-tab="health" onclick="showTab(this)"><span class="nav-ico">&#9889;</span>Health</button>
  <div class="nav-lbl">Info</div>
  <button class="nav-item" data-tab="about" onclick="showTab(this)"><span class="nav-ico">◎</span>About</button>
  <button class="nav-item" data-tab="changelog" onclick="showTab(this)"><span class="nav-ico">📋</span>Changelog</button>
  <div class="nav-lbl">Control</div>
  <button class="nav-item" onclick="openDrawer()"><span class="nav-ico">⚙</span>Settings</button>
  <div class="sb-foot">
    <div>version <span id="s-ver">—</span></div>
    <div id="s-uptime">—</div>
  </div>
</aside>
<!-- Main -->
<div class="main" id="main-scroll">
  <div class="topbar">
    <div class="tb-left">
      <span class="pg-title" id="pg-title">Overview</span>
      <span id="tb-host-ip" style="display:none;font-family:'SF Mono',Consolas,monospace;font-size:13px;font-weight:600;color:var(--blue);background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);border-radius:16px;padding:2px 10px;white-space:nowrap" title="Host LAN IP"></span>
    </div>
    <div class="tb-center">
      <span class="tb-test" id="tb-test"><span class="pulse"></span><span id="tb-test-ico"></span><span class="tb-test-name" id="tb-test-name">—</span></span>
    </div>
    <div class="tb-right">
      <span id="cfg-s-pill" class="mono" style="color:var(--muted)">—</span>
      <span id="cfg-z-pill" class="mono" style="color:var(--muted)">—</span>
      <span id="status-pill" class="tp-pill tp-dim"><span class="pulse"></span>Starting</span>
      <button id="btn-restart" class="ico-btn ok ro-ctrl" onclick="restartTests()" title="Restart tests (same settings)" style="display:none">&#9654; Restart</button>
      <button id="btn-pause" class="ico-btn ro-ctrl" onclick="togglePause()" title="Pause / Resume">&#9208;</button>
      <button id="btn-stop" class="ico-btn danger ro-ctrl" onclick="stopTests()" title="Stop all tests">&#9209;</button>
      <button class="ico-btn" onclick="openDrawer()" title="Settings">&#9881;</button>
      <button class="ico-btn" id="btn-theme" onclick="toggleTheme()" title="Toggle dark / light mode">&#9790;</button>
      <button class="ico-btn" id="btn-lock" onclick="showAuthModal()" title="Unlock admin access" style="display:none">&#128274;</button>
      <span id="pill-live" class="tp-pill tp-running ro-ctrl" style="cursor:pointer" onclick="handleLiveClick()" title="Click to stop all tests"><span class="pulse"></span>LIVE</span>
    </div>
  </div>
  <div class="ro-banner" id="ro-banner">
    &#128274; <strong>Read-only</strong> &mdash; this system is under active admin control. You can monitor but cannot modify settings or control tests.
    <button class="ro-unlock" onclick="showAuthModal()">Unlock</button>
  </div>
  <div class="content">
    <!-- Overview -->
    <div id="tab-overview" class="panel active">
      <div id="ov-grid" style="display:flex;flex-direction:column;gap:14px">
      <div class="cards" data-widget="stat-cards" style="grid-template-columns:repeat(auto-fit,minmax(140px,1fr));cursor:default">
        <div class="card"><div class="clbl">CPU</div><div class="cval c-green" id="ov-cpu">&#8212;</div></div>
        <div class="card"><div class="clbl">Memory</div><div class="cval c-blue" id="ov-mem">&#8212;</div></div>
        <div class="card"><div class="clbl">Load Average</div><div class="cval c-amber" id="ov-load" style="font-size:16px;white-space:normal;word-break:break-all">&#8212;</div><div class="csub">1m &middot; 5m &middot; 15m</div></div>
        <div class="card"><div class="clbl">Total Requests</div><div class="cval c-blue" id="v-total">&#8212;</div><div class="csub" id="s-total">&#8212;</div></div>
        <div class="card"><div class="clbl">Success Rate</div><div class="cval" id="v-rate">&#8212;</div><div class="csub" id="s-rate">&#8212;</div></div>
        <div class="card hi"><div class="clbl">Active Test</div><div class="cval c-green" id="v-test" style="font-size:16px;white-space:normal;word-break:break-word;line-height:1.2">&#8212;</div><div class="csub" id="s-test">&#8212;</div></div>
        <div class="card"><div class="clbl">Iteration</div><div class="cval c-amber" id="v-iter">&#8212;</div><div class="csub" id="s-iter">&#8212;</div></div>
        <div class="card"><div class="clbl">Probes / min</div><div class="cval c-blue" id="v-ppm">&#8212;</div><div class="csub" id="s-ppm">accumulating&hellip;</div></div>
      </div>
      <div class="cc" data-widget="net-io" style="display:flex;flex-direction:column;gap:10px">
        <div class="ctitle">Network I/O <span id="net-iface" style="font-weight:400;letter-spacing:0;text-transform:none;color:var(--dim);font-size:12px"></span>
          <select class="net-interval" onchange="setNetInterval(+this.value)" title="Refresh interval">
            <option value="1000" selected>1s</option><option value="2000">2s</option>
            <option value="5000">5s</option><option value="10000">10s</option>
            <option value="15000">15s</option><option value="30000">30s</option>
          </select>
        </div>
        <div class="net-widget">
          <div class="net-dir"><div class="net-lbl">&#9650; TX</div><div class="net-val c-blue" id="ov-tx">&#8212;</div></div>
          <div style="width:1px;background:var(--border);align-self:stretch"></div>
          <div class="net-dir"><div class="net-lbl">&#9660; RX</div><div class="net-val c-green" id="ov-rx">&#8212;</div></div>
        </div>
        <canvas id="net-spark" style="width:100%;height:50px"></canvas>
      </div>
      <div class="charts" data-widget="charts">
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
          <div class="ctitle">Requests Over Time <span id="hist-info" style="font-weight:400;letter-spacing:0;text-transform:none;font-size:12px;color:var(--dim)"></span></div>
          <canvas id="spark" style="width:100%;height:160px"></canvas>
        </div>
      </div>
      <div class="tcard" data-widget="test-breakdown">
        <div class="thdr">Test Breakdown <span style="color:var(--dim);font-weight:400;letter-spacing:0;text-transform:none;font-size:12px">&#8250; click row to expand</span></div>
        <table><thead><tr><th></th><th>Test</th><th class="r">Attempts</th><th class="r">OK</th><th class="r">Fail</th><th class="r">Rate</th><th class="r">Avg</th><th class="r">Last Run</th></tr></thead>
        <tbody id="tbl-body"><tr><td colspan="8" class="empty">Waiting for data&#8230;</td></tr></tbody></table>
      </div>
      <div class="ecard" data-widget="live-events">
        <div class="ehdr">Live Events <span id="ev-cnt" style="color:var(--dim);font-weight:400;letter-spacing:0;text-transform:none"></span></div>
        <div class="ebody" id="ev-body"><div class="empty">Waiting&#8230;</div></div>
      </div>
      <div class="tcard" data-widget="top-failing">
        <div class="thdr">Top Failing Suites</div>
        <div id="top-fail-body"><div class="empty">Waiting for data&#8230;</div></div>
      </div>
      </div><!-- /#ov-grid -->
    </div>
    <!-- Security Summary -->
    <div id="tab-security" class="panel">
      <div id="sec-grid" style="display:flex;flex-direction:column;gap:14px">
      <div class="cards" data-widget="sec-stats">
        <div class="card"><div class="clbl">Total Probes</div><div class="cval c-blue" id="sec-total">&#8212;</div><div class="csub" id="sec-total-sub">&#8212;</div></div>
        <div class="card"><div class="clbl">Blocked</div><div class="cval" id="sec-blocked" style="color:var(--amber)">&#8212;</div><div class="csub" id="sec-blocked-sub">&#8212;</div></div>
        <div class="card"><div class="clbl">Silently Dropped</div><div class="cval" id="sec-dropped" style="color:#818cf8">&#8212;</div><div class="csub" id="sec-dropped-sub">&#8212;</div></div>
        <div class="card"><div class="clbl">Allowed</div><div class="cval c-green" id="sec-allowed">&#8212;</div><div class="csub" id="sec-allowed-sub">&#8212;</div></div>
      </div>
      <div class="charts" data-widget="sec-charts">
        <div class="cc">
          <div class="ctitle">Outcome Distribution
            <select class="net-interval" onchange="setSecInterval(+this.value)" title="Summary refresh interval" id="sec-interval-sel">
              <option value="1000" selected>1s</option><option value="5000">5s</option>
              <option value="30000">30s</option><option value="60000">1m</option>
            </select>
          </div>
          <div class="sec-donut-wrap">
            <canvas id="sec-donut" width="180" height="180"></canvas>
            <div class="sec-legend">
              <div class="leg"><div class="leg-dot" style="background:#22c55e"></div><span id="sec-leg-allowed">&#8212; Allowed</span></div>
              <div class="leg"><div class="leg-dot" style="background:var(--amber)"></div><span id="sec-leg-blocked">&#8212; Blocked</span></div>
              <div class="leg"><div class="leg-dot" style="background:#818cf8"></div><span id="sec-leg-dropped">&#8212; Dropped</span></div>
              <div class="leg"><div class="leg-dot" style="background:var(--muted)"></div><span id="sec-leg-other">&#8212; Other</span></div>
            </div>
          </div>
        </div>
        <div class="cc">
          <div class="ctitle">Block &amp; Drop Trend</div>
          <canvas id="sec-trend" style="width:100%;height:160px"></canvas>
        </div>
      </div>
      <div class="tcard" data-widget="sec-breakdown">
        <div class="thdr" style="display:flex;align-items:center;justify-content:space-between">Per-Suite Security Breakdown <span style="color:var(--dim);font-weight:400;letter-spacing:0;text-transform:none;font-size:12px">sorted by blocked</span><span style="display:flex;gap:6px"><button class="ico-btn" style="font-size:12px;padding:3px 10px" onclick="exportSec('csv')" title="Export CSV">CSV</button><button class="ico-btn" style="font-size:12px;padding:3px 10px" onclick="exportSec('json')" title="Export JSON">JSON</button></span></div>
        <table><thead><tr><th>Suite</th><th class="r">Probes</th><th class="r" style="color:#22c55e">Allowed</th><th class="r" style="color:var(--amber)">Blocked</th><th class="r" style="color:#818cf8">Dropped</th><th class="r">Block%</th><th class="r">Drop%</th></tr></thead>
        <tbody id="sec-tbl"><tr><td colspan="7" class="empty">Waiting for data&#8230;</td></tr></tbody></table>
      </div>
      <div class="tcard" data-widget="sec-signals">
        <div class="thdr">Block Signal Breakdown <span style="color:var(--dim);font-weight:400;letter-spacing:0;text-transform:none;font-size:12px">how security controls are signalling blocks</span></div>
        <div id="sec-signals" class="sec-signals"><div class="empty">Waiting for data&#8230;</div></div>
      </div>
      </div><!-- /#sec-grid -->
    </div>
    <!-- Tests -->
    <div id="tab-tests" class="panel">
      <div class="tgrid" id="test-grid"><div class="empty">Waiting for data&#8230;</div></div>
    </div>
    <!-- Output -->
    <div id="tab-output" class="panel">
      <div class="otb">
        <span class="otlbl">Live View</span>
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
      <div id="wait-banner" style="display:none;align-items:center;padding:10px 14px;background:rgba(245,158,11,.06);border-top:1px solid rgba(245,158,11,.3);border-bottom:1px solid rgba(245,158,11,.3);flex-shrink:0">
        <div style="flex:1;height:1px;background:rgba(245,158,11,.3)"></div>
        <div id="wait-banner-txt" style="padding:0 16px;font-size:16px;font-weight:600;color:var(--amber);white-space:nowrap">&#8987; Pausing between tests…</div>
        <div style="flex:1;height:1px;background:rgba(245,158,11,.3)"></div>
      </div>
      <div class="obody" id="obody"></div>
    </div>
    <!-- Health -->
    <div id="tab-health" class="panel">
      <div id="health-grid" style="display:flex;flex-direction:column;gap:14px">
      <div class="tcard" data-widget="h-netinfo">
        <div class="thdr">Network Interfaces
          <span style="display:flex;gap:20px;align-items:center;font-weight:400;letter-spacing:0;text-transform:none;font-size:15px;color:var(--muted)">
            <span id="h-lan-ip-wrap">Host LAN IP: <span id="h-lan-ip" style="color:var(--blue);font-family:'SF Mono',Consolas,monospace;font-size:17px;font-weight:600">&#8212;</span></span>
            <span>Public IP: <span id="h-pub-ip" style="color:var(--green);font-family:'SF Mono',Consolas,monospace;font-size:17px;font-weight:600">&#8212;</span></span>
          </span>
        </div>
        <table><thead><tr><th>Interface</th><th>IPv4 Address</th><th>MAC Address</th><th class="r">Speed</th><th class="r">MTU</th><th class="r">Link</th></tr></thead>
        <tbody id="netinfo-body"><tr><td colspan="6" class="empty">Loading&#8230;</td></tr></tbody></table>
      </div>
      <div class="h-row" data-widget="h-io-row">
        <div class="cc">
          <div class="ctitle">Swap Usage <span id="swap-pct" style="font-weight:400;letter-spacing:0;text-transform:none;color:var(--dim)"></span></div>
          <div id="swap-detail" style="font-family:'SF Mono',Consolas,monospace;font-size:14px;color:var(--muted);margin-top:4px">&#8212; MB / &#8212; MB used</div>
          <div style="background:#1e2d3d;border-radius:4px;height:8px;margin-top:8px;overflow:hidden">
            <div id="swap-bar" style="height:100%;background:var(--amber);width:0%;transition:width .4s ease"></div>
          </div>
        </div>
        <div class="cc">
          <div class="ctitle">Cumulative Disk I/O <span style="font-weight:400;letter-spacing:0;text-transform:none;color:var(--dim);font-size:12px">since start</span></div>
          <div style="display:flex;gap:16px;margin-top:6px;font-family:'SF Mono',Consolas,monospace;font-size:14px">
            <span><span style="color:var(--muted)">Read: </span><span id="cum-drd" style="color:var(--green)">&#8212;</span></span>
            <span><span style="color:var(--muted)">Write: </span><span id="cum-dwr" style="color:var(--blue)">&#8212;</span></span>
          </div>
        </div>
      </div>
      <div class="h-row" data-widget="h-sys-row">
        <div class="cc">
          <div class="ctitle">System Uptime</div>
          <div id="sys-uptime" style="font-family:'SF Mono',Consolas,monospace;font-size:20px;color:var(--green);padding:8px 0 4px">&#8212;</div>
        </div>
        <div class="cc">
          <div class="ctitle">Process Internals</div>
          <div style="display:flex;gap:20px;margin-top:6px;font-family:'SF Mono',Consolas,monospace;font-size:14px">
            <span><span style="color:var(--muted)">Threads: </span><span id="h-threads" style="color:var(--text)">&#8212;</span></span>
            <span><span style="color:var(--muted)">Open FDs: </span><span id="h-fds" style="color:var(--text)">&#8212;</span><span id="h-fds-limit" style="color:var(--dim);font-size:11px"></span></span>
          </div>
        </div>
      </div>
      <div class="h-gauges" data-widget="h-gauges">
        <div class="cc"><div class="ctitle">CPU Usage <span id="cpu-cur" style="font-weight:400;letter-spacing:0;text-transform:none;color:var(--dim)"></span></div>
          <div class="gauge-wrap"><canvas id="cpu-gauge" width="200" height="130"></canvas></div>
          <canvas id="cpu-spark" style="width:100%;height:44px;margin-top:8px"></canvas>
        </div>
        <div class="cc"><div class="ctitle">Memory Usage <span id="mem-cur" style="font-weight:400;letter-spacing:0;text-transform:none;color:var(--dim)"></span></div>
          <div class="gauge-wrap">
            <canvas id="mem-gauge" width="200" height="130"></canvas>
            <div id="mem-detail" style="font-size:13px;color:var(--muted);margin-top:4px">&#8212; MB / &#8212; MB used</div>
            <div id="mem-stacked-bar" style="display:flex;height:8px;border-radius:4px;overflow:hidden;margin-top:8px;background:#1e2d3d"></div>
            <div id="mem-stacked-legend" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;font-size:11px;color:var(--muted)"></div>
          </div>
          <canvas id="mem-spark" style="width:100%;height:44px;margin-top:8px"></canvas>
        </div>
      </div>
      <div class="tcard" data-widget="h-cpu-cores">
        <div class="thdr">Per-Core CPU Usage</div>
        <div id="cpu-cores-body" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;padding:4px 0"><div class="empty">Loading&#8230;</div></div>
      </div>
      <div class="h-row" data-widget="h-load-row">
        <div class="cc">
          <div class="ctitle">Load Average <span style="font-weight:400;letter-spacing:0;text-transform:none;color:var(--dim)">1m &middot; 5m &middot; 15m</span></div>
          <div id="h-load" style="font-family:'SF Mono',Consolas,monospace;font-size:20px;color:var(--green);padding:8px 0 4px">&#8212; &middot; &#8212; &middot; &#8212;</div>
        </div>
        <div class="cc">
          <div class="ctitle">Disk I/O</div>
          <div style="display:flex;gap:16px;margin-bottom:8px;font-family:'SF Mono',Consolas,monospace;font-size:14px">
            <span><span style="color:var(--muted)">Read: </span><span id="disk-read" style="color:var(--green)">&#8212;</span></span>
            <span><span style="color:var(--muted)">Write: </span><span id="disk-write" style="color:var(--blue)">&#8212;</span></span>
          </div>
          <canvas id="disk-bars" width="300" height="58" style="width:100%"></canvas>
        </div>
      </div>
      <div class="cc" data-widget="h-net-io">
        <div class="ctitle">Network I/O <span id="h-net-iface" style="font-weight:400;letter-spacing:0;text-transform:none;color:var(--dim)"></span></div>
        <div style="display:flex;gap:24px;font-family:'SF Mono',Consolas,monospace;font-size:15px;margin-top:6px">
          <div><div style="font-size:12px;font-weight:600;letter-spacing:.6px;text-transform:uppercase;color:var(--muted)">&#9660; Receive</div><div id="h-rx" class="c-green" style="font-size:22px;font-weight:700;margin-top:3px">&#8212;</div></div>
          <div><div style="font-size:12px;font-weight:600;letter-spacing:.6px;text-transform:uppercase;color:var(--muted)">&#9650; Transmit</div><div id="h-tx" class="c-blue" style="font-size:22px;font-weight:700;margin-top:3px">&#8212;</div></div>
        </div>
        <canvas id="h-net-spark" width="600" height="60" style="width:100%;margin-top:10px"></canvas>
        <div style="display:flex;gap:24px;margin-top:10px;font-family:'SF Mono',Consolas,monospace;font-size:14px;color:var(--muted)">
          <span>&#8595; cumulative: <span id="cum-rx" style="color:var(--green)">&#8212;</span></span>
          <span>&#8593; cumulative: <span id="cum-tx" style="color:var(--blue)">&#8212;</span></span>
        </div>
      </div>
      <div class="tcard" data-widget="h-top-proc">
        <div class="thdr">Top Processes <span style="color:var(--dim);font-weight:400;letter-spacing:0;text-transform:none;font-size:12px">sorted by CPU</span></div>
        <table><thead><tr><th class="r">PID</th><th>Name</th><th class="r">CPU%</th><th class="r">Mem%</th><th class="r">RSS</th></tr></thead>
        <tbody id="proc-body"><tr><td colspan="5" class="empty">Loading&#8230;</td></tr></tbody></table>
      </div>
      </div><!-- /#health-grid -->
    </div>
    <!-- Diagnostics -->
    <div id="tab-diagnostics" class="panel">
      <div class="diag-tool">
        <div class="diag-tool-hdr">&#128300; Traceroute</div>
        <div class="diag-input-row">
          <input id="tr-target" class="diag-input" type="text" placeholder="hostname or IP (e.g. 8.8.8.8)" spellcheck="false" autocomplete="off" onkeydown="if(event.key==='Enter')runTrace()">
          <select id="tr-proto" class="diag-input" style="flex:0 0 auto;width:auto;padding-right:24px" onchange="trProtoChange()">
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="icmp">ICMP</option>
          </select>
          <input id="tr-port" class="diag-input" type="text" value="443" style="flex:0 0 64px" title="Destination port (TCP mode)">
          <button id="tr-btn" class="diag-btn" onclick="runTrace()">Trace</button>
          <button id="tr-stop" class="diag-btn cancel" onclick="stopTrace()" style="display:none">Stop</button>
        </div>
        <div id="tr-results"><div class="tr-status">Enter a hostname or IP address and click Trace.</div></div>
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
          <div class="a-sub">Simulates realistic network traffic across 52 test suites &#8212; DNS, HTTP/S, BGP, SSH, VoIP/UCaaS, C2 beacons, DLP, IDS/WAF triggers, lateral movement, TLS inspection, Metasploit vuln scanners, encoded payload delivery, and more.<br>Purpose-built to stress-test firewalls, IDS/IPS, URL filters, DLP engines, CASB/SASE/SSE platforms, and SIEM pipelines.</div>
        </div>
      </div>
      <div class="a-section">
        <div class="a-h">Links &amp; Resources</div>
        <div class="lk-grid">
          <a class="lk" href="https://github.com/jdibby/traffgen" target="_blank" rel="noopener"><span class="lk-ico">&#9415;</span><div class="lk-body"><div class="lk-name">GitHub Repository</div><div class="lk-url">github.com/jdibby/traffgen</div></div></a>
          <a class="lk" href="https://hub.docker.com/r/jdibby/traffgen" target="_blank" rel="noopener"><span class="lk-ico">&#127987;</span><div class="lk-body"><div class="lk-name">Docker Hub</div><div class="lk-url">hub.docker.com/r/jdibby/traffgen</div></div></a>
          <a class="lk" href="https://github.com/jdibby/traffgen/tree/main/docs" target="_blank" rel="noopener"><span class="lk-ico">&#128218;</span><div class="lk-body"><div class="lk-name">Documentation</div><div class="lk-url">github.com/jdibby/traffgen/docs</div></div></a>
        </div>
      </div>
      <div class="a-section">
        <div class="a-h">Quick Start</div>
        <div class="cmd-blk"><span class="cmt"># With web dashboard (https://&lt;host&gt;:7777)</span>
docker run --pull=always --detach --restart unless-stopped <span class="flg">-p 7777:7777</span> --name traffgen jdibby/traffgen:latest --suite=all --size=S --max-wait-secs=20 --loop

<span class="cmt"># Headless — no web dashboard, log output only</span>
docker run --pull=always --detach --restart unless-stopped --name traffgen jdibby/traffgen:latest --suite=all --size=S --max-wait-secs=20 --loop

<span class="cmt"># One-command install on fresh host (interactive — asks suite, size, UI options)</span>
sudo bash &lt; &lt;(curl -sk https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh)

<span class="cmt"># Run a specific suite once (interactive terminal output)</span>
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
          <tr><td>Connectivity</td><td style="color:var(--text)">dns &middot; icmp &middot; bgp &middot; ntp &middot; ssh &middot; doh &middot; dot &middot; blocklist-probe</td></tr>
          <tr><td>Web &amp; HTTP</td><td style="color:var(--text)">http &middot; https &middot; http3 &middot; web-crawl &middot; ftp &middot; bulk-transfer &middot; speedtest &middot; url-latency &middot; s3</td></tr>
          <tr><td>Threat Simulation</td><td style="color:var(--text)">c2-beacon &middot; malware-samples &middot; c2-useragents &middot; phishing-domains &middot; squatting &middot; av-test &middot; ad-tracker &middot; pornography</td></tr>
          <tr><td>Data Exfiltration</td><td style="color:var(--text)">dns-exfil &middot; data-exfil-http &middot; dlp &middot; llm-dlp</td></tr>
          <tr><td>IDS / IPS / WAF</td><td style="color:var(--text)">ids-trigger &middot; waf-attack &middot; log4shell &middot; nmap &middot; msf-webapp &middot; msf-enterprise &middot; msf-appliance &middot; msf-cisa-kev &middot; msf-middleware &middot; msf-recon &middot; web-scanner</td></tr>
          <tr><td>VoIP / UCaaS</td><td style="color:var(--text)">voip &middot; ucaas</td></tr>
          <tr><td>SASE / SSE / CASB</td><td style="color:var(--text)">shadow-it &middot; tor-anonymizer &middot; tls-inspection &middot; lateral-movement</td></tr>
          <tr><td>Security Tools</td><td style="color:var(--text)">snmp &middot; post-quantum &middot; ai-browse</td></tr>
          <tr><td>all</td><td style="color:var(--text)">Shuffled rotation of every suite above</td></tr>
        </table>
      </div>
      <div class="a-section">
        <div class="a-h">CLI Reference</div>
        <table class="st-table">
          <tr><th>Flag</th><th>Values</th><th>Default</th><th>Description</th></tr>
          <tr><td>--suite</td><td style="color:var(--text)">any suite name</td><td>all</td><td>Test suite to run</td></tr>
          <tr><td>--size</td><td style="color:var(--text)">XS S M L XL</td><td>S</td><td>Traffic volume / intensity</td></tr>
          <tr><td>--loop</td><td style="color:var(--text)">flag</td><td>off</td><td>Loop forever, random suite each iteration</td></tr>
          <tr><td>--max-wait-secs</td><td style="color:var(--text)">integer</td><td>20</td><td>Max pause between iterations</td></tr>
          <tr><td>--nowait</td><td style="color:var(--text)">flag</td><td>off</td><td>Skip all inter-test pauses</td></tr>
        </table>
      </div>
      <div class="a-section">
        <div class="a-h">Web Dashboard</div>
        <div style="color:var(--muted);font-size:14px;line-height:1.6">
          Runs on HTTPS port 7777. Uses a self-signed TLS certificate &#8212; your browser will show a certificate warning the first time; this is expected and safe.<br><br>
          Use <strong style="color:var(--text)">Settings</strong> to change suite, size, and wait times. Changes apply at the next test boundary without restarting the container.
          Use <strong style="color:var(--text)">&#9208; Pause</strong> to temporarily halt traffic and <strong style="color:var(--text)">&#9209; Stop</strong> to halt all tests.
          Click the <strong style="color:var(--green)">&#9679; LIVE</strong> indicator in the top-right as a shortcut to stop all tests.
        </div>
      </div>
    </div>

    <!-- Changelog -->
    <div id="tab-changelog" class="panel">
      <div style="max-width:900px">

        <div class="a-section">
          <div class="a-h">v3.4.0 &mdash; <span style="color:var(--muted);font-weight:400">May 2026</span></div>
          <table class="st-table" style="margin-top:10px">
            <tr><th style="width:80px">Type</th><th style="width:140px">Area</th><th>Description</th></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Replaced <strong>metasploit-check</strong> with six themed Metasploit suites: <strong>msf-webapp</strong> (Drupal/Joomla/WordPress/GitLab/PHP/Magento), <strong>msf-enterprise</strong> (Exchange/Atlassian/ManageEngine/SAP), <strong>msf-appliance</strong> (Cisco/PAN-OS/Juniper/FortiOS/Ivanti/F5), <strong>msf-cisa-kev</strong> (Log4Shell/GoAnywhere/MOVEit/Barracuda/SolarWinds/Check Point), <strong>msf-middleware</strong> (Struts2/WebLogic/JBoss/Spring/Jenkins/OFBiz/Solr), <strong>msf-recon</strong> (EternalBlue probe, SMB/RDP/MySQL/Redis/HTTP auxiliary scanners)</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>MSF suite output now parsed per-module — each check outcome classified as <strong>allow</strong> (reachable, check ran), <strong>drop</strong> (ECONNREFUSED/ETIMEDOUT), or <strong>fail</strong> (module error); results reflected in dashboard stat cards</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Tests page suite cards now organized alphabetically within named category sections (Connectivity &amp; Network, Web &amp; HTTP, Encrypted &amp; Modern Protocols, Threat Detection &amp; IDS/IPS, Recon &amp; Lateral Movement, Evasion &amp; C2, UCaaS &amp; Communications, Content Filtering)</td></tr>
            <tr><td><span class="cl-chg">CHG</span></td><td>Suites</td><td>Renamed 11 suites for clarity: <strong>ids-trigger</strong> → <strong>ids-sigs</strong>, <strong>virus</strong> → <strong>av-test</strong>, <strong>malware-agents</strong> → <strong>c2-useragents</strong>, <strong>malware-download</strong> → <strong>malware-samples</strong>, <strong>url-response</strong> → <strong>url-latency</strong>, <strong>bigfile</strong> → <strong>bulk-transfer</strong>, <strong>crawl</strong> → <strong>web-crawl</strong>, <strong>ads</strong> → <strong>ad-tracker</strong>, <strong>tls-check</strong> → <strong>tls-inspection</strong>, <strong>domain-check</strong> → <strong>blocklist-probe</strong>, <strong>kyber</strong> → <strong>post-quantum</strong></td></tr>
          </table>
        </div>

        <div class="a-section">
          <div class="a-h">v3.3.0 &mdash; <span style="color:var(--muted);font-weight:400">May 2026</span></div>
          <table class="st-table" style="margin-top:10px">
            <tr><th style="width:80px">Type</th><th style="width:140px">Area</th><th>Description</th></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>msf-aux-scan</strong> — Metasploit auxiliary vulnerability scanners (EternalBlue, BlueKeep, Heartbleed, Shellshock, Log4Shell, SMB enum, RDP) against live LAN hosts only; two-phase: ping sweep first, then scan confirmed-live hosts; respects <code>--lateral-networks</code> filter</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>msf-payload-delivery</strong> — msfvenom generates encoded shellcode payloads (shikata-ga-nai, xor_dynamic, powershell_base64, countdown) and delivers them via HTTP to <code>scanme.nmap.org</code> / <code>testmyids.com</code>; tests NGFW/SASE deep-packet inspection of obfuscated malware in transit</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>msf-cred-spray</strong> — Metasploit credential-testing auxiliary modules (SSH, FTP, SMB, HTTP, Telnet) with fake credentials against public test targets only; generates protocol-level brute-force traffic for UEBA/SIEM/identity-security validation</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Dashboard</td><td>Lateral Movement Networks section in Settings drawer now hidden by default; only shown when <em>lateral-movement</em> suite is selected</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Dashboard</td><td>Stat cards now use <code>auto-fit</code> grid — cards expand to fill available horizontal space on wide screens</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Deployment</td><td><code>stager.sh</code> Note and WARNING lines now print in red for visibility</td></tr>
          </table>
        </div>

        <div class="a-section">
          <div class="a-h">v3.2.0 &mdash; <span style="color:var(--muted);font-weight:400">May 2026</span></div>
          <table class="st-table" style="margin-top:10px">
            <tr><th style="width:80px">Type</th><th style="width:140px">Area</th><th>Description</th></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Lateral Movement</td><td>Multi-network concurrent scanning — all physical host interfaces discovered and swept simultaneously; per-subnet Phase 1 (ping sweep) and Phase 2 (port scan) run in parallel via <code>ThreadPoolExecutor</code></td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Lateral Movement</td><td>Network selector in Settings drawer and test modal — choose which detected subnets to scan; leave all checked to scan every network</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Lateral Movement</td><td><code>--lateral-networks</code> CLI flag — comma-separated CIDRs to restrict scanning (e.g. <code>--lateral-networks=192.168.1.0/24,10.0.0.0/24</code>); omit to scan all</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>API</td><td>New <code>GET /api/networks</code> endpoint — returns available and currently-selected lateral movement networks from generator state</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td>Configurable web dashboard port in <code>stager.sh</code> — prompts for port number (default 7777); uses <code>-p &lt;port&gt;:7777</code> so container always binds internally on 7777</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Dashboard</td><td>Network selector in Settings drawer was hidden behind suite dropdown change — now always visible; also added to lateral-movement test modal</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Dashboard</td><td>Read-only control release delay reduced from 10 s to 4 s — the JS reconnect timer is 3 s, so 4 s gives adequate margin while releasing the slot much faster after a tab closes</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Dashboard</td><td>Links &amp; Resources cards — URL text now truncates with ellipsis instead of overflowing; added Documentation link card</td></tr>
          </table>
        </div>

        <div class="a-section">
          <div class="a-h">v3.1.0 &mdash; <span style="color:var(--muted);font-weight:400">May 2026</span></div>
          <table class="st-table" style="margin-top:10px">
            <tr><th style="width:80px">Type</th><th style="width:140px">Area</th><th>Description</th></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>voip</strong> suite — STUN binding requests (RFC 5389, UDP/3478) and SIP OPTIONS (RFC 3261, UDP/5060) against 12 public registrars</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>ucaas</strong> suite — HEAD probes to 34 UCaaS endpoints: Zoom, Teams, Webex, Google Meet, Slack, RingCentral, 8x8, Vonage, GoTo, and more</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Changelog page in the web UI (this page)</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Topbar redesigned as a 3-column flex layout — host LAN IP pinned left, active test pill always centered, controls pinned right</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Host LAN IP displayed in topbar for easy identification when running multiple instances</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Green <strong>▶ Restart</strong> button appears in topbar when tests are stopped — resumes with same settings without restarting the container</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>LIVE pill changes to <strong>▶ RESTART</strong> when stopped; clicking it restarts tests rather than showing a "already stopped" toast</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>TLS Check</td><td>SASE/SSE vendor detection expanded — added Cloudflare Gateway, Menlo Security, Akamai SIA, Microsoft Defender, Lookout/CipherCloud, Aryaka, Versa Networks, Perimeter 81, Check Point Harmony, Proofpoint, F5 BIG-IP, A10 Networks, Juniper (now covers all major SASE vendors)</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td>macOS support in <code>stager.sh</code> — Homebrew, Docker Desktop via <code>brew install --cask docker</code>, <code>en0/en1</code> IP detection, hex netmask → CIDR prefix via python3</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td><code>stager.sh</code> interactive configuration — asks suite, size, loop, max-wait, dashboard on/off, and host networking before launching; shows confirmation summary</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Docs</td><td>README restructured to concise overview; full detail moved to <code>docs/</code> — deployment, configuration, suites, web-dashboard</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Generator</td><td>Stop no longer causes tests to restart — <code>finish_test()</code> now enters an idle loop instead of calling <code>sys.exit()</code>, keeping the container alive so Docker's restart policy doesn't relaunch traffic generation</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Generator</td><td>Mid-test stop now uses <code>_thread.interrupt_main()</code> to raise <code>KeyboardInterrupt</code> in the main thread rather than <code>os._exit()</code>, which also kept the container alive</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Dashboard</td><td>Stop and Pause buttons locked in read-only mode on first page load — premature <code>checkRole()</code> call before SSE established the controller session; removed the early call</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Dashboard</td><td>Toast in session read-only mode said "click Unlock" — there is no Unlock button in that mode; now says "Another session has control — you are read-only"</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>TLS Check</td><td>Cato Networks intercepted connections reported as CLEAN — the CA CN used hyphens (<code>Cato-Networks-Server-…</code>) which didn't match the space-separated token; fixed by normalising hyphens before matching</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Deployment</td><td>Duplicate Docker apt/yum sources caused <code>apt-get update</code> failures on hosts where Docker was previously added via a different method; conflicting files now removed before first update</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Deployment</td><td>Quick Start commands changed from <code>--network=host</code> to <code>-p 7777:7777</code> for cross-platform compatibility (macOS/Windows Docker Desktop do not support host networking)</td></tr>
          </table>
        </div>

        <div class="a-section">
          <div class="a-h">v3.0.0 &mdash; <span style="color:var(--muted);font-weight:400">February 2026</span></div>
          <table class="st-table" style="margin-top:10px">
            <tr><th style="width:80px">Type</th><th style="width:140px">Area</th><th>Description</th></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Live HTTPS web dashboard on port 7777 — built-in Flask server with SSE state streaming, dark/light mode, no external dependencies</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td><strong>Overview</strong> page — stat cards, network I/O sparkline, donut chart, requests-over-time sparkline, per-test breakdown table, LIVE EVENTS feed</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td><strong>Security</strong> page — KPI cards (probes/blocked/dropped/allowed), outcome donut, Block &amp; Drop Trend sparkline with hover tooltips, per-suite security breakdown</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td><strong>Tests</strong> page — card grid for every suite with emoji icons, attempt/ok/fail counters, click-to-run modal</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td><strong>Live View</strong> page — real-time log stream with level filters, auto-scroll, pop-out window, sticky toolbar</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td><strong>Health</strong> page — CPU/memory gauges, load average, disk I/O, network sparkline, Network Info widget (IP/MAC/speed/MTU, virtual interfaces filtered), top processes</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Draggable widget layout on Overview, Security, and Health pages — grab ⠿ handle to reorder; order saved to localStorage</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Multi-user session mode — first browser tab to connect gets admin control; additional tabs are read-only with a visible banner</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Settings drawer — change suite, size, wait time, loop mode without restarting the container; changes apply at next test boundary via execv</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Suite name tooltips — hover any suite name anywhere in the UI for its full description</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Topbar active test pill — always shows the currently running suite with emoji icon and pulse dot across all pages</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Host LAN IP shown in Network Info widget header (uses real host IP via <code>HOST_LAN_CIDR</code>, not Docker bridge address)</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Real suite names with dashes used everywhere in the UI (was inconsistent mix of underscores/spaces)</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Dashboard</td><td>Auto-navigate to Live View after clicking Run on the Tests page</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>tls-check</strong> — probes 15 HTTPS hosts, compares cert chains, identifies TLS inspection proxies and names the SASE/SSE vendor from the issuer</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>ids-trigger</strong> — sends Shellshock, Heartbleed, SQL injection, XSS, and EICAR payloads over HTTP to trigger IDS/IPS signatures</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>snmp</strong> v1/v2c/v3 — GET and WALK requests against public SNMP test agents</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>kyber</strong> — TLS 1.3 handshakes using X25519Kyber768 post-quantum key exchange to test whether SASE/NGFW platforms can inspect PQ traffic</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>ai-browse</strong> — simulates AI assistant API calls to OpenAI, Anthropic, Gemini, Mistral and LLM-heavy browsing sessions</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>lateral-movement</strong> — nmap host discovery and port scan against the physical LAN; reads <code>HOST_LAN_CIDR</code> or falls back to <code>--network=host</code></td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>shadow-it</strong>, <strong>tor-anonymizer</strong>, <strong>waf-attack</strong>, <strong>log4shell</strong>, <strong>metasploit-check</strong>, <strong>web-scanner</strong> (metasploit-check replaced by themed suites in later release)</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td>Multi-arch Docker image — <code>linux/amd64</code>, <code>linux/arm64</code>, <code>linux/arm/v7</code>; GitHub Actions auto-builds and pushes on every merge to main</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td>Fully automatic TLS proxy CA detection at container startup — probes 15 diverse HTTPS hosts in parallel, votes on proxy CA fingerprint, installs winning cert, runs verification pass</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td><code>stager.sh</code> — one-command deploy on Ubuntu, Debian, Rocky Linux, AlmaLinux, Amazon Linux 2/2023, Raspberry Pi 4/5; sets up Docker, prunes old containers, injects <code>HOST_LAN_CIDR</code></td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td><code>stager.sh</code> system-changes warning banner with explicit acceptance prompt before making any changes</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>600-second inactivity watchdog — force-exits the process if no test activity is detected; Docker restart policy recovers immediately</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>Per-suite wall-clock timeout guard — daemon thread enforces a maximum runtime per suite so one stuck test can't block the entire loop</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>Healthcheck via heartbeat file — <code>healthcheck.sh</code> reads <code>/tmp/traffgen.health</code> written every 2 s; replaces fragile <code>pgrep</code>-based check</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Dashboard</td><td>Live View SSE truncation — events were cut off mid-line; fixed buffering and auto-scroll to use browser page scrollbar</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Dashboard</td><td>Network Info widget — virtual/bridge interfaces (veth*, docker*, br-*) filtered out when using <code>--network=host</code></td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Dashboard</td><td>LIVE EVENTS time column was rendering at 15px — increased to match TEST BREAKDOWN font sizing</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Suites</td><td>nmap test output parsing rewritten to use grepable format for accurate ok/block/drop/fail stats</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Deployment</td><td>TLS interception alerts made prominent and vendor-specific in <code>tls-check</code> output (was generic warning)</td></tr>
          </table>
        </div>

        <div class="a-section">
          <div class="a-h">v2.6.0 &mdash; <span style="color:var(--muted);font-weight:400">January 2026</span></div>
          <table class="st-table" style="margin-top:10px">
            <tr><th style="width:80px">Type</th><th style="width:140px">Area</th><th>Description</th></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>lateral-movement</strong> (preview) — LAN host detection via <code>/proc/net/route</code> and <code>traceroute</code>; <code>HOST_LAN_IP</code> injected by <code>stager.sh</code> as fallback</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>CPU/Memory/Load Average mini-widgets integrated into Overview stat card grid</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td><code>stager.sh</code> captures host LAN IP and subnet prefix before container start, injects as <code>HOST_LAN_CIDR</code> environment variable</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td><code>stager.sh</code> runs <code>apt upgrade</code> / <code>dnf upgrade</code> on the host before installing Docker</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Suites</td><td>Lateral movement LAN detection — added <code>/proc/net/route</code> as primary strategy; traceroute as secondary fallback</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Deployment</td><td><code>stager.sh</code> banner replaced Unicode box-drawing characters with plain ASCII for compatibility across all terminals</td></tr>
          </table>
        </div>

        <div class="a-section">
          <div class="a-h">v2.5.0 &mdash; <span style="color:var(--muted);font-weight:400">November 2025</span></div>
          <table class="st-table" style="margin-top:10px">
            <tr><th style="width:80px">Type</th><th style="width:140px">Area</th><th>Description</th></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>bgp</strong> — GoBGP-based BGP session simulation with OPEN, KEEPALIVE, and UPDATE messages to public route collectors</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>doh</strong> (DNS-over-HTTPS) and <strong>dot</strong> (DNS-over-TLS) suites</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>llm-dlp</strong> — exfiltrates synthetic PII, credit card numbers, SSNs, API keys, and corporate secrets via LLM API prompts to test CASB DLP controls; 4 prompt categories including obfuscation and prompt injection</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>http3</strong> — QUIC/HTTP3 requests using <code>curl --http3-only</code> to validate QUIC inspection capability</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>data-exfil-http</strong> — simulates HTTP-based data exfiltration using POST/PUT with synthetic sensitive payloads in realistic field names</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td>Metasploit Framework pre-bundled in image via multi-stage build with vendored gems — no runtime gem install needed</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td>Automatic TLS inspection CA support — detects MITM proxy CA at startup and installs it; supports Cato Networks and any vendor</td></tr>
          </table>
        </div>

        <div class="a-section">
          <div class="a-h">v2.4.0 &mdash; <span style="color:var(--muted);font-weight:400">October 2025</span></div>
          <table class="st-table" style="margin-top:10px">
            <tr><th style="width:80px">Type</th><th style="width:140px">Area</th><th>Description</th></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>llm-dlp</strong> (initial version) — fake PII exfiltration to LLM APIs</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Suite naming standardised — all suites use dash-separated keys matching their CLI <code>--suite</code> value</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>Per-request status detail added to all test output — each request logs URL, HTTP status, latency, and outcome classification</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>Per-suite aggregate summary printed after every suite run — attempts, ok, fail, block, drop with colour coding</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>500 modern user-agent strings replacing the previous small static list; coverage across browsers, crawlers, mobile, and security tools</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>Concurrent HEAD requests via thread pool for batch endpoint probing suites</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Generator</td><td>Container hang prevention — process-group kill, per-test timeouts, watchdog reduction</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Suites</td><td>Metasploit bundler gem lookup fixed at runtime; 5 new MSF check scripts added</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Deployment</td><td>Switched base image from Ubuntu 25.10 to Debian Bookworm Slim for stability and smaller size</td></tr>
            <tr><td><span class="cl-fix">FIX</span></td><td>Deployment</td><td>Fixed Nikto install — not in Debian Bookworm repos; now cloned from upstream</td></tr>
          </table>
        </div>

        <div class="a-section">
          <div class="a-h">v2.3.0 &mdash; <span style="color:var(--muted);font-weight:400">September 2025</span></div>
          <table class="st-table" style="margin-top:10px">
            <tr><th style="width:80px">Type</th><th style="width:140px">Area</th><th>Description</th></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>kyber</strong> (initial), <strong>ai-browse</strong> (initial), <strong>shadow-it</strong>, <strong>tor-anonymizer</strong>, <strong>waf-attack</strong>, <strong>log4shell</strong></td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>voip</strong> (initial preview) — SIP and RTP traffic simulation</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>XS size tier added — minimal intensity for low-resource hosts</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>Pacing system overhauled — consistent wait times across all size tiers with configurable <code>--max-wait-secs</code></td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td>Docker image size significantly reduced via Dockerfile optimisation and multi-stage build</td></tr>
          </table>
        </div>

        <div class="a-section">
          <div class="a-h">v2.2.0 &mdash; <span style="color:var(--muted);font-weight:400">August 2025</span></div>
          <table class="st-table" style="margin-top:10px">
            <tr><th style="width:80px">Type</th><th style="width:140px">Area</th><th>Description</th></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>malware-agents</strong>, <strong>phishing-domains</strong>, <strong>squatting</strong>, <strong>ads</strong>, <strong>pornography</strong>, <strong>domain-check</strong> suites</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Added <strong>snmp</strong> (initial), <strong>nmap</strong> expanded with aggressive timing and OS detection</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>CLI refactored — <code>--suite</code>, <code>--size</code>, <code>--loop</code>, <code>--max-wait-secs</code>, <code>--nowait</code>, <code>--list</code>, <code>--version</code> flags</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>Helper functions for concurrent batch requests, size-to-limit scaling, and progress display</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td>GitHub Actions workflow — auto-build and push multi-arch Docker image on every push to main</td></tr>
          </table>
        </div>

        <div class="a-section">
          <div class="a-h">v2.0.0 &mdash; <span style="color:var(--muted);font-weight:400">July 2025</span></div>
          <table class="st-table" style="margin-top:10px">
            <tr><th style="width:80px">Type</th><th style="width:140px">Area</th><th>Description</th></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Suites</td><td>Initial suite set: <strong>dns</strong> · <strong>icmp</strong> · <strong>http</strong> · <strong>https</strong> · <strong>ftp</strong> · <strong>ssh</strong> · <strong>ntp</strong> · <strong>nmap</strong> · <strong>crawl</strong> · <strong>bigfile</strong> · <strong>speedtest</strong> · <strong>c2-beacon</strong> · <strong>malware-download</strong> · <strong>virus</strong> · <strong>dlp</strong> · <strong>dns-exfil</strong> · <strong>url-response</strong> · <strong>s3</strong></td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>Multi-protocol traffic generation across DNS, HTTP/S, FTP, SSH, ICMP, NTP, SMTP</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Generator</td><td>Round-robin suite rotation with random shuffle per loop iteration</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td>Docker container with <code>HEALTHCHECK</code>, <code>restart: unless-stopped</code>, and <code>--pull=always</code> support</td></tr>
            <tr><td><span class="cl-feat">FEAT</span></td><td>Deployment</td><td>Multi-arch build: <code>linux/amd64</code> · <code>linux/arm64</code> · <code>linux/arm/v7</code> (Raspberry Pi)</td></tr>
          </table>
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
    <div style="font-size:12px;color:var(--muted)">Current configuration:</div>
    <div class="cur-cfg" id="cur-cfg">&#8212;</div>
    <div class="field"><label>Suite</label><select id="cfg-suite" onchange="onSuiteChange(this.value)"><option value="all">all &#8212; run everything</option></select></div>
    <div id="lateral-nets-section" style="display:none">
      <div class="modal-sep" style="margin:4px 0 8px">Lateral Movement Networks</div>
      <div class="field" style="flex-direction:column;align-items:flex-start;gap:5px">
        <div style="font-size:12px;color:var(--muted)">Select which networks to scan (leave all checked to scan every detected network).</div>
        <div id="lateral-nets-list" style="display:flex;flex-direction:column;gap:5px;width:100%;margin-top:4px"></div>
        <div id="lateral-nets-none" style="font-size:12px;color:var(--muted)">No networks detected — will auto-detect at runtime</div>
      </div>
    </div>
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
    <button class="btn-p" id="drawer-apply" onclick="applySettings()">Apply &amp; Restart</button>
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
          <select id="modal-size"><option value="XS">XS</option><option value="S" selected>S</option><option value="M">M</option><option value="L">L</option><option value="XL">XL</option></select>
        </div>
        <div class="field" style="margin-bottom:10px"><label>Max Wait</label>
          <div class="rngw"><input type="range" id="modal-wait" min="5" max="300" step="5" value="20" oninput="$('modal-wv').textContent=this.value+'s'"><span class="rngv" id="modal-wv">20s</span></div>
        </div>
        <div class="field"><div class="togrow"><span class="toglbl">Loop Mode</span><label class="tog"><input type="checkbox" id="modal-loop"><span class="tslider"></span></label></div></div>
      </div>
      <div id="modal-lateral-section" style="display:none">
        <div class="modal-sep" style="margin-bottom:10px">Networks to Scan</div>
        <div style="font-size:12px;color:var(--muted);margin-bottom:8px">Select which networks to scan (leave all checked to scan every detected network).</div>
        <div id="modal-lateral-list" style="display:flex;flex-direction:column;gap:5px"></div>
        <div id="modal-lateral-none" style="font-size:12px;color:var(--muted);display:none">No networks detected — will auto-detect at runtime</div>
      </div>
    </div>
    <div class="modal-ftr">
      <button class="btn-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-run" id="btn-run-modal" onclick="runFromModal()">&#9654; Run This Test</button>
    </div>
  </div>
</div>
<div class="auth-ov" id="auth-ov" onclick="if(event.target===this)closeAuthModal()">
  <div class="auth-box">
    <div class="auth-hdr"><span style="font-weight:700;font-size:16px">&#128274; Admin Access</span><button class="ico-btn" onclick="closeAuthModal()">&#10005;</button></div>
    <div class="auth-body">
      <p class="auth-note">Enter the admin token to unlock full control of this system.</p>
      <input class="auth-inp" id="auth-inp" type="password" placeholder="Admin token" onkeydown="if(event.key==='Enter')attemptAuth()">
    </div>
    <div class="auth-ftr">
      <button class="btn-cancel" onclick="closeAuthModal()">Cancel</button>
      <button class="btn-run" onclick="attemptAuth()">&#128275; Unlock</button>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
const $=id=>document.getElementById(id);
const H=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const N=n=>Number(n).toLocaleString();
function _canvasText(){return document.documentElement.classList.contains('light')?'#1f2328':'#e2e8f0';}
function _canvasMuted(){return document.documentElement.classList.contains('light')?'#636e7b':'#64748b';}
function _canvasBg(){return document.documentElement.classList.contains('light')?'#f0f3f7':'#1e2d3d';}
const Tc=ts=>new Date(ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
const Ts=ts=>new Date(ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',hour12:false});
const Dur=ms=>ms<1000?ms+'ms':(ms/1000).toFixed(1)+'s';
const RC=p=>p>=90?'var(--green)':p>=70?'var(--amber)':'var(--red)';
let _start=null,_uptimer=null,_elTimer=null,_pauseTimer=null,_autoScroll=true,_scrollLock=false;
let _waitBannerTimer=null,_waitBannerUntil=0;
function _showWaitBanner(until){
  const wb=$('wait-banner'),txt=$('wait-banner-txt');if(!wb||!txt)return;
  _waitBannerUntil=until;
  wb.style.display='flex';
  if(_waitBannerTimer)clearInterval(_waitBannerTimer);
  function tick(){
    const rem=until>0?Math.max(0,Math.floor(until-Date.now()/1000)):0;
    txt.textContent=until>0&&rem>0
      ?'⏳ Pausing between tests — next test in '+rem+'s'
      :'⏳ Pausing between tests…';
    if(until>0&&rem<=0){_hideWaitBanner();}
  }
  tick();
  _waitBannerTimer=setInterval(tick,1000);
}
function _hideWaitBanner(){
  if(_waitBannerTimer){clearInterval(_waitBannerTimer);_waitBannerTimer=null;}
  const wb=$('wait-banner');if(wb)wb.style.display='none';
  _waitBannerUntil=0;
}
(()=>{const ob=$('obody');if(!ob)return;ob.addEventListener('scroll',()=>{if(_scrollLock)return;const gap=ob.scrollHeight-ob.scrollTop-ob.clientHeight;const atBot=gap<120;if(atBot&&!_autoScroll){_autoScroll=true;const b=$('btn-as');if(b)b.innerHTML='Auto-scroll &#10003;';}else if(!atBot&&_autoScroll){_autoScroll=false;const b=$('btn-as');if(b)b.innerHTML='Auto-scroll &#10007;';}},{passive:true});})();
let _lastState=null,_logEs=null,_logFilter='all';
let _xRows=new Set(),_xEvs=new Set(),_modalSuite=null,_isPaused=false,_lastTest=null;
let _SD={};  // suite name → description, populated on first state arrival
let _isAdmin=true,_authRequired=false,_adminToken='',_sessionMode=false,_hasController=false;
let _sessionId=(()=>{try{let s=sessionStorage.getItem('tg-sid');if(!s){s=crypto.randomUUID();sessionStorage.setItem('tg-sid',s);}return s;}catch(e){return '';}})();
function _getToken(){try{return localStorage.getItem('tg-admin-token')||'';}catch(e){return '';}}
function _setToken(t){try{if(t)localStorage.setItem('tg-admin-token',t);else localStorage.removeItem('tg-admin-token');}catch(e){}}
function _sidQs(){return _sessionId?'?sid='+encodeURIComponent(_sessionId):'';}
function _ctrl(body){
  const hdrs={'Content-Type':'application/json','X-Admin-Token':_adminToken};
  if(_sessionId)hdrs['X-Session-ID']=_sessionId;
  return fetch('/api/control'+_sidQs(),{method:'POST',headers:hdrs,body:JSON.stringify(body)});
}
function checkRole(){
  _adminToken=_getToken();
  const hdrs={'X-Admin-Token':_adminToken};
  if(_sessionId)hdrs['X-Session-ID']=_sessionId;
  fetch('/api/role'+_sidQs(),{headers:hdrs}).then(r=>r.json()).then(d=>{
    _authRequired=d.auth_required;_sessionMode=d.session_mode||false;_hasController=d.has_controller||false;_isAdmin=d.admin;applyRoleUI();
  }).catch(()=>{});
}
function applyRoleUI(){
  if(!_authRequired&&!_sessionMode){$('btn-lock').style.display='none';return;}
  const ro=!_isAdmin;
  const btext=_sessionMode&&ro&&!_hasController?'Waiting for control…':_sessionMode&&ro?'Another session is currently in control — you are read-only':'Read-only mode';
  const bel=$('ro-banner');bel.style.display=ro?'flex':'none';if(ro)bel.textContent=btext;
  $('btn-lock').style.display=(!_sessionMode&&ro)?'inline-grid':'none';
  document.body.classList.toggle('ro-mode',ro);
  $('btn-run-modal').disabled=ro;
  $('drawer-apply').disabled=ro;
}
function showAuthModal(){$('auth-ov').classList.add('open');$('auth-inp').value='';setTimeout(()=>$('auth-inp').focus(),60);}
function closeAuthModal(){$('auth-ov').classList.remove('open');}
function attemptAuth(){
  const t=$('auth-inp').value.trim();if(!t)return;
  const hdrs={'X-Admin-Token':t};if(_sessionId)hdrs['X-Session-ID']=_sessionId;
  fetch('/api/role'+_sidQs(),{headers:hdrs}).then(r=>r.json()).then(d=>{
    if(d.admin){_adminToken=t;_setToken(t);_isAdmin=true;applyRoleUI();closeAuthModal();toast('Admin access granted',true);}
    else toast('Invalid admin token',false);
  }).catch(()=>toast('Request failed',false));
}
let _healthTimer=null,_netInfoTimer=null,_lastHealth=null,_netHist=[],_hNetHist=[],_netTimer=null,_netInterval=1000;
let _cpuHist=[],_memHist=[];
function uptime(t){const s=Math.floor(Date.now()/1000-t);return[Math.floor(s/3600),Math.floor((s%3600)/60),s%60].map(v=>String(v).padStart(2,'0')).join(':');}
function elapsed(t){if(!t)return'';const s=Math.floor(Date.now()/1000-t);if(s<60)return s+'s elapsed';if(s<3600)return Math.floor(s/60)+'m '+(s%60)+'s elapsed';return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m elapsed';}
const PAGE_TITLES={overview:'Overview',security:'Security',tests:'Tests',output:'Live View',diagnostics:'Diagnostics',health:'Health',about:'About',changelog:'Changelog'};
const SUITE_ICONS={
  'ad-tracker':'🎯','ai-browse':'🤖','bgp':'🌐','bulk-transfer':'💾',
  'blocklist-probe':'🚫','c2-beacon':'📡','llm-dlp':'🧠','web-crawl':'🕷️','dlp':'🔒',
  'dns':'🔍','dns-exfil':'📤','doh':'🔐',
  'dot':'🔑','ftp':'📁','http':'🌍','http3':'⚡',
  'https':'🛡️','icmp':'🏓','ids-sigs':'🚨','post-quantum':'🔮',
  'lateral-movement':'🕵️','log4shell':'💥','tls-inspection':'🔏',
  'shadow-it':'👥','waf-attack':'🛑','data-exfil-http':'📬',
  'tor-anonymizer':'🧅',
  'c2-useragents':'👾','malware-samples':'🦠','av-test':'☣️',
  'msf-webapp':'🌐','msf-enterprise':'🏢','msf-appliance':'📡',
  'msf-cisa-kev':'🚨','msf-middleware':'⚙️','msf-recon':'🔭',
  'msf-aux-scan':'🔍','msf-payload-delivery':'📦','msf-cred-spray':'🔑',
  'speedtest':'🚀','nmap':'🗺️','ntp':'🕐','phishing-domains':'🎣',
  'pornography':'🔞','snmp':'📊','squatting':'🔤','s3':'🪣',
  'ssh':'💻','url-latency':'⏱️','web-scanner':'🔬',
  'voip':'📞','ucaas':'🎥',
  'all':'✨',
};
function suiteIco(n){const k=n.replace(/_/g,'-');return(SUITE_ICONS[k]||SUITE_ICONS[n]||'◈')+' ';}

const _SDL={
'ad-tracker':'Sends HEAD requests to 300k+ domains from the Hagezi pro ad/tracker blocklist, fetched at runtime and cached for the session. Exercises the ad-blocking and tracker-blocking URL-filter categories on NGFW and SASE platforms. High <em>allowed</em> rate means your URL filter is not enforcing ad-blocker policy. High <em>blocked</em> confirms the category is active and logging.',
'ai-browse':'HEAD requests to AI/LLM service endpoints: OpenAI, Anthropic, Mistral, Cohere, Hugging Face, Perplexity, and others. Validates whether your URL-filter or CASB policy categorises and controls access to AI services. Essential for organisations with AI-use policies — confirms that allow/block rules are actually being enforced and generating log events.',
'av-test':'Downloads EICAR AV test files and benign malware-marker samples to /dev/null. The EICAR string is the industry-standard test for inline antivirus without using real malware. High <em>allowed</em> means your inline AV or sandbox is not scanning downloads. <em>Blocked</em> confirms the AV engine intercepted the known-malware signature before it reached the endpoint.',
'bgp':'Attempts a BGP peering session using GoBGP against configured neighbors. Validates that your NGFW BGP application-ID fires, that BGP is only allowed from authorised peers, and that route-manipulation attempts generate SIEM events. Tests both TCP/179 ACL enforcement and BGP route-policy inspection.',
'blocklist-probe':'Resolves random samples from the Hagezi DNS threat-intelligence blocklist — known malware C2 domains, phishing infrastructure, and unwanted telemetry. Tests whether your DNS resolver or DNS security layer (e.g. Cisco Umbrella, Cloudflare Gateway, Palo Alto DNS Security) returns NXDOMAIN or a sinkhole IP. High <em>allowed</em> means blocklisted domains are resolving normally — a gap in DNS threat intel.',
'bulk-transfer':'Streams a large HTTP download to /dev/null — size scales with --size (XS=10 MB → XL=5 GB). Tests large-file bandwidth-cap policies, DLP file-size thresholds, and whether your proxy correctly enforces download limits. Also useful for saturating throughput to measure firewall/proxy impact on bulk transfer performance.',
'c2-beacon':'Simulates a C2 beacon: periodic HTTP POST to public echo services using known C2 framework user-agent strings (Cobalt Strike, Meterpreter, Empire, DarkComet, Sliver) with bimodal jitter (80% short 1–5s, 20% slow 10–30s). Exercises NDR behavioural models, SASE C2 detection, and SIEM correlation rules that fire on periodic outbound POST patterns.',
'c2-useragents':'HEAD requests to malware-category test URLs (WICAR, AMTSO, Google Safe Browsing test pages) using known C2 framework and RAT user-agents: Cobalt Strike, Meterpreter, PowerShell Empire, Sliver, QuasarRAT, Emotet, AgentTesla, njRAT, and others. Tests two controls independently: URL-category blocking of malware destinations, and UA-based C2 behavioral detection.',
'data-exfil-http':'POSTs synthetic PII and credential payloads to paste/file-drop services: SSN lists, Luhn-valid credit card numbers, RSA private key blocks, NTLM hashes, and CSV PII. The services return 4xx (no account) but outbound POST bodies are fully visible to inline DLP engines. Tests DLP outbound content inspection and CASB upload-control policies.',
'dlp':'Downloads DLP test files over HTTPS containing structured PII and PCI data patterns — SSNs, credit card numbers, IBAN codes, and bank account numbers. Tests inline DLP file-scanning and download-inspection policies. High <em>allowed</em> means structured sensitive data is crossing the wire without DLP intervention.',
'dns':'dig queries across multiple public resolvers (Google, Cloudflare, Quad9, OpenDNS, Cisco Umbrella) for a diverse set of domains. Validates basic DNS reachability, tests whether your firewall forces DNS through a specific resolver, and confirms DNS logging is active. Useful for detecting DNS hijacking or split-horizon misconfigurations.',
'dns-exfil':'Simulates DNS tunnelling exfiltration: base32-encoded payloads embedded in TXT record queries, mixed with A and MX lookups, with 0.3–2.0s jitter. Tests whether your DNS security layer or IDS detects abnormally long subdomain labels, high TXT query rates, or known DNS-exfil tool signatures (iodine, dnscat2 patterns).',
'doh':'DNS over HTTPS queries via RFC 8484 JSON API to rotating DoH providers (Cloudflare, Google, NextDNS, Quad9, AdGuard). Tests whether your NGFW or proxy can identify and enforce policy on DoH traffic — which bypasses traditional UDP/53 inspection. <em>Allowed</em> means DoH bypass is succeeding; <em>blocked</em> means the platform decrypts or blocks HTTPS to known DoH endpoints.',
'dot':'DNS over TLS handshakes on TCP/853 via openssl s_client. Tests whether your firewall blocks or inspects DoT — a common DNS-bypass technique. <em>Dropped</em> means TCP/853 is being blocked (correct for most policies). <em>Allowed</em> means DoT is reaching external resolvers, potentially bypassing your DNS security controls.',
'ftp':'FTP file download via curl with rate limiting against a public test FTP server. Tests FTP inspection, application-ID categorisation, and file-transfer policy. Validates whether FTP is being proxied/logged or simply allowed through without inspection.',
'http':'HTTP HEAD requests to a broad set of plain-HTTP endpoints followed by ZIP and tar.gz file downloads. Tests HTTP inspection, file-type enforcement, and download logging. Also validates that your proxy or NGFW correctly handles unencrypted HTTP vs enforcing HTTPS redirect.',
'http3':'HTTP/3 QUIC HEAD requests via a native aioquic implementation over UDP/443. QUIC is invisible to many legacy inspection stacks that only parse TCP. Tests QUIC visibility and QUIC-block policy. <em>Allowed</em> on http3 while blocked on https indicates your inspection stack has a QUIC blind spot.',
'https':'HTTPS HEAD requests to a wide endpoint pool followed by an iterative TLS crawl. Tests TLS inspection policy, certificate validation enforcement, and HTTPS download logging. Baseline suite for confirming your SASE/proxy is correctly decrypting and inspecting TLS traffic.',
'icmp':'Ping and traceroute to a set of remote hosts. Validates ICMP policy (many NGFWs block outbound ICMP by default), confirms basic internet reachability, and generates traceroute-path events. Useful for detecting ICMP-rate-limiting or silent ICMP drops by the firewall.',
'ids-sigs':'Fires 16 HTTP requests to testmyids.com — the Emerging Threats IDS validation service — each matching a distinct Snort/Suricata signature: 10 scanner user-agents (sqlmap, Nikto, Havij, ZmEu, Acunetix, etc.) and 6 web-attack URL probes (LFI, SQLi, XSS, .env disclosure, wp-admin, cmd-injection). High <em>allowed</em> means your IDS/IPS inline mode is not blocking these well-known signatures.',
'lateral-movement':'Two-phase east-west reconnaissance against all physical networks the Docker host is connected to. Phase 1: nmap ping sweep to enumerate live hosts. Phase 2: port scan every live host on 12 lateral movement ports (SSH/22, Kerberos/88, RPC/135, SMB/445, LDAP/389, RDP/3389, WinRM/5985-5986). Designed to validate micro-segmentation — confirms east-west firewall policy blocks lateral movement between segments.',
'llm-dlp':'POSTs synthetic PII (SSNs, card numbers, medical records, corporate secrets, API keys) as prompts to LLM APIs (OpenAI, Anthropic, Google, Cohere) and probes browser-accessible LLM endpoints. Tests CASB/DLP controls on AI-service uploads — the key gap for organisations allowing AI tools: sensitive data leaving in prompt payloads.',
'log4shell':'Injects Log4Shell (CVE-2021-44228) JNDI payloads into 6 HTTP headers (User-Agent, X-Forwarded-For, Referer, X-Api-Version, X-Custom-IP, Accept-Language) using LDAP, RMI, DNS, and obfuscated ${lower:} / ${::-} bypass variants. Triggers Suricata SIDs 2034907/2034908 (ET EXPLOIT Log4j). Validates IDS/WAF/SASE Log4Shell detection depth including bypass-variant coverage.',
'malware-samples':'Downloads known-malware file samples from public malware repositories to /dev/null. Tests whether anti-malware scanning or URL reputation filtering blocks downloads before they reach the endpoint. <em>Blocked</em> confirms your inline AV/sandbox intercepted the file. <em>Allowed</em> means the file crossed the wire undetected — a direct gap in endpoint-protection coverage.',
'msf-appliance':'Metasploit check-mode probes for network appliance CVEs: Cisco IOS XE (CVE-2023-20198/20273), Palo Alto PAN-OS GlobalProtect (CVE-2024-3400, CVSS 10), Juniper SRX/EX J-Web (CVE-2023-36844), Fortinet FortiOS SSL VPN (CVE-2023-27997), Ivanti Connect Secure, and F5 BIG-IP TMUI (CVE-2020-5902). All in check mode only — no exploitation. Tests whether your IDS/NGFW fires on appliance-targeted CVE probe patterns.',
'msf-aux-scan':'Metasploit auxiliary vulnerability scanners against live LAN hosts only — never blind subnet scanning. Phase 1: ping sweep to confirm live hosts. Phase 2: MSF auxiliary modules (EternalBlue/MS17-010, BlueKeep/CVE-2019-0708, Heartbleed, Shellshock, Log4Shell scanner, SMB enum, RDP detection) against confirmed-live hosts. Tests IDS/IPS detection of MSF scanner traffic and CVE probe signatures.',
'msf-cisa-kev':'Metasploit check-mode probes for CISA Known Exploited Vulnerabilities confirmed actively exploited in the wild: Log4Shell (CVE-2021-44228), GoAnywhere MFT (CVE-2024-0204), MOVEit Transfer (CVE-2023-34362), Barracuda ESG (CVE-2023-2868, UNC4841), SolarWinds WHD (CVE-2024-28986), Check Point SSL VPN (CVE-2024-24919). Highest-priority IDS/IPS validation — all are confirmed nation-state and ransomware group attack vectors.',
'msf-cred-spray':'Metasploit credential-testing auxiliary modules (SSH, FTP, SMB, HTTP Basic-Auth, Telnet) with clearly fake credentials against public test targets only — never LAN hosts to avoid account lockout. Generates protocol-level auth-attempt traffic that UEBA, SIEM, and identity-security platforms should detect as credential spraying. Validates whether your SOC has visibility into multi-protocol brute-force events.',
'msf-enterprise':'Metasploit check-mode probes for enterprise software CVEs: Exchange ProxyShell (CVE-2021-34473/34523/31207) and ProxyLogon (CVE-2021-26855), Atlassian Confluence OGNL (CVE-2023-22527), Atlassian Crowd deserialization (CVE-2019-11580), ManageEngine ADSelfService SAML RCE (CVE-2022-47966), SAP WebDynpro deserialization (CVE-2020-6287, CVSS 10), SaltStack Salt API (CVE-2021-25281). Tests whether your IDS/IPS has enterprise-product CVE signatures deployed.',
'msf-middleware':'Metasploit check-mode probes for app server and middleware CVEs: Struts2 S2-045 Content-Type OGNL (CVE-2017-5638) and S2-052 XStream deserialization (CVE-2017-9805), Oracle WebLogic T3 deserialization (CVE-2019-2725), JBoss unauthenticated deployment, Apache OFBiz deserialization (CVE-2021-26295), Spring Cloud Function SpEL (CVE-2022-22963), Jenkins Script Console, Apache Solr Velocity RCE (CVE-2019-17558).',
'msf-payload-delivery':'Generates encoded shellcode payloads via msfvenom (shikata_ga_nai, xor_dynamic, powershell_base64, countdown) and delivers them as HTTP POST bodies to scanme.nmap.org and testmyids.com. Payloads are never executed — no listener, no shell. Tests whether NGFW/SASE deep-packet inspection detects obfuscated malware payload bytes in transit, even when encoder-layered to evade signature matching.',
'msf-recon':'Metasploit auxiliary recon scanners that generate tier-1 IDS/IPS fingerprinting traffic: EternalBlue (MS17-010) probe, SMB share enumeration, RDP service detection, MySQL version banner, Redis unauthenticated access, HTTP version banner grab, robots.txt fetch, SSH version scan. Output parsed per-module — <em>drop</em> means your firewall is silently blocking the probe; <em>allowed</em> means the scan reached a live service.',
'msf-webapp':'Metasploit check-mode probes for web app CVEs: Drupal Drupalgeddon2 (CVE-2018-7600) and Drupalgeddon3 (CVE-2018-7602), Joomla HTTP header RCE (CVE-2015-8562), WordPress RevSlider file upload, GitLab ExifTool RCE (CVE-2021-22205), PHP CGI argument injection (CVE-2024-4577), Magento Shoplift SQLi (CVE-2015-1397), Webmin Package Update RCE (CVE-2019-12840). Tests IDS/IPS web-app CVE signature coverage.',
'nmap':'Nmap port scan covering ports 1–1024 against authorised public hosts (scanme.nmap.org, testmyids.com, juice-shop.herokuapp.com), followed by an NSE CVE-script scan (--script=ALL). Tests whether IDS/IPS detects and alerts on port-scan patterns and CVE-detection probe signatures. Validates that your SIEM receives port-scan events and correlates them correctly.',
'ntp':'NTP UDP probes to a pool of public time servers (pool.ntp.org stratum-1/2 servers). Validates NTP reachability, tests whether your firewall allows or blocks outbound UDP/123, and confirms NTP application-ID categorisation. <em>Dropped</em> across all targets may indicate UDP/123 ACL or NTP reflection-attack mitigation blocking outbound probes.',
'phishing-domains':'Resolves domains from an active phishing feed to /dev/null. Tests anti-phishing DNS/URL filtering — confirms that recently-registered phishing domains are blocked and that blocks are generating SIEM events. High <em>allowed</em> means your threat-intel feed latency is too high or anti-phishing categorisation is not enforced.',
'pornography':'HTTPS crawl of adult-content endpoints. Tests the adult-content URL-filter category and confirms policy enforcement is logging correctly. Primarily useful for organisations with acceptable-use policies — validates that the category block is active and generating audit-log events for compliance reporting.',
'post-quantum':'HTTPS HEAD requests using X25519MLKEM768 (Kyber) hybrid post-quantum key exchange. Tests whether TLS inspection infrastructure can handle PQC cipher suites without breaking connectivity. <em>Dropped</em> or TLS errors may indicate your SSL/TLS proxy does not support PQC key exchange and will break traffic as clients adopt hybrid PQC by default in TLS 1.3.',
's3':'Simulates S3 bucket access: GET requests to public AWS datasets and private-style bucket paths (200 or 403 — both are CASB-visible S3 events), plus PUT requests uploading synthetic PII/credential payloads to S3 paths. PUT requests return 403 (no credentials) but outbound data is fully visible to DLP and CASB engines as cloud-upload attempts. Also targets Wasabi and Backblaze B2.',
'shadow-it':'HEAD requests to 27 unsanctioned cloud apps across 5 CASB categories: personal file sharing (Dropbox, MEGA, WeTransfer, iCloud), personal messaging (Discord, Telegram), privacy mail (ProtonMail, Tutanota), paste/file hosting (Pastebin, GoFile), and crypto/blockchain (Coinbase, Etherscan). Tests CASB app-control categories. High <em>allowed</em> means shadow IT apps are not controlled.',
'snmp':'SNMPv1, SNMPv2c, and SNMPv3 walks against public SNMP test targets using common community strings (public, private, community) and default credentials. Tests SNMP application-ID detection, validates whether SNMP is logged by your SIEM, and confirms SNMPv1/v2c community-string exposure alerts fire on your IDS.',
'speedtest':'fast.com speed test via fastcli. Measures download throughput as experienced by the container — a direct measurement of firewall/proxy throughput impact. Compare results with and without the security stack to quantify TLS inspection overhead and identify throughput bottlenecks.',
'squatting':'Runs dnstwist to generate typosquatting variants of popular brand domains (homoglyphs, additions, transpositions, bitsquatting), resolves each variant, and checks for live A records. Tests whether DNS analytics detect abnormal typosquatting lookup volumes. High resolution rate for lookalike domains may indicate active phishing infrastructure targeting your brand.',
'ssh':'Non-interactive SSH connection attempts to a set of endpoints — establishes the TCP connection and completes key exchange without authenticating. Tests SSH application-ID categorisation, validates that your NGFW generates SSH session events, and confirms SSH is only allowed to authorised destinations.',
'tls-inspection':'Connects to 20 diverse HTTPS endpoints (finance, government, social, developer, CDN) and reports the TLS certificate issuer for each. Classifies each as CLEAN (direct cert), INTERCEPTED (issuer matches a known SASE/proxy vendor CA), UNVERIFIED (proxy re-signing with untrusted CA), or UNREACHABLE. Detects selective bypass: if high-risk categories are CLEAN while others are INTERCEPTED, your proxy has category-based bypass rules.',
'tor-anonymizer':'HEAD requests to Tor Project, commercial VPN landing pages, and web-proxy sites (check.torproject.org, ProtonVPN, NordVPN, Mullvad, kproxy.com, croxyproxy.com, etc.). Tests the anonymizers/proxy-avoidance URL-filter category on NGFW and SASE. High <em>allowed</em> means users can reach proxy/VPN services that would let them bypass your controls.',
'ucaas':'HEAD requests to 30+ UCaaS signaling URLs across Zoom, Teams, WebEx, Google Meet, Slack, RingCentral, 8x8, GoTo, Discord voice, Apple FaceTime, Vonage, Twilio, and Jitsi. Validates UCaaS/video-conferencing app-ID categories on Palo Alto, Cato, Zscaler, and Prisma Access. Confirms UCaaS QoS policies are matching the correct application.',
'url-latency':'Measures HTTPS response times across a diverse URL set using the Python requests library, logging HTTP status and latency for each. Populates URL-filter logs and tests latency impact of your SSL inspection stack. Elevated latency on inspected sites compared to bypassed sites quantifies the real-world overhead of your SASE/proxy.',
'voip':'Phase 1: STUN Binding Requests (UDP/3478 + 19302) to 15 public STUN servers used by Zoom, Google Meet, Teams, and SIP stacks — tests WebRTC and STUN visibility. Phase 2: SIP OPTIONS probes (UDP/5060) to 12 public SIP registrars — the standard SIP keepalive that triggers SIP app-ID signatures. Tests whether your NGFW correctly identifies and logs VoIP/WebRTC signaling traffic.',
'waf-attack':'Sends 18 WAF-targeting attack payloads in URL query params and POST bodies: SQLi (UNION SELECT, error-based, blind, SLEEP), XSS (script/img/svg tags), LFI (path traversal), SSRF (AWS metadata endpoint, localhost), OS command injection (semicolon/pipe/backtick), XXE (external entity declaration), and SSTI (Jinja2/Twig template expressions). Tests WAF inline blocking depth across all major attack categories.',
'web-crawl':'Iterative web crawl from a configurable seed URL (--crawl-start), following links to a depth that scales with --size. Mimics a browser browsing session for URL categorisation and user-activity analytics testing. Generates realistic GET request patterns across multiple domains — useful for testing URL filtering, SSL inspection, and user-activity analytics at session depth.',
'web-scanner':'Nikto web vulnerability scanner against testmyids.com. Generates broad vulnerability-probe HTTP requests: path traversal, CGI probes, HTTP header injection, known CVE fingerprints, dangerous method tests, and server-banner extraction. Tests whether your IDS/WAF detects and logs web-scanner traffic and validates that Nikto UA signatures fire on your IDS.',
};
(function(){
  const tip=document.createElement('div');
  tip.id='suite-tip';
  document.body.appendChild(tip);
  let _tid=null;
  const GAP=14;
  function rePos(x,y){
    const tw=tip.offsetWidth||340,th=tip.offsetHeight||80;
    const vw=window.innerWidth,vh=window.innerHeight;
    let l=x+GAP,t=y+GAP;
    if(l+tw>vw-8)l=x-tw-GAP;
    if(t+th>vh-8)t=y-th-GAP;
    tip.style.left=Math.max(8,l)+'px';
    tip.style.top=Math.max(8,t)+'px';
  }
  document.addEventListener('mouseover',e=>{
    const card=e.target.closest('.tcard2');
    if(!card)return;
    clearTimeout(_tid);
    const nm=card.dataset.suite||'',desc=card.dataset.desc||'';
    if(!desc)return;
    const detail=_SDL[nm]||desc;tip.innerHTML='<div class="st-name">'+suiteIco(nm)+'<span>'+nm+'</span></div><div class="st-body">'+detail+'</div>';
    rePos(e.clientX,e.clientY);
    _tid=setTimeout(()=>tip.classList.add('show'),80);
  });
  document.addEventListener('mousemove',e=>{
    if(tip.classList.contains('show'))rePos(e.clientX,e.clientY);
  });
  document.addEventListener('mouseout',e=>{
    if(!e.target.closest('.tcard2'))return;
    clearTimeout(_tid);tip.classList.remove('show');
  });
})();
const _SC={
  'bgp':'Connectivity & Network','dns':'Connectivity & Network','icmp':'Connectivity & Network',
  'ntp':'Connectivity & Network','snmp':'Connectivity & Network','ssh':'Connectivity & Network',
  'ad-tracker':'Web & HTTP','ai-browse':'Web & HTTP','bulk-transfer':'Web & HTTP','web-crawl':'Web & HTTP',
  'ftp':'Web & HTTP','http':'Web & HTTP','https':'Web & HTTP','s3':'Web & HTTP',
  'speedtest':'Web & HTTP','url-latency':'Web & HTTP',
  'doh':'Encrypted & Modern Protocols','dot':'Encrypted & Modern Protocols',
  'http3':'Encrypted & Modern Protocols','post-quantum':'Encrypted & Modern Protocols',
  'data-exfil-http':'Threat Detection & IDS/IPS','dlp':'Threat Detection & IDS/IPS',
  'ids-sigs':'Threat Detection & IDS/IPS','log4shell':'Threat Detection & IDS/IPS',
  'c2-useragents':'Threat Detection & IDS/IPS','malware-samples':'Threat Detection & IDS/IPS',
  'msf-appliance':'Threat Detection & IDS/IPS','msf-aux-scan':'Threat Detection & IDS/IPS',
  'msf-cisa-kev':'Threat Detection & IDS/IPS','msf-cred-spray':'Threat Detection & IDS/IPS',
  'msf-enterprise':'Threat Detection & IDS/IPS','msf-middleware':'Threat Detection & IDS/IPS',
  'msf-payload-delivery':'Threat Detection & IDS/IPS','msf-recon':'Threat Detection & IDS/IPS',
  'msf-webapp':'Threat Detection & IDS/IPS',
  'nmap':'Threat Detection & IDS/IPS','tls-inspection':'Threat Detection & IDS/IPS',
  'av-test':'Threat Detection & IDS/IPS','waf-attack':'Threat Detection & IDS/IPS',
  'web-scanner':'Threat Detection & IDS/IPS',
  'blocklist-probe':'Recon & Lateral Movement','lateral-movement':'Recon & Lateral Movement',
  'phishing-domains':'Recon & Lateral Movement','squatting':'Recon & Lateral Movement',
  'c2-beacon':'Evasion & C2','dns-exfil':'Evasion & C2','llm-dlp':'Evasion & C2',
  'shadow-it':'Evasion & C2','tor-anonymizer':'Evasion & C2',
  'ucaas':'UCaaS & Communications','voip':'UCaaS & Communications',
  'pornography':'Content Filtering',
};
let _testsCat='all';
function _openTestsSub(){$('tests-sub').classList.add('open');$('tests-arr').classList.add('open');}
function _closeTestsSub(){$('tests-sub').classList.remove('open');$('tests-arr').classList.remove('open');}
function toggleTestsNav(btn){
  _openTestsSub();
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  btn.classList.add('active');
  $('tab-tests').classList.add('active');
  $('pg-title').textContent='Tests';
}
function collapseTestsSub(e){
  e.stopPropagation();
  if($('tests-sub').classList.contains('open')){_closeTestsSub();}else{_openTestsSub();}
}
function setTestsCat(el,cat){
  _testsCat=cat;
  document.querySelectorAll('.nav-sub-item').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  if(_lastState)renderState(_lastState);
}
function showTab(btn){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  btn.classList.add('active');
  $('tab-'+btn.dataset.tab).classList.add('active');
  $('pg-title').textContent=PAGE_TITLES[btn.dataset.tab]||btn.dataset.tab;
  if(btn.dataset.tab!=='tests')_closeTestsSub();
  if(btn.dataset.tab==='output')connectLog();
  clearInterval(_healthTimer);_healthTimer=null;
  clearInterval(_netInfoTimer);_netInfoTimer=null;
  clearInterval(_secTimer);_secTimer=null;
  if(btn.dataset.tab==='health'){pollHealth();pollNetInfo();_healthTimer=setInterval(()=>{pollHealth();},2500);_netInfoTimer=setInterval(pollNetInfo,15000);_initDrag('health-grid');}
  if(btn.dataset.tab==='security'){updateSecurityTab();_secTimer=setInterval(updateSecurityTab,_secInterval);_initDrag('sec-grid');}
}
function navTo(tab){if(tab==='tests'){const btn=$('nav-tests');if(btn)toggleTestsNav(btn);return;}const btn=document.querySelector('.nav-item[data-tab="'+tab+'"]');if(btn)showTab(btn);}
function drawDonut(ok,fail){
  const c=$('donut'),ctx=c.getContext('2d'),W=c.width,H2=c.height,cx=W/2,cy=H2/2,r=66,ri=46;
  const tot=ok+fail;ctx.clearRect(0,0,W,H2);
  if(!tot){ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.arc(cx,cy,ri,0,Math.PI*2,true);ctx.fillStyle=_canvasBg();ctx.fill('evenodd');ctx.fillStyle=_canvasMuted();ctx.font='13px system-ui';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText('No data',cx,cy);return;}
  const okA=(ok/tot)*Math.PI*2,s=-Math.PI/2;
  ctx.beginPath();ctx.arc(cx,cy,r,s,s+okA);ctx.arc(cx,cy,ri,s+okA,s,true);ctx.fillStyle='#22c55e';ctx.fill();
  if(fail>0){ctx.beginPath();ctx.arc(cx,cy,r,s+okA,s+Math.PI*2);ctx.arc(cx,cy,ri,s+Math.PI*2,s+okA,true);ctx.fillStyle='#f85149';ctx.fill();}
  ctx.fillStyle=_canvasText();ctx.font='bold 19px SF Mono,Consolas,monospace';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(((ok/tot)*100).toFixed(1)+'%',cx,cy-6);
  ctx.fillStyle=_canvasMuted();ctx.font='12px system-ui';ctx.fillText('success',cx,cy+9);
}
function drawSpark(history){
  const c=$('spark'),rect=c.getBoundingClientRect();c.width=Math.floor(rect.width)||500;c.height=Math.floor(rect.height)||160;
  const ctx=c.getContext('2d'),W=c.width,H2=c.height,P={t:10,r:10,b:22,l:36},IW=W-P.l-P.r,IH=H2-P.t-P.b;
  ctx.clearRect(0,0,W,H2);
  if(!history||history.length<2){ctx.fillStyle=_canvasMuted();ctx.font='13px system-ui';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText('Accumulating data…',W/2,H2/2);return;}
  const okV=history.map(p=>p.ok||0),failV=history.map(p=>p.fail||0),mx=Math.max(...okV,...failV,1);
  const xOf=i=>P.l+(i/(history.length-1))*IW,yOf=v=>P.t+IH-(v/mx)*IH;
  ctx.strokeStyle='#1e2d3d';ctx.lineWidth=1;
  for(let i=0;i<=4;i++){const y=P.t+(i/4)*IH;ctx.beginPath();ctx.moveTo(P.l,y);ctx.lineTo(P.l+IW,y);ctx.stroke();ctx.fillStyle=_canvasMuted();ctx.font='12px SF Mono,Consolas,monospace';ctx.textAlign='right';ctx.fillText(Math.round(mx*(1-i/4)),P.l-4,y+3);}
  ctx.beginPath();history.forEach((p,i)=>{const x=xOf(i),y=yOf(p.ok||0);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y)});
  ctx.lineTo(xOf(history.length-1),P.t+IH);ctx.lineTo(xOf(0),P.t+IH);ctx.closePath();
  const g=ctx.createLinearGradient(0,P.t,0,P.t+IH);g.addColorStop(0,'rgba(34,197,94,.22)');g.addColorStop(1,'rgba(34,197,94,.01)');ctx.fillStyle=g;ctx.fill();
  ctx.beginPath();history.forEach((p,i)=>{const x=xOf(i),y=yOf(p.ok||0);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y)});
  ctx.strokeStyle='#22c55e';ctx.lineWidth=2;ctx.lineJoin='round';ctx.stroke();
  if(failV.some(v=>v>0)){ctx.beginPath();history.forEach((p,i)=>{const x=xOf(i),y=yOf(p.fail||0);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y)});ctx.strokeStyle='#f85149';ctx.lineWidth=1.5;ctx.setLineDash([4,3]);ctx.stroke();ctx.setLineDash([]);}
  ctx.fillStyle=_canvasMuted();ctx.font='12px SF Mono,Consolas,monospace';ctx.textAlign='left';ctx.fillText(Ts(history[0].t),P.l,H2-3);ctx.textAlign='right';ctx.fillText(Ts(history[history.length-1].t),P.l+IW,H2-3);
}
const ST_CLS={running:'tp-running',between_tests:'tp-dim',paused:'tp-paused',stopped:'tp-stopped',starting:'tp-dim'};
const ST_LBL={running:'Running',between_tests:'Between Tests',paused:'Paused',stopped:'Stopped',starting:'Starting'};
function apply(s){
  _lastState=s;
  if(s.suites&&s.suites.length&&!Object.keys(_SD).length){s.suites.forEach(su=>{_SD[su.name]=su.description||'';});}
  const ver=s.version||'—';
  $('s-ver').textContent=ver;$('about-ver').textContent=ver;
  if(s.started_at&&!_start){_start=s.started_at;clearInterval(_uptimer);_uptimer=setInterval(()=>$('s-uptime').textContent='up '+uptime(_start),1000);}
  const st=s.status||'starting';
  if(st==='between_tests'){const pu=s.pause_until||0,now=Date.now()/1000;_showWaitBanner(pu>now?pu:0);}else{_hideWaitBanner();}
  const pill=$('status-pill');pill.className='tp-pill '+(ST_CLS[st]||'tp-dim');
  clearInterval(_pauseTimer);_pauseTimer=null;
  if(st==='between_tests'&&s.pause_until){
    const renderCD=()=>{const rem=Math.max(0,Math.ceil(s.pause_until-Date.now()/1000));pill.textContent='Between Tests ('+rem+'s)';if(rem<=0){clearInterval(_pauseTimer);_pauseTimer=null;}};
    renderCD();_pauseTimer=setInterval(renderCD,250);
  } else {
    const dot=st==='running'||st==='starting';pill.innerHTML=(dot?'<span class="pulse"></span>':'')+(ST_LBL[st]||st);
  }
  _isPaused=(st==='paused');$('btn-pause').innerHTML=_isPaused?'&#9654;':'&#9208;';$('btn-pause').title=_isPaused?'Resume tests':'Pause tests';
  const isStopped=(st==='stopped');
  $('btn-restart').style.display=isStopped?'inline-flex':'none';
  $('btn-pause').style.display=isStopped?'none':'inline-grid';
  $('btn-stop').style.display=isStopped?'none':'inline-grid';
  const lp=$('pill-live');if(isStopped){lp.className='tp-pill tp-stopped';lp.innerHTML='&#9654; RESTART';lp.title='Click to restart tests';}else{lp.className='tp-pill tp-running';lp.innerHTML='<span class="pulse"></span>LIVE';lp.title='Click to stop all tests';}
  $('cfg-s-pill').textContent='suite:'+(s.suite||'—');$('cfg-z-pill').textContent='size:'+(s.size||'—');
  const tot=s.totals||{},ok=tot.ok||0,fail=tot.fail||0,att=tot.attempts||0,p=att?ok/att*100:0,blk=tot.blocked||0,drp=tot.dropped||0;
  $('v-total').textContent=N(att);$('s-total').textContent=N(ok)+' ok \xb7 '+N(fail)+' fail'+(blk?' \xb7 '+N(blk)+' blocked':'')+(drp?' \xb7 '+N(drp)+' dropped':'');
  $('v-rate').textContent=att?p.toFixed(1)+'%':'—';$('v-rate').style.color=att?RC(p):'var(--muted)';$('s-rate').textContent=att?N(att)+' total requests':'No data yet';
  const cur=s.current_test||'',tsa=s.test_started_at||0;
  $('v-test').textContent=cur?cur:'—';
  const tbt=$('tb-test'),tbn=$('tb-test-name'),tbi=$('tb-test-ico');
  if(tbt&&tbn&&tbi){if(cur&&st==='running'){tbt.classList.add('visible');tbn.textContent=cur;tbi.textContent=suiteIco(cur);}else{tbt.classList.remove('visible');}}
  if(tsa&&cur){clearInterval(_elTimer);const upEl=()=>$('s-test').textContent=elapsed(tsa);upEl();_elTimer=setInterval(upEl,1000);}
  else{clearInterval(_elTimer);$('s-test').textContent=s.loop?'Loop mode':'Single-run';}
  $('v-iter').textContent=s.iteration?'#'+N(s.iteration):'—';$('s-iter').textContent='Suite: '+(s.suite||'—')+' \xb7 Size: '+(s.size||'—');
  drawDonut(ok,fail);$('leg-ok').textContent=N(ok)+' OK';$('leg-fail').textContent=N(fail)+' Fail';
  const hist=s.history||[];drawSpark(hist);if(hist.length>1)$('hist-info').textContent=hist.length+' samples';
  if(hist.length>=2){const h0=hist[hist.length-2],h1=hist[hist.length-1],dt=h1.t-h0.t,dp=(h1.ok+h1.fail)-(h0.ok+h0.fail);if(dt>0){const ppm=Math.round(dp/dt*60);$('v-ppm').textContent=N(ppm);$('s-ppm').textContent='probes per minute';}}else{$('v-ppm').textContent='—';$('s-ppm').textContent='accumulating…';}
  const tests=s.tests||{},names=Object.keys(tests).sort(),tb=$('tbl-body');
  if(!names.length){tb.innerHTML='<tr><td colspan="8" class="empty">Waiting…</td></tr>';}
  else tb.innerHTML=names.map(n=>{
    const t=tests[n],ta=t.attempts||0,tok=t.ok||0,tf=t.fail||0,tp=ta?tok/ta*100:0;
    const bc=RC(tp),lr=t.last_run_at?Tc(t.last_run_at):'—',act=n===cur,exp=_xRows.has(n);
    const codes=t.codes||{};
    const ctags=Object.entries(codes).sort().map(([k,v])=>`<span class="ctag">${H(k)}: ${N(v)}</span>`).join('');
    return`<tr class="mrow${act?' style="background:rgba(34,197,94,.04)"':''}" onclick="toggleRow('${n}')">
      <td><span class="chev${exp?' open':''}">&#8250;</span></td>
      <td class="nm" title="${_SD[n]||''}" style="cursor:default"><span class="s-ico">${suiteIco(n)}</span>${act?'<span style="color:var(--green)">&#9654; </span>':''}${H(n)}</td>
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
      <div class="xi"><div class="xl">Blocked</div>${N(t.blocked||0)}</div>
      <div class="xi"><div class="xl">Dropped</div>${N(t.dropped||0)}</div>
    </div></td></tr>`;
  }).join('');
  const evs=(s.events||[]).slice().reverse().slice(0,30),eb=$('ev-body');
  $('ev-cnt').textContent=evs.length?' \xb7 '+evs.length+' events':'';
  eb.innerHTML=!evs.length?'<div class="empty">Waiting…</div>':evs.map((e,i)=>{
    const exp=_xEvs.has(i);
    const codes=e.codes&&Object.keys(e.codes).length?Object.entries(e.codes).sort().map(([k,v])=>k+':'+v).join(' \xb7 '):'';
    return`<div class="ev-wrap" onclick="toggleEv(${i})"><div class="evrow">
      <span class="et">${Tc(e.t)}</span>
      <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${_SD[e.test||'']||''}">${H((e.test||''))}</span>
      <span class="${e.ok?'eok':'efail'}">${e.ok?'✓ OK':'✗ FAIL'}</span>
      <span class="edur">${e.dur_ms!=null?Dur(e.dur_ms):'—'}</span>
      <span class="echev${exp?' open':''}">&#8250;</span>
    </div>
    <div class="evdet${exp?' open':''}">suite: ${H(e.test||'—')} \xb7 result: ${e.ok?'OK':'FAIL'} \xb7 dur: ${e.dur_ms!=null?Dur(e.dur_ms):'—'} \xb7 responses: ${e.responses||0}${e.blocked?' \xb7 blocked: '+N(e.blocked):''}${e.dropped?' \xb7 dropped: '+N(e.dropped):''}${codes?' \xb7 codes: '+H(codes):''}</div>
    </div>`;
  }).join('');
  const suites=s.suites||[],tg=$('test-grid');
  if(!suites.length){tg.innerHTML='<div class="empty">Waiting for data…</div>';}
  else{
    const _CO=['Connectivity & Network','Web & HTTP','Encrypted & Modern Protocols',
               'Threat Detection & IDS/IPS','Recon & Lateral Movement','Evasion & C2',
               'UCaaS & Communications','Content Filtering'];
    const _CI={'Connectivity & Network':'🌐','Web & HTTP':'🌍',
               'Encrypted & Modern Protocols':'🔐','Threat Detection & IDS/IPS':'🛡️',
               'Recon & Lateral Movement':'🕵️','Evasion & C2':'📡',
               'UCaaS & Communications':'📞','Content Filtering':'🚧'};
    const cm={};
    const filtSuites=_testsCat==='all'?suites:suites.filter(su=>(_SC[su.name]||'')===_testsCat);
    filtSuites.forEach(su=>{const c=_SC[su.name]||'Other';(cm[c]=cm[c]||[]).push(su);});
    Object.values(cm).forEach(a=>a.sort((a,b)=>a.name.localeCompare(b.name)));
    const co=_CO.concat(Object.keys(cm).filter(c=>!_CO.includes(c)).sort());
    const mkCard=su=>{
      const td=tests[su.name]||{},ta=td.attempts||0,tok=td.ok||0,tf=td.fail||0,tp=ta?tok/ta*100:0;
      const bc=RC(tp),act=su.name===cur;
      return`<div class="tcard2${act?' running':''}" data-suite="${H(su.name)}" data-desc="${H(su.description||'')}" onclick="openModal(this.dataset.suite,this.dataset.desc)">
        <div class="tcn" title="${H(su.description||'')}"><span class="s-ico">${suiteIco(su.name)}</span><span class="tcn-lbl">${H(su.name)}</span>${act?'<span class="badge">RUNNING</span>':''}</div>
        <div class="tcd">${H(su.description||'—')}</div>
        <div class="tcs"><span style="color:var(--muted)">${N(ta)} attempts</span><span style="color:var(--green)">${N(tok)} ok</span><span style="color:${tf?'var(--red)':'var(--muted)'}">${N(tf)} fail</span>${ta?'<span style="color:'+bc+'">'+tp.toFixed(1)+'%</span>':''}</div>
        ${ta?`<div class="tcbar"><div class="tcbf" style="width:${tp}%;background:${bc}"></div></div>`:''}
      </div>`;
    };
    if(!filtSuites.length){tg.innerHTML='<div class="empty">No suites in this category</div>';}
    else tg.innerHTML=co.filter(c=>cm[c]).map((c,i)=>
      `<div class="tcat-hdr"${i===0?'':''} >${_CI[c]||'📋'} ${H(c)}</div>`+cm[c].map(mkCard).join('')
    ).join('');
  }
  // Top failing suites widget
  (function(){
    const tfb=$('top-fail-body');if(!tfb)return;
    const ts=_lastState&&_lastState.tests||{};
    const rows=Object.entries(ts).filter(([,t])=>(t.attempts||0)>0).map(([n,t])=>{
      const ta=t.attempts||0,tf=t.fail||0,fp=ta?tf/ta*100:0;
      return{n,ta,tf,fp};
    }).filter(r=>r.tf>0).sort((a,b)=>b.fp-a.fp).slice(0,8);
    if(!rows.length){tfb.innerHTML='<div class="empty" style="color:var(--green)">&#10003; No failures</div>';return;}
    tfb.innerHTML='<table style="width:100%"><thead><tr><th>Suite</th><th class="r">Attempts</th><th class="r">Fails</th><th class="r">Fail%</th></tr></thead><tbody>'+
      rows.map(r=>{
        const c=r.fp>50?'var(--red)':r.fp>20?'var(--amber)':'var(--muted)';
        return`<tr class="mrow" style="cursor:pointer" onclick="openModal('${H(r.n)}','')"><td><span class="s-ico">${suiteIco(r.n)}</span>${H(r.n)}</td><td class="r">${N(r.ta)}</td><td class="r" style="color:var(--red)">${N(r.tf)}</td><td class="r"><span style="color:${c};font-weight:600">${r.fp.toFixed(1)}%</span></td></tr>`;
      }).join('')+'</tbody></table>';
  })();
  if(!$('drawer').classList.contains('open')){
    const sel=$('cfg-suite');
    if(sel.options.length<=1&&suites.length){suites.forEach(su=>{const o=document.createElement('option');o.value=su.name;o.textContent=su.name+' — '+su.description;sel.appendChild(o);});}
    sel.value=s.suite||'all';$('cfg-size').value=s.size||'S';$('cfg-wait').value=s.max_wait_secs||20;$('wait-val').textContent=(s.max_wait_secs||20)+'s';$('cfg-loop').checked=!!s.loop;
  }
  $('cur-cfg').innerHTML=`<span class="cfg-chip">suite:${H(s.suite||'—')}</span><span class="cfg-chip">size:${H(s.size||'—')}</span><span class="cfg-chip">wait:${s.max_wait_secs||20}s</span><span class="cfg-chip">${s.loop?'loop':'single'}</span>`;
  if($('tab-security').classList.contains('active'))updateSecurityTab();
}
function toggleRow(n){if(_xRows.has(n))_xRows.delete(n);else _xRows.add(n);if(_lastState)apply(_lastState);}
function toggleEv(i){if(_xEvs.has(i))_xEvs.delete(i);else _xEvs.add(i);if(_lastState)apply(_lastState);}
function connect(){
  const url='/events'+(_sessionId?'?sid='+encodeURIComponent(_sessionId):'');
  const es=new EventSource(url);
  let _roleChecked=false;
  es.onmessage=ev=>{
    try{apply(JSON.parse(ev.data))}catch(e){}
    if(!_roleChecked){_roleChecked=true;checkRole();}
  };
  es.onerror=()=>{_roleChecked=false;es.close();$('pill-live').className='tp-pill tp-paused';$('pill-live').innerHTML='⚠ RECONNECT';setTimeout(connect,3000);};
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
  document.querySelectorAll('#obody .ll').forEach(el=>{
    if(el.classList.contains('ll-sep')||el.classList.contains('rule')||el.classList.contains('banner'))return;
    el.style.display=(lvl==='all'||el.classList.contains(lvl))?'':'none';
  });
}
function appendLog(d){
  const b=$('obody'),lvl=d.level||'info';
  // rule and banner are always shown as structural context; others respect the filter
  const structural=lvl==='rule'||lvl==='banner';
  if(!structural&&_logFilter!=='all'&&lvl!==_logFilter)return;
  const test=d.test||'';
  if(test&&test!==_lastTest){
    _lastTest=test;
    const sep=document.createElement('div');sep.className='ll ll-sep';
    sep.innerHTML=`<div class="sep-line"></div><div class="sep-txt">${H(test)}</div><div class="sep-line"></div>`;
    b.appendChild(sep);
  }
  const div=document.createElement('div');
  const ts=Tc(d.t||Date.now()/1000);
  const msg=d.msg||'';
  if(lvl==='rule'){
    // Strip leading/trailing dash chars and whitespace to extract label
    const txt=msg.replace(/^[─━—\- ]+/,'').replace(/[─━—\- ]+$/,'').trim();
    div.className='ll ll-sep rule';
    div.innerHTML=`<div class="sep-line"></div>${txt?`<div class="sep-txt">${H(txt)}</div><div class="sep-line"></div>`:''}`;
  } else if(lvl==='banner'){
    div.className='ll banner';
    div.innerHTML=`<span class="llm">${H(msg)}</span>`;
  } else if(lvl==='summary'){
    div.className='ll summary';
    div.innerHTML=`<span class="llt">${ts}</span><span class="llm">${H(msg)}</span>`;
  } else {
    div.className='ll '+lvl;
    const icon=lvl==='ok'?'✔ ':lvl==='error'?'✗ ':lvl==='warn'?'⚠ ':'';
    div.innerHTML=`<span class="llt">${ts}</span><span class="llv">${H(lvl.toUpperCase().slice(0,5).padEnd(5))}</span><span class="llm">${icon?`<span style="opacity:.7">${icon}</span>`:''}${H(msg)}</span>`;
  }
  if(!structural&&_logFilter!=='all'&&!div.classList.contains(_logFilter))div.style.display='none';
  b.appendChild(div);
  if(_autoScroll)_scrollToBot();
  while(b.children.length>800)b.removeChild(b.firstChild);
}
function _scrollToBot(){
  const ob=$('obody');if(!ob)return;
  _scrollLock=true;
  ob.scrollTop=ob.scrollHeight;
  setTimeout(()=>{_scrollLock=false;},50);
}
// Self-healing: if auto-scroll is on but we drifted from the bottom, catch up
setInterval(()=>{
  if(!_autoScroll)return;
  const ob=$('obody');if(!ob)return;
  const gap=ob.scrollHeight-ob.scrollTop-ob.clientHeight;
  if(gap>120)_scrollToBot();
},2000);
function toggleAS(){_autoScroll=!_autoScroll;$('btn-as').innerHTML='Auto-scroll '+(_autoScroll?'&#10003;':'&#10007;');if(_autoScroll)_scrollToBot();}

// ── Draggable overview widgets ─────────────────────────────────────────────────
function _initDrag(gridId){
  const grid=$(gridId);if(!grid)return;
  let dragged=null;
  // Inject drag handles into the first .ctitle/.thdr/.ehdr found in each widget
  grid.querySelectorAll('[data-widget]').forEach(card=>{
    if(card.querySelector('.drag-handle'))return;
    const hdr=card.querySelector('.ctitle,.thdr,.ehdr,.clbl');
    const h=document.createElement('span');
    h.className='drag-handle';h.title='Drag to reorder';h.innerHTML='&#8942;&#8942;';
    h.setAttribute('draggable','false');
    if(hdr)hdr.prepend(h);else card.prepend(h);
    // mousedown on handle activates draggable on parent then drag fires naturally
    h.addEventListener('mousedown',()=>{card.setAttribute('draggable','true');});
    h.addEventListener('mouseup',()=>{card.removeAttribute('draggable');});
  });
  grid.querySelectorAll('[data-widget]').forEach(card=>{
    card.addEventListener('dragstart',e=>{if(!card.getAttribute('draggable'))return;dragged=card;setTimeout(()=>card.classList.add('dragging'),0);e.dataTransfer.effectAllowed='move';});
    card.addEventListener('dragend',()=>{card.removeAttribute('draggable');card.classList.remove('dragging');grid.querySelectorAll('[data-widget]').forEach(c=>c.classList.remove('drag-over'));_saveWidgetOrder(gridId);dragged=null;});
    card.addEventListener('dragover',e=>{e.preventDefault();if(card!==dragged)card.classList.add('drag-over');});
    card.addEventListener('dragleave',e=>{if(!card.contains(e.relatedTarget))card.classList.remove('drag-over');});
    card.addEventListener('drop',e=>{e.preventDefault();card.classList.remove('drag-over');if(dragged&&dragged!==card){const els=[...grid.querySelectorAll('[data-widget]')];const di=els.indexOf(dragged),ci=els.indexOf(card);if(di<ci)card.after(dragged);else card.before(dragged);}});
  });
  _restoreWidgetOrder(gridId);
}
function _saveWidgetOrder(gridId){
  const grid=$(gridId);if(!grid)return;
  const order=[...grid.querySelectorAll('[data-widget]')].map(c=>c.dataset.widget);
  try{localStorage.setItem('tg-widget-order-'+gridId,JSON.stringify(order));}catch(e){}
}
function _restoreWidgetOrder(gridId){
  const grid=$(gridId);if(!grid)return;
  let order;try{order=JSON.parse(localStorage.getItem('tg-widget-order-'+gridId)||'null');}catch(e){return;}
  if(!order||!order.length)return;
  order.forEach(id=>{const c=grid.querySelector('[data-widget="'+id+'"]');if(c)grid.appendChild(c);});
}
let _lateralNetsAvailable=[];
function _buildNetCheckboxes(containerId, noneId, nets, selectedSet){
  const list=$(containerId),none=$(noneId);
  list.innerHTML='';
  if(!nets.length){none.style.display='';return;}
  none.style.display='none';
  nets.forEach(net=>{
    const lbl=document.createElement('label');
    lbl.style.cssText='display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;padding:5px 8px;border-radius:6px;background:var(--surf2);border:1px solid var(--border)';
    const cb=document.createElement('input');
    cb.type='checkbox';cb.value=net.cidr;cb.checked=selectedSet.size===0||selectedSet.has(net.cidr);
    const txt=document.createElement('span');
    txt.innerHTML=`<span style="font-family:monospace;font-weight:600">${H(net.cidr)}</span><span style="color:var(--muted);font-size:11px;margin-left:4px">(${H(net.ip)})</span>`;
    lbl.appendChild(cb);lbl.appendChild(txt);list.appendChild(lbl);
  });
}
function _loadDrawerNetworks(){
  fetch('/api/networks').then(r=>r.json()).then(d=>{
    _lateralNetsAvailable=d.available||[];
    const selected=new Set(d.selected||[]);
    _buildNetCheckboxes('lateral-nets-list','lateral-nets-none',_lateralNetsAvailable,selected);
  }).catch(()=>{});
}
function onSuiteChange(val){
  const sec=$('lateral-nets-section');
  if(val==='lateral-movement'){
    sec.style.display='';
    _loadDrawerNetworks();
  }else{
    sec.style.display='none';
  }
}
function openDrawer(){
  $('drawer').classList.add('open');$('overlay').classList.add('open');
  onSuiteChange($('cfg-suite').value);
}
function closeDrawer(){$('drawer').classList.remove('open');$('overlay').classList.remove('open');}
function toast(msg,ok){const t=$('toast');t.textContent=msg;t.className='toast '+(ok?'ok':'err');t.style.display='block';setTimeout(()=>t.style.display='none',3500);}
function applySettings(){
  if(!_isAdmin){toast(_sessionMode?'Another session has control — you are read-only':'Admin access required — click Unlock',false);return;}
  const body={suite:$('cfg-suite').value,size:$('cfg-size').value,max_wait_secs:parseInt($('cfg-wait').value),loop:$('cfg-loop').checked,nowait:$('cfg-nowait').checked};
  if(_lateralNetsAvailable.length){
    const checked=[...document.querySelectorAll('#lateral-nets-list input[type=checkbox]:checked')].map(c=>c.value);
    body.lateral_networks=(checked.length===_lateralNetsAvailable.length)?[]:checked;
  }else{
    body.lateral_networks=[];
  }
  _ctrl(body).then(r=>r.json()).then(d=>{if(d.ok){toast('Settings applied — restarting at next boundary…',true);closeDrawer();}else toast('Error: '+d.error,false);})
    .catch(()=>toast('Request failed',false));
}
function togglePause(){
  if(!_isAdmin){toast(_sessionMode?'Another session has control — you are read-only':'Admin access required — click Unlock',false);return;}
  const action=_isPaused?'resume':'pause';
  _ctrl({action}).then(r=>r.json()).then(d=>{if(d.ok)toast(action==='pause'?'Tests paused — will stop after current test':'Tests resuming…',true);else toast('Error: '+d.error,false);})
    .catch(()=>toast('Request failed',false));
}
function stopTests(){
  if(!_isAdmin){toast(_sessionMode?'Another session has control — you are read-only':'Admin access required — click Unlock',false);return;}
  if(!confirm('Stop all tests? Use Settings ⚙ to restart with new parameters, or click Restart Tests when stopped.'))return;
  _ctrl({action:'stop'}).then(r=>r.json()).then(d=>{if(d.ok)toast('Stop signal sent — tests will halt after current test',true);else toast('Error: '+d.error,false);})
    .catch(()=>toast('Request failed',false));
}
function restartTests(){
  if(!_isAdmin){toast(_sessionMode?'Another session has control — you are read-only':'Admin access required — click Unlock',false);return;}
  const st=_lastState||{};
  const body={suite:st.suite||'all',size:st.size||'S',max_wait_secs:st.max_wait_secs||20,loop:st.loop!==false,nowait:false};
  _ctrl(body).then(r=>r.json()).then(d=>{if(d.ok)toast('Restarting tests…',true);else toast('Error: '+d.error,false);})
    .catch(()=>toast('Request failed',false));
}
function handleLiveClick(){if(_lastState&&_lastState.status==='stopped'){restartTests();return;}stopTests();}
let _modalLateralNets=[];
function openModal(name,desc){
  _modalSuite=name;$('modal-name').textContent=name;$('modal-desc').textContent=desc||'No description available.';
  const td=(_lastState&&_lastState.tests&&_lastState.tests[name])||{};
  const ta=td.attempts||0,tok=td.ok||0,tf=td.fail||0;
  $('ms-att').textContent=ta?N(ta):'—';$('ms-ok').textContent=tok?N(tok):'—';$('ms-fail').textContent=tf?N(tf):'—';
  if(_lastState){$('modal-size').value=_lastState.size||'S';$('modal-wait').value=_lastState.max_wait_secs||20;$('modal-wv').textContent=($('modal-wait').value)+'s';$('modal-loop').checked=!!_lastState.loop;}
  const latSec=$('modal-lateral-section');
  if(name==='lateral-movement'){
    latSec.style.display='';
    fetch('/api/networks').then(r=>r.json()).then(d=>{
      _modalLateralNets=d.available||[];
      const selected=new Set(d.selected||[]);
      _buildNetCheckboxes('modal-lateral-list','modal-lateral-none',_modalLateralNets,selected);
    }).catch(()=>{});
  }else{
    latSec.style.display='none';
    _modalLateralNets=[];
  }
  $('modal-ov').classList.add('open');
}
function closeModal(){$('modal-ov').classList.remove('open');_modalSuite=null;}
function runFromModal(){
  if(!_modalSuite)return;
  if(!_isAdmin){toast(_sessionMode?'Another session has control — you are read-only':'Admin access required — click Unlock',false);return;}
  const body={suite:_modalSuite,size:$('modal-size').value,max_wait_secs:parseInt($('modal-wait').value),loop:$('modal-loop').checked,nowait:false};
  if(_modalSuite==='lateral-movement'&&_modalLateralNets.length){
    const checked=[...document.querySelectorAll('#modal-lateral-list input[type=checkbox]:checked')].map(c=>c.value);
    body.lateral_networks=(checked.length===_modalLateralNets.length)?[]:checked;
  }else{
    body.lateral_networks=[];
  }
  _ctrl(body).then(r=>r.json()).then(d=>{if(d.ok){toast('Running '+_modalSuite+' — generator restarting…',true);closeModal();navTo('output');}else toast('Error: '+d.error,false);})
    .catch(()=>toast('Request failed',false));
}
// ── Health / perf functions ────────────────────────────────────────────────────
function fmtIO(v){const m=v*8/1000;if(m<0.01)return'<0.01 Mbps';if(m<10)return m.toFixed(2)+' Mbps';return m.toFixed(1)+' Mbps';}
function gaugeColor(p){return p>85?'var(--red)':p>65?'var(--amber)':'var(--green)';}
function gaugeHex(p){return p>85?'#f85149':p>65?'#f59e0b':'#22c55e';}
function drawLineSpark(cid,vals,color){
  const c=$(cid);if(!c)return;
  const rect=c.getBoundingClientRect();
  c.width=Math.floor(rect.width)||300;c.height=Math.floor(rect.height)||44;
  const ctx=c.getContext('2d'),W=c.width,H2=c.height,P={t:4,r:4,b:4,l:4};
  ctx.clearRect(0,0,W,H2);
  if(!vals||vals.length<2){ctx.fillStyle=_canvasMuted();ctx.font='12px system-ui';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText('Accumulating…',W/2,H2/2);return;}
  const mx=Math.max(...vals,1),IW=W-P.l-P.r,IH=H2-P.t-P.b;
  const xOf=i=>P.l+(i/(vals.length-1))*IW,yOf=v=>P.t+IH-(v/100)*IH;
  // Filled area
  const grad=ctx.createLinearGradient(0,P.t,0,P.t+IH);
  grad.addColorStop(0,color+'55');grad.addColorStop(1,color+'08');
  ctx.beginPath();ctx.moveTo(xOf(0),yOf(vals[0]));
  vals.forEach((v,i)=>{if(i)ctx.lineTo(xOf(i),yOf(v));});
  ctx.lineTo(xOf(vals.length-1),H2-P.b);ctx.lineTo(xOf(0),H2-P.b);ctx.closePath();
  ctx.fillStyle=grad;ctx.fill();
  // Line
  ctx.beginPath();ctx.moveTo(xOf(0),yOf(vals[0]));
  vals.forEach((v,i)=>{if(i)ctx.lineTo(xOf(i),yOf(v));});
  ctx.strokeStyle=color;ctx.lineWidth=1.5;ctx.lineJoin='round';ctx.stroke();
}
function drawGauge(cid,pct,label,color){
  const c=$(cid),ctx=c.getContext('2d'),W=c.width,H2=c.height,cx=W/2,cy=H2*0.72;
  const r=Math.min(W,H2)*0.4,sa=0.75*Math.PI,span=1.5*Math.PI;
  ctx.clearRect(0,0,W,H2);
  ctx.beginPath();ctx.arc(cx,cy,r,sa,sa+span);ctx.strokeStyle='#1e2d3d';ctx.lineWidth=10;ctx.lineCap='round';ctx.stroke();
  const va=sa+(Math.max(0,Math.min(100,pct))/100)*span;
  if(pct>0){ctx.beginPath();ctx.arc(cx,cy,r,sa,va);ctx.strokeStyle=color;ctx.lineWidth=10;ctx.lineCap='round';ctx.stroke();}
  ctx.fillStyle=_canvasText();ctx.font='bold 22px SF Mono,Consolas,monospace';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(pct.toFixed(1)+'%',cx,cy-6);
  ctx.fillStyle=_canvasMuted();ctx.font='12px system-ui';ctx.fillText(label,cx,cy+10);
}
function drawDiskBars(r,w){
  const c=$('disk-bars'),rect=c.getBoundingClientRect();
  c.width=Math.floor(rect.width)||300;c.height=58;
  const ctx=c.getContext('2d'),W=c.width,bh=16,lw=48,gy=6;
  ctx.clearRect(0,0,W,58);
  _diskPeakHist.push(Math.max(r,w));if(_diskPeakHist.length>60)_diskPeakHist.shift();
  const mx=Math.max(..._diskPeakHist,500);
  const drawBar=(y,v,col,lbl)=>{
    ctx.fillStyle=_canvasMuted();ctx.font='12px SF Mono,Consolas,monospace';ctx.textAlign='right';ctx.textBaseline='middle';ctx.fillText(lbl,lw-4,y+bh/2);
    ctx.fillStyle=_canvasBg();ctx.fillRect(lw,y,W-lw-gy,bh);
    const bw=Math.max(2,(v/mx)*(W-lw-gy));
    ctx.fillStyle=col;ctx.fillRect(lw,y,bw,bh);
    ctx.fillStyle=_canvasText();ctx.textAlign='left';ctx.font='12px SF Mono,Consolas,monospace';ctx.fillText(fmtIO(v),lw+bw+4,y+bh/2);
  };
  drawBar(4,r,'#22c55e','Read');drawBar(34,w,'#58a6ff','Write');
}
function drawNetSpark(cid,hist,rxColor,txColor){
  const c=$(cid),rect=c.getBoundingClientRect();
  c.width=Math.floor(rect.width)||400;c.height=Math.floor(rect.height)||60;
  const ctx=c.getContext('2d'),W=c.width,H2=c.height,P={t:4,r:6,b:16,l:10};
  const IW=W-P.l-P.r,IH=H2-P.t-P.b;
  ctx.clearRect(0,0,W,H2);
  if(!hist||hist.length<2){ctx.fillStyle=_canvasMuted();ctx.font='12px system-ui';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText('Accumulating…',W/2,H2/2);return;}
  const mx=Math.max(...hist.map(p=>Math.max(p.rx||0,p.tx||0)),1);
  const xOf=i=>P.l+(i/(hist.length-1))*IW,yOf=v=>P.t+IH-(v/mx)*IH;
  const drawLine=(key,col)=>{
    ctx.beginPath();hist.forEach((p,i)=>{const x=xOf(i),y=yOf(p[key]||0);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});
    ctx.strokeStyle=col;ctx.lineWidth=1.5;ctx.lineJoin='round';ctx.stroke();
  };
  drawLine('rx','#22c55e');drawLine('tx','#58a6ff');
  ctx.fillStyle=_canvasMuted();ctx.font='12px SF Mono,Consolas,monospace';ctx.textAlign='left';ctx.fillText(fmtIO(hist[hist.length-1].rx||0)+' rx',P.l,H2-3);
  ctx.textAlign='right';ctx.fillText(fmtIO(hist[hist.length-1].tx||0)+' tx',P.l+IW,H2-3);
}
function fmtUptime(s){const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60);return(d?d+'d ':'')+h+'h '+m+'m';}
function fmtMB(v){return v>=1024?(v/1024).toFixed(2)+' GB':v.toFixed(0)+' MB';}
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
  const cpuPct=d.cpu_pct||0,memPct=d.mem_pct||0;
  drawGauge('cpu-gauge',cpuPct,'CPU',gaugeColor(cpuPct));
  drawGauge('mem-gauge',memPct,'Memory',gaugeColor(memPct));
  _cpuHist.push(cpuPct);if(_cpuHist.length>60)_cpuHist.shift();
  _memHist.push(memPct);if(_memHist.length>60)_memHist.shift();
  drawLineSpark('cpu-spark',_cpuHist,gaugeHex(cpuPct));
  drawLineSpark('mem-spark',_memHist,gaugeHex(memPct));
  if($('cpu-cur'))$('cpu-cur').textContent=cpuPct.toFixed(1)+'%';
  if($('mem-cur'))$('mem-cur').textContent=memPct.toFixed(1)+'%';
  if($('mem-detail'))$('mem-detail').textContent=(d.mem_used_mb||0).toFixed(0)+' MB / '+(d.mem_total_mb||0).toFixed(0)+' MB used';
  // Stacked memory bar: used(red)|buffers(blue)|cached(amber)|free(dim)
  (function(){
    const bar=$('mem-stacked-bar'),leg=$('mem-stacked-legend');
    if(!bar)return;
    const tot=d.mem_total_mb||1;
    const used=d.mem_used_mb||0,buf=d.mem_buffers_mb||0,cach=d.mem_cached_mb||0,free=d.mem_free_mb||0;
    const segs=[['Used','var(--red)',used],['Buffers','#58a6ff',buf],['Cached','var(--amber)',cach],['Free','#374151',Math.max(0,tot-used-buf-cach)]];
    bar.innerHTML=segs.map(([,col,v])=>`<div style="flex:${v/tot};background:${col};height:100%"></div>`).join('');
    if(leg)leg.innerHTML=segs.map(([lbl,col,v])=>`<span style="display:flex;align-items:center;gap:3px"><span style="width:8px;height:8px;border-radius:50%;background:${col};display:inline-block"></span>${lbl}: ${fmtMB(v)}</span>`).join('');
  })();
  // Per-core CPU bars
  (function(){
    const cb=$('cpu-cores-body');if(!cb)return;
    const cores=d.cpu_cores||[];
    if(!cores.length){cb.innerHTML='<div class="empty" style="font-size:12px">Single core or data pending</div>';return;}
    cb.innerHTML=cores.map(c=>{
      const col=gaugeHex(c.total);
      return`<div style="background:#151b27;border-radius:8px;padding:8px 10px">`+
        `<div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px"><span style="color:var(--muted)">Core ${c.idx}</span><span style="color:${col};font-weight:600">${c.total.toFixed(1)}%</span></div>`+
        `<div style="background:#1e2d3d;border-radius:3px;height:6px;overflow:hidden;display:flex">`+
        `<div style="flex:${c.user};background:#22c55e"></div>`+
        `<div style="flex:${c.sys};background:var(--amber)"></div>`+
        `<div style="flex:${Math.max(0,100-c.user-c.sys)};background:transparent"></div>`+
        `</div>`+
        `<div style="display:flex;gap:8px;margin-top:3px;font-size:10px;color:var(--dim)">`+
        `<span style="color:#22c55e">usr ${c.user.toFixed(0)}%</span>`+
        `<span style="color:var(--amber)">sys ${c.sys.toFixed(0)}%</span>`+
        `</div></div>`;
    }).join('');
  })();
  const la=d.load_avg||[0,0,0];
  if($('h-load'))$('h-load').textContent=la.map(v=>v.toFixed(2)).join('  \xb7  ');
  if($('ov-cpu'))$('ov-cpu').textContent=cpuPct.toFixed(1)+'%';
  if($('ov-mem'))$('ov-mem').textContent=memPct.toFixed(1)+'%';
  if($('ov-load'))$('ov-load').textContent=la.map(v=>v.toFixed(2)).join('  \xb7  ');
  if($('disk-read'))$('disk-read').textContent=fmtIO(d.disk_read_kbps||0);
  if($('disk-write'))$('disk-write').textContent=fmtIO(d.disk_write_kbps||0);
  drawDiskBars(d.disk_read_kbps||0,d.disk_write_kbps||0);
  if($('h-rx'))$('h-rx').textContent=fmtIO(rx);
  if($('h-tx'))$('h-tx').textContent=fmtIO(tx);
  _hNetHist.push({rx,tx,t:Date.now()/1000});if(_hNetHist.length>60)_hNetHist.shift();
  drawNetSpark('h-net-spark',_hNetHist,'#22c55e','#58a6ff');
  if($('cum-rx'))$('cum-rx').textContent=fmtMB(d.net_rx_total_mb||0);
  if($('cum-tx'))$('cum-tx').textContent=fmtMB(d.net_tx_total_mb||0);
  if($('cum-drd'))$('cum-drd').textContent=fmtMB(d.disk_rd_total_mb||0);
  if($('cum-dwr'))$('cum-dwr').textContent=fmtMB(d.disk_wr_total_mb||0);
  // Swap
  const swapPct=d.swap_pct||0;
  if($('swap-detail'))$('swap-detail').textContent=(d.swap_used_mb||0).toFixed(0)+' MB / '+(d.swap_total_mb||0).toFixed(0)+' MB used';
  if($('swap-bar'))$('swap-bar').style.width=Math.min(100,swapPct)+'%';
  if($('swap-pct'))$('swap-pct').textContent=swapPct.toFixed(1)+'%';
  // System uptime + process internals
  if($('sys-uptime'))$('sys-uptime').textContent=fmtUptime(d.uptime_secs||0);
  if($('h-threads'))$('h-threads').textContent=d.thread_count||'—';
  if($('h-fds')){
    const fdCount=d.fd_count||0,fdLimit=d.fd_limit||0;
    const fdPct=fdLimit?fdCount/fdLimit*100:0;
    const fdC=fdPct>90?'var(--red)':fdPct>70?'var(--amber)':'var(--text)';
    $('h-fds').textContent=fdCount;
    $('h-fds').style.color=fdC;
    if($('h-fds-limit'))$('h-fds-limit').textContent=fdLimit?' / '+fdLimit+' ('+(fdPct.toFixed(0))+'%)':'';
  }
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
function setNetInterval(ms){
  _netInterval=ms||1000;
  clearInterval(_netTimer);
  _netTimer=setInterval(pollHealth,_netInterval);
}
// Kick off overview network widget immediately and keep it live at 1s default
pollHealth();
_netTimer=setInterval(pollHealth,_netInterval);
// ── Network info widget ───────────────────────────────────────────────────────
function applyNetInfo(d){
  if(!d)return;
  if($('h-pub-ip'))$('h-pub-ip').textContent=d.public_ip||'—';
  if($('h-lan-ip')){const lip=d.host_lan_ip||'';$('h-lan-ip').textContent=lip||'—';if($('h-lan-ip-wrap'))$('h-lan-ip-wrap').style.display=lip?'':'none';}
  const tbip=$('tb-host-ip');if(tbip){const lip=d.host_lan_ip||'';tbip.textContent=lip;tbip.style.display=lip?'':'none';}
  const tb=$('netinfo-body');if(!tb)return;
  const ifaces=d.interfaces||[];
  if(!ifaces.length){tb.innerHTML='<tr><td colspan="6" class="empty">No interfaces</td></tr>';return;}
  tb.innerHTML=ifaces.map(i=>{
    const linkC=i.link==='up'?'var(--green)':i.link==='down'?'var(--red)':'var(--muted)';
    const ipStr=i.ip||'<span style="color:var(--muted)">—</span>';
    const macStr=i.mac||'<span style="color:var(--muted)">—</span>';
    return`<tr class="mrow"><td class="nm">${H(i.name)}</td><td style="font-family:'SF Mono',Consolas,monospace;font-size:14px">${ipStr}</td><td style="font-family:'SF Mono',Consolas,monospace;font-size:14px">${macStr}</td><td class="r" style="color:var(--muted)">${H(i.speed||'—')}</td><td class="r" style="color:var(--muted)">${i.mtu||'—'}</td><td class="r"><span style="color:${linkC}">${H(i.link||'—')}</span></td></tr>`;
  }).join('');
}
function pollNetInfo(){
  fetch('/api/netinfo')
    .then(r=>{if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})
    .then(d=>{
      applyNetInfo(d);
      if(!d.interfaces||!d.interfaces.length){setTimeout(pollNetInfo,3000);}
    })
    .catch(e=>{const tb=$('netinfo-body');if(tb)tb.innerHTML='<tr><td colspan="6" class="empty" style="color:var(--red)">Error: '+String(e)+'</td></tr>';setTimeout(pollNetInfo,5000);});
}
pollNetInfo();
setInterval(pollNetInfo,30000);
// ── Security Summary ──────────────────────────────────────────────────────────
let _secTimer=null,_secInterval=1000,_secHist=[];
let _diskPeakHist=[];
function drawSecDonut(allowed,blocked,dropped,other){
  const c=$('sec-donut');if(!c)return;
  const ctx=c.getContext('2d'),W=c.width,H2=c.height,cx=W/2,cy=H2/2,r=66,ri=46;
  const tot=allowed+blocked+dropped+other;
  ctx.clearRect(0,0,W,H2);
  if(!tot){ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.arc(cx,cy,ri,0,Math.PI*2,true);ctx.fillStyle=_canvasBg();ctx.fill('evenodd');ctx.fillStyle=_canvasMuted();ctx.font='13px system-ui';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText('No data',cx,cy);return;}
  const slices=[{v:allowed,c:'#22c55e'},{v:blocked,c:'#f59e0b'},{v:dropped,c:'#818cf8'},{v:other,c:'#475569'}];
  let angle=-Math.PI/2;
  slices.forEach(sl=>{if(!sl.v)return;const a=(sl.v/tot)*Math.PI*2;ctx.beginPath();ctx.arc(cx,cy,r,angle,angle+a);ctx.arc(cx,cy,ri,angle+a,angle,true);ctx.fillStyle=sl.c;ctx.fill();angle+=a;});
  const bpct=tot?(blocked/tot*100).toFixed(1)+'%':'—';
  ctx.fillStyle=_canvasText();ctx.font='bold 18px SF Mono,Consolas,monospace';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(bpct,cx,cy-7);
  ctx.fillStyle=_canvasMuted();ctx.font='12px system-ui';ctx.fillText('blocked',cx,cy+8);
}
function drawSecTrend(hist){
  const c=$('sec-trend');if(!c)return;
  const rect=c.getBoundingClientRect();c.width=Math.floor(rect.width)||500;c.height=Math.floor(rect.height)||160;
  const ctx=c.getContext('2d'),W=c.width,H2=c.height,P={t:10,r:10,b:22,l:36},IW=W-P.l-P.r,IH=H2-P.t-P.b;
  ctx.clearRect(0,0,W,H2);
  if(!hist||hist.length<2){ctx.fillStyle=_canvasMuted();ctx.font='13px system-ui';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText('Accumulating data…',W/2,H2/2);return;}
  const mx=100;
  const xOf=i=>P.l+(i/(hist.length-1))*IW,yOf=v=>P.t+IH-(Math.max(0,Math.min(100,v))/mx)*IH;
  ctx.strokeStyle='#1e2d3d';ctx.lineWidth=1;
  for(let i=0;i<=4;i++){const y=P.t+(i/4)*IH;ctx.beginPath();ctx.moveTo(P.l,y);ctx.lineTo(P.l+IW,y);ctx.stroke();ctx.fillStyle=_canvasMuted();ctx.font='12px SF Mono,Consolas,monospace';ctx.textAlign='right';ctx.fillText(Math.round(100*(1-i/4))+'%',P.l-4,y+3);}
  const drawLine=(key,col,dash)=>{if(dash)ctx.setLineDash(dash);else ctx.setLineDash([]);ctx.beginPath();hist.forEach((p,i)=>{const x=xOf(i),y=yOf(p[key]||0);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});ctx.strokeStyle=col;ctx.lineWidth=2;ctx.lineJoin='round';ctx.stroke();ctx.setLineDash([]);};
  drawLine('block_pct','#f59e0b');
  drawLine('drop_pct','#818cf8',[4,3]);
  ctx.fillStyle=_canvasMuted();ctx.font='12px SF Mono,Consolas,monospace';ctx.textAlign='left';ctx.fillText(Ts(hist[0].t),P.l,H2-3);ctx.textAlign='right';ctx.fillText(Ts(hist[hist.length-1].t),P.l+IW,H2-3);
}
function updateSecurityTab(){
  if(!_lastState)return;
  const tests=_lastState.tests||{};
  const tot=_lastState.totals||{};
  const blk=tot.blocked||0,drp=tot.dropped||0,rch=tot.allowed||0;
  const totalProbes=rch+blk+drp;
  const other=Math.max(0,(tot.attempts||0)-totalProbes);
  const pct=(n,d)=>d?((n/d)*100).toFixed(1)+'%':'—';
  $('sec-total').textContent=N(totalProbes);$('sec-total-sub').textContent=totalProbes?'total probes':'No data yet';
  $('sec-blocked').textContent=N(blk);$('sec-blocked-sub').textContent=totalProbes?pct(blk,totalProbes)+' of probes':'—';
  $('sec-dropped').textContent=N(drp);$('sec-dropped-sub').textContent=totalProbes?pct(drp,totalProbes)+' of probes':'—';
  $('sec-allowed').textContent=N(rch);$('sec-allowed-sub').textContent=totalProbes?pct(rch,totalProbes)+' of probes':'—';
  $('sec-leg-allowed').textContent=N(rch)+' Allowed';
  $('sec-leg-blocked').textContent=N(blk)+' Blocked';
  $('sec-leg-dropped').textContent=N(drp)+' Dropped';
  $('sec-leg-other').textContent=N(other)+' Other';
  drawSecDonut(rch,blk,drp,other);
  // snapshot for trend (rate-limited to configured interval)
  const now=Date.now()/1000;
  if(!_secHist.length||now-_secHist[_secHist.length-1].t>=(_secInterval/1000)-1){
    _secHist.push({t:now,block_pct:totalProbes?blk/totalProbes*100:0,drop_pct:totalProbes?drp/totalProbes*100:0,reach_pct:totalProbes?rch/totalProbes*100:0});
    if(_secHist.length>120)_secHist.shift();
  }
  drawSecTrend(_secHist);
  // per-suite table — sort by blocked desc
  const rows=Object.entries(tests).map(([n,t])=>({n,ta:t.attempts||0,rch:t.allowed||0,blk:t.blocked||0,drp:t.dropped||0,tot:(t.allowed||0)+(t.blocked||0)+(t.dropped||0)}));
  rows.sort((a,b)=>b.blk-a.blk||(b.drp-a.drp));
  const tb=$('sec-tbl');
  if(!rows.length){tb.innerHTML='<tr><td colspan="7" class="empty">Waiting…</td></tr>';}
  else tb.innerHTML=rows.map(r=>{
    const bp=r.tot?r.blk/r.tot*100:0,dp=r.tot?r.drp/r.tot*100:0;
    const bpC=bp>50?'var(--red)':bp>10?'var(--amber)':'var(--muted)';
    const dpC=dp>50?'var(--red)':dp>10?'#818cf8':'var(--muted)';
    return`<tr class="mrow"><td class="nm" title="${_SD[r.n]||''}" style="cursor:default"><span class="s-ico">${suiteIco(r.n)}</span>${H(r.n)}</td><td class="r">${N(r.tot)}</td><td class="r" style="color:#22c55e">${N(r.rch)}</td><td class="r" style="color:var(--amber)">${N(r.blk)}</td><td class="r" style="color:#818cf8">${N(r.drp)}</td><td class="r"><span style="color:${bpC}">${r.tot?bp.toFixed(1)+'%':'—'}</span></td><td class="r"><span style="color:${dpC}">${r.tot?dp.toFixed(1)+'%':'—'}</span></td></tr>`;
  }).join('');
  // block signal breakdown — aggregate codes across filtered tests
  const codeTotals={};
  Object.values(tests).forEach(t=>{Object.entries(t.codes||{}).forEach(([k,v])=>{codeTotals[k]=(codeTotals[k]||0)+v;});});
  // also add pseudo-codes for TCP-level blocks (exit codes stored as exitN)
  const signalDefs={
    '4xx':'HTTP 4xx','exit7':'TCP RST (firewall block)','exit5':'Proxy refused',
    'exit35':'TLS intercept','exit97':'SOCKS refused','exit6':'DNS sinkhole',
    'exit28':'Timeout (silent drop)','2xx':'HTTP 2xx (allowed)','3xx':'HTTP 3xx (redirect)',
    '5xx':'HTTP 5xx (server error)',
  };
  const sigEl=$('sec-signals');
  const entries=Object.entries(codeTotals).filter(([,v])=>v>0).sort((a,b)=>b[1]-a[1]);
  if(!entries.length){sigEl.innerHTML='<div class="empty">No data yet</div>';return;}
  const blockCodes=new Set(['4xx','exit7','exit5','exit35','exit97']);
  const dropCodes=new Set(['exit6','exit28']);
  sigEl.innerHTML=entries.map(([k,v])=>{
    const lbl=signalDefs[k]||k;
    const col=blockCodes.has(k)?'var(--amber)':dropCodes.has(k)?'#818cf8':k.startsWith('2')?'#22c55e':'var(--muted)';
    return`<div class="sec-sig"><div class="sec-sig-val" style="color:${col}">${N(v)}</div><div class="sec-sig-lbl">${H(lbl)}</div></div>`;
  }).join('');
}
function setSecInterval(ms){
  _secInterval=ms||60000;
  clearInterval(_secTimer);
  if($('tab-security').classList.contains('active'))_secTimer=setInterval(updateSecurityTab,_secInterval);
}
function toggleTheme(){
  const on=document.documentElement.classList.toggle('light');
  $('btn-theme').innerHTML=on?'&#9788;':'&#9790;';
  try{localStorage.setItem('tg-theme',on?'light':'dark');}catch(e){}
}
// Restore saved theme preference
try{if(localStorage.getItem('tg-theme')==='light'){document.documentElement.classList.add('light');$('btn-theme').innerHTML='&#9788;';}}catch(e){}
// ── Traceroute visualizer ──────────────────────────────────────────────────
let _trSrc=null;
function _trColor(ms){
  if(ms===null)return'var(--muted)';
  if(ms<10)return'#22c55e';
  if(ms<50)return'#06b6d4';
  if(ms<100)return'#f59e0b';
  if(ms<200)return'#f97316';
  return'#ef4444';
}
function _trBarW(ms){return ms===null?0:Math.min(100,ms/300*100);}
function renderHop(hop){
  const res=$('tr-results');
  if(res.querySelector('.tr-status'))res.innerHTML='';
  const avg=hop.avg_rtt,col=_trColor(avg);
  const ipLbl=hop.timeout?'* timeout':(hop.ip||'—');
  const rttLbl=hop.timeout?'*':avg!==null?avg.toFixed(1)+' ms':'—';
  const row=document.createElement('div');
  row.className='tr-hop';
  row.innerHTML=`<span class="tr-hop-num">${hop.hop}</span><span class="tr-hop-ip${hop.timeout?' timeout':''}" title="${H(hop.ip||'')}">${H(ipLbl)}</span><span class="tr-hop-rtt" style="color:${col}">${H(rttLbl)}</span><div class="tr-bar-wrap"><div class="tr-bar-fill" style="width:${_trBarW(avg)}%;background:${col}"></div></div>`;
  res.appendChild(row);
}
function runTrace(){
  const t=$('tr-target').value.trim();
  if(!t)return;
  const proto=$('tr-proto').value,port=$('tr-port').value||'443';
  stopTrace();
  $('tr-results').innerHTML='<div class="tr-status">Tracing '+H(t)+' via '+proto.toUpperCase()+'…</div>';
  $('tr-btn').disabled=true;$('tr-stop').style.display='';
  _trSrc=new EventSource('/api/traceroute?target='+encodeURIComponent(t)+'&proto='+proto+'&port='+encodeURIComponent(port));
  _trSrc.onmessage=e=>{
    const d=JSON.parse(e.data);
    if(d.header){
      const hdr=document.createElement('div');hdr.className='tr-header';hdr.textContent=d.header;
      $('tr-results').innerHTML='';$('tr-results').appendChild(hdr);
    }else if(d.hop){renderHop(d.hop);}
    else if(d.done||d.error){
      if(d.error){const el=document.createElement('div');el.className='tr-error';el.textContent=d.error;$('tr-results').appendChild(el);}
      _trSrc.close();_trSrc=null;$('tr-btn').disabled=false;$('tr-stop').style.display='none';
    }
  };
  _trSrc.onerror=()=>{stopTrace();};
}
function stopTrace(){
  if(_trSrc){_trSrc.close();_trSrc=null;}
  $('tr-btn').disabled=false;$('tr-stop').style.display='none';
}
function trProtoChange(){
  const p=$('tr-proto').value;
  $('tr-port').style.display=p==='tcp'?'':' none';
}
// ── Security export ───────────────────────────────────────────────────────
function exportSec(fmt){
  if(!_lastState)return;
  const tests=_lastState.tests||{};
  const rows=Object.entries(tests).map(([n,t])=>{
    const rch=t.allowed||0,blk=t.blocked||0,drp=t.dropped||0,tot=rch+blk+drp;
    return{suite:n,probes:tot,allowed:rch,blocked:blk,dropped:drp,
           block_pct:tot?+(blk/tot*100).toFixed(1):0,drop_pct:tot?+(drp/tot*100).toFixed(1):0};
  }).sort((a,b)=>b.blocked-a.blocked);
  const date=new Date().toISOString().slice(0,10);
  let blob,name;
  if(fmt==='csv'){
    const hdr='suite,probes,allowed,blocked,dropped,block_pct,drop_pct\n';
    const body=rows.map(r=>[r.suite,r.probes,r.allowed,r.blocked,r.dropped,r.block_pct,r.drop_pct].join(',')).join('\n');
    blob=new Blob([hdr+body],{type:'text/csv'});name='traffgen-security-'+date+'.csv';
  }else{
    blob=new Blob([JSON.stringify({date,rows},null,2)],{type:'application/json'});name='traffgen-security-'+date+'.json';
  }
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();URL.revokeObjectURL(a.href);
}
// ── Keyboard shortcuts ────────────────────────────────────────────────────
(function(){
  const _TAB_KEYS={'1':'overview','2':'security','3':'tests','4':'output','5':'health','6':'about','7':'changelog'};
  document.addEventListener('keydown',function(e){
    if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA'||e.target.tagName==='SELECT'||e.target.isContentEditable)return;
    if(e.metaKey||e.ctrlKey||e.altKey)return;
    const k=e.key;
    if(_TAB_KEYS[k]){e.preventDefault();navTo(_TAB_KEYS[k]);return;}
    if(k==='r'||k==='R'){const btn=$('btn-restart');if(btn&&btn.style.display!=='none'&&!btn.disabled){btn.click();}return;}
    if(k==='p'||k==='P'){const btn=$('btn-pause');if(btn&&btn.style.display!=='none'){btn.click();}return;}
    if(k==='Escape'){if($('drawer').classList.contains('open')){closeDrawer();}const m=$('suite-modal');if(m&&m.style.display!=='none'){closeModal&&closeModal();}return;}
    if(k==='?'){showKbHelp();return;}
  });
  const _KBH_HTML='<div id="kb-overlay" onclick="if(event.target.id===\'kb-overlay\')this.remove()" style="position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:10000;display:flex;align-items:center;justify-content:center"><div style="background:#1a1f2e;border:1px solid rgba(255,255,255,.12);border-radius:14px;padding:24px 32px;min-width:340px;max-width:480px"><div style="font-weight:700;font-size:16px;color:#e8eaf0;margin-bottom:16px">Keyboard Shortcuts</div><table style="width:100%;border-collapse:collapse;font-size:14px">'+
    [['1–7','Navigate tabs'],['R','Restart tests'],['P','Pause / Resume'],['Esc','Close modal / drawer'],['?','This help']]
    .map(([k,v])=>'<tr><td style="padding:5px 16px 5px 0;font-family:SF Mono,Consolas,monospace;color:#22c55e;white-space:nowrap">'+k+'</td><td style="padding:5px 0;color:#9aa3b8">'+v+'</td></tr>').join('')+
    '</table><button onclick="document.getElementById(\'kb-overlay\').remove()" style="margin-top:16px;padding:6px 18px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12);border-radius:8px;color:#e8eaf0;cursor:pointer;font-size:13px">Close</button></div></div>';
  window.showKbHelp=function(){if(!$('kb-overlay')){document.body.insertAdjacentHTML('beforeend',_KBH_HTML);}};
})();
// ── URL fragment routing ─────────────────────────────────────────────────
(function(){
  const _TABS=['overview','security','tests','output','diagnostics','health','about','changelog'];
  function _fragTab(){
    const h=location.hash.slice(1).split('/')[0];
    return _TABS.includes(h)?h:null;
  }
  const init=_fragTab();
  if(init){setTimeout(()=>navTo(init),0);}
  const _origShowTab=window.showTab;
  window.showTab=function(btn){
    _origShowTab(btn);
    if(btn.dataset&&btn.dataset.tab)history.replaceState(null,'','#'+btn.dataset.tab);
  };
  const _origToggleTests=window.toggleTestsNav;
  window.toggleTestsNav=function(btn){
    _origToggleTests(btn);
    history.replaceState(null,'','#tests');
  };
  window.addEventListener('popstate',function(){
    const t=_fragTab();if(t)navTo(t);
  });
})();
window.addEventListener('resize',()=>{
  if(_lastState){drawSpark(_lastState.history||[]);drawSecTrend(_secHist);}
  if(_lastHealth){drawDiskBars(_lastHealth.disk_read_kbps||0,_lastHealth.disk_write_kbps||0);drawNetSpark('net-spark',_netHist);drawNetSpark('h-net-spark',_hNetHist);}
});
// ── Canvas hover tooltips ──────────────────────────────────────────────────
const _tt=document.createElement('div');_tt.className='tt';document.body.appendChild(_tt);
function showTip(e,lines){
  _tt.innerHTML=lines.filter(Boolean).join('<br>');_tt.style.display='block';
  const r=_tt.getBoundingClientRect();
  let x=e.clientX+14,y=e.clientY-r.height/2;
  if(x+r.width>window.innerWidth-4)x=e.clientX-r.width-10;
  if(y<4)y=4;if(y+r.height>window.innerHeight-4)y=window.innerHeight-r.height-4;
  _tt.style.left=x+'px';_tt.style.top=y+'px';
}
function hideTip(){_tt.style.display='none';}
function wireTip(cid,pl,pr,getHist,fmt){
  const c=$(cid);if(!c)return;
  c.style.cursor='crosshair';
  c.addEventListener('mousemove',e=>{
    const h=getHist();if(!h||h.length<2)return;
    const rect=c.getBoundingClientRect();
    const IW=rect.width-pl-pr;
    const xi=e.clientX-rect.left-pl;
    let i=Math.round(xi/IW*(h.length-1));
    i=Math.max(0,Math.min(h.length-1,i));
    showTip(e,fmt(h[i]));
  });
  c.addEventListener('mouseleave',hideTip);
}
wireTip('spark',36,10,()=>(_lastState&&_lastState.history)||[],p=>[
  `<span style="color:var(--muted)">${Tc(p.t)}</span>`,
  `<span style="color:var(--green)">✔ OK&nbsp;&nbsp;&nbsp;${N(p.ok)}</span>`,
  p.fail?`<span style="color:var(--red)">✗ Fail&nbsp;&nbsp;${N(p.fail)}</span>`:''
]);
wireTip('net-spark',10,6,()=>_netHist,p=>[
  `<span style="color:var(--muted)">${Tc(p.t)}</span>`,
  `<span style="color:var(--green)">▼ RX&nbsp;&nbsp;${fmtIO(p.rx||0)}</span>`,
  `<span style="color:var(--blue)">▲ TX&nbsp;&nbsp;${fmtIO(p.tx||0)}</span>`
]);
wireTip('h-net-spark',10,6,()=>_hNetHist,p=>[
  `<span style="color:var(--muted)">${Tc(p.t)}</span>`,
  `<span style="color:var(--green)">▼ RX&nbsp;&nbsp;${fmtIO(p.rx||0)}</span>`,
  `<span style="color:var(--blue)">▲ TX&nbsp;&nbsp;${fmtIO(p.tx||0)}</span>`
]);
wireTip('sec-trend',36,10,()=>_secHist,p=>[
  `<span style="color:var(--muted)">${Tc(p.t)}</span>`,
  `<span style="color:#f59e0b">⬛ Block&nbsp;&nbsp;${p.block_pct!=null?p.block_pct.toFixed(1)+'%':'—'}</span>`,
  `<span style="color:#818cf8">╌ Drop&nbsp;&nbsp;&nbsp;${p.drop_pct!=null?p.drop_pct.toFixed(1)+'%':'—'}</span>`,
  p.reach_pct!=null?`<span style="color:#22c55e">✔ Allow&nbsp;&nbsp;${p.reach_pct.toFixed(1)+'%'}</span>`:''
]);
connect();
setInterval(checkRole,5000);
_initDrag('ov-grid');
_initDrag('sec-grid');
_initDrag('health-grid');

// ── Disclaimer modal (shown once per browser session) ─────────────────────
(function(){
  if(sessionStorage.getItem('disclaimer_ack'))return;
  const overlay=document.createElement('div');
  overlay.style.cssText='position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.85);display:flex;align-items:center;justify-content:center;padding:20px';
  overlay.innerHTML=`
<div style="background:var(--surf);border:1px solid var(--amber);border-radius:8px;max-width:540px;width:100%;padding:28px 32px;box-shadow:0 8px 40px rgba(0,0,0,.6)">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
    <span style="font-size:24px">⚠</span>
    <span style="font-size:18px;font-weight:700;color:var(--amber)">Disclaimer</span>
  </div>
  <p style="color:var(--text);line-height:1.65;margin-bottom:12px">
    This tool is intended for <strong>authorized security testing and research
    in controlled lab environments only</strong>.
  </p>
  <ul style="color:var(--text);line-height:1.65;padding-left:18px;margin-bottom:20px">
    <li style="margin-bottom:6px">You are solely responsible for obtaining explicit written permission before testing any systems or networks.</li>
    <li style="margin-bottom:6px">The author(s) accept <strong>no liability</strong> for misuse, unauthorized access, damage, data loss, or legal consequences arising from use of this tool.</li>
    <li>Use of this software constitutes acceptance of these terms.</li>
  </ul>
  <button id="disclaimer-ack" style="width:100%;padding:10px;background:var(--amber);color:#000;font-weight:700;font-size:15px;border:none;border-radius:6px;cursor:pointer">
    I Understand — Continue
  </button>
</div>`;
  document.body.appendChild(overlay);
  document.getElementById('disclaimer-ack').addEventListener('click',function(){
    sessionStorage.setItem('disclaimer_ack','1');
    overlay.remove();
  });
})();
</script>
</body></html>"""
_LOG_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>traffgen &middot; Live View</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#080c10;--surf:#161b22;--border:#1e2d3d;--green:#22c55e;--red:#f85149;--amber:#f59e0b;--blue:#60a5fa;--text:#c9d1d9;--muted:#64748b;--dim:#374151}
html,body{height:100%;overflow:hidden}
body{background:var(--bg);color:var(--text);font-family:'SF Mono',Consolas,monospace;font-size:14px;display:flex;flex-direction:column}
.hdr{display:flex;align-items:center;gap:8px;padding:7px 12px;background:var(--surf);border-bottom:1px solid var(--border);flex-shrink:0}
.title{font-weight:700;font-size:15px;margin-right:auto;color:var(--text)}
.btn{padding:5px 12px;border-radius:5px;border:1px solid var(--border);background:var(--bg);color:var(--muted);font-size:15px;cursor:pointer}
.btn:hover{border-color:var(--green);color:var(--green)}
.btn.af{border-color:var(--green);color:var(--green)}
.fgrp{display:flex;gap:3px}
.body{flex:1;overflow-y:auto;padding:2px 0;min-height:0}
.ll{padding:1px 12px;display:flex;align-items:baseline;white-space:pre-wrap;word-break:break-all}
.ll:hover{background:rgba(255,255,255,.02)}
.ll-sep{padding:4px 0;display:flex;align-items:center}
.sep-line{flex:1;height:1px;background:var(--dim);opacity:.3}
.sep-txt{padding:0 10px;font-size:12px;letter-spacing:.5px;color:var(--dim);white-space:nowrap}
.llt{color:#374151;margin-right:8px;flex-shrink:0;font-size:13px}
.llv{font-weight:700;margin-right:8px;flex-shrink:0;width:40px;font-size:13px}
.llm{color:#c9d1d9;flex:1}
.ll.info .llv{color:#60a5fa}.ll.ok .llv{color:#22c55e}.ll.warn .llv{color:#f59e0b}.ll.error .llv{color:#f85149}.ll.debug .llv{color:#374151}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--dim);border-radius:2px}
</style>
</head>
<body>
<div class="hdr">
  <span class="title">&#9889; traffgen &middot; Live View</span>
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
const Tc=ts=>new Date(ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
function setF(btn,lvl){lf=lvl;document.querySelectorAll('.fgrp .btn').forEach(x=>x.classList.remove('af'));btn.classList.add('af');document.querySelectorAll('.ll').forEach(el=>{if(el.classList.contains('ll-sep'))return;el.style.display=(lvl==='all'||el.classList.contains(lvl))?'':'none';});}
const es=new EventSource('/log');
es.onmessage=ev=>{
  try{
    const d=JSON.parse(ev.data),lvl=d.level||'info';
    const test=d.test||'';
    if(test&&test!==lt){lt=test;const sep=document.createElement('div');sep.className='ll ll-sep';sep.innerHTML='<div class="sep-line"></div><div class="sep-txt">'+H(test)+'</div><div class="sep-line"></div>';b.appendChild(sep);}
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
    threading.Thread(target=_sample_health,   daemon=True, name="health-sampler").start()
    threading.Thread(target=_sample_net_info, daemon=True, name="net-info-sampler").start()
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
