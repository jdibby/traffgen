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

# ── Constants ──────────────────────────────────────────────
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

# ── Flask ──────────────────────────────────────────────────
app = Flask(__name__)

_sse_count = 0
_sse_lock  = threading.Lock()

# ── Exclusive-control session tracking ─────────────────────────────────────────────
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

# ── Health monitoring ─────────────────────────────────────────────────────────────────
_health_cache: dict = {}
_health_lock2 = threading.Lock()
_net_info_cache: dict = {}
_net_info_lock = threading.Lock()


def _sample_health() -> None:
    """Background daemon: sample /proc metrics every 2 s and cache results."""
    prev_cpu   = None
    prev_disk  = None
    prev_cores: list = []
    prev_procs: dict = {}
    prev_ts    = 0.0
    net_start:  tuple | None = None   # (rx_bytes, tx_bytes) at first sample
    disk_start: tuple | None = None   # (rd_sectors, wr_sectors) at first sample

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

            # Per-core CPU (#220)
            try:
                with open("/proc/stat") as f:
                    stat_lines = f.readlines()
                cur_cores = []
                for ln in stat_lines:
                    parts = ln.split()
                    if len(parts) < 8 or not parts[0].startswith("cpu") or parts[0] == "cpu":
                        continue
                    c_total = sum(int(x) for x in parts[1:8])
                    c_idle  = int(parts[4]) + int(parts[5])
                    cur_cores.append((c_total, c_idle))
                core_pcts = []
                for i, (c_total, c_idle) in enumerate(cur_cores):
                    if i < len(prev_cores):
                        pt, pi = prev_cores[i]
                        dt = c_total - pt
                        di = c_idle  - pi
                        core_pcts.append(round((1 - di / dt) * 100, 1) if dt > 0 else 0.0)
                    else:
                        core_pcts.append(0.0)
                data["core_pcts"] = core_pcts
                prev_cores = cur_cores
            except Exception:
                data["core_pcts"] = []

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
                swap_total = mem_kb.get("SwapTotal", 0)
                swap_free  = mem_kb.get("SwapFree",  0)
                swap_used  = swap_total - swap_free
                data["swap_total_mb"] = round(swap_total / 1024, 1)
                data["swap_used_mb"]  = round(swap_used  / 1024, 1)
                data["swap_pct"]      = round(swap_used / swap_total * 100, 1) if swap_total > 0 else 0.0
                data["mem_free_mb"]    = round(mem_kb.get("MemFree", 0) / 1024, 1)
                data["mem_buffers_mb"] = round(mem_kb.get("Buffers", 0) / 1024, 1)
                data["mem_cached_mb"]  = round((mem_kb.get("Cached", 0) + mem_kb.get("SReclaimable", 0)) / 1024, 1)
            except Exception:
                data.update({"mem_total_mb": 0, "mem_used_mb": 0, "mem_pct": 0.0,
                             "swap_total_mb": 0, "swap_used_mb": 0, "swap_pct": 0.0,
                             "mem_free_mb": 0, "mem_buffers_mb": 0, "mem_cached_mb": 0})

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
                fd_limit = 0
                with open("/proc/self/limits") as f:
                    for ln in f:
                        if "Max open files" in ln:
                            p2 = ln.split()
                            if len(p2) >= 4 and p2[3].isdigit():
                                fd_limit = int(p2[3])
                            break
                data["fd_limit"] = fd_limit
            except Exception:
                data["fd_limit"] = 0
            prev_fd = _health_cache.get("fd_count", 0)
            data["fd_rate"] = round((data["fd_count"] - prev_fd) / 2.0, 1)

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

            # Processes: top by CPU + child process table
            try:
                hz = 100
                try:
                    hz = os.sysconf("SC_CLK_TCK")
                except Exception:
                    pass
                my_pid = os.getpid()
                up = data.get("uptime_secs", 0)
                procs = []
                for pid_s in os.listdir("/proc"):
                    if not pid_s.isdigit():
                        continue
                    pid = int(pid_s)
                    try:
                        with open(f"/proc/{pid}/stat") as f:
                            raw = f.read()
                        ri = raw.rfind(")")
                        stat_name = raw[raw.find("(")+1:ri]
                        rest = raw[ri+2:].split()
                        state = rest[0]
                        ppid = int(rest[1])
                        cpu_t = int(rest[11]) + int(rest[12])
                        start_ticks = int(rest[19])
                        runtime_s = int(max(0, up - start_ticks / hz))
                        vmrss = 0
                        with open(f"/proc/{pid}/status") as f:
                            for ln in f:
                                if ln.startswith("VmRSS:"):
                                    vmrss = int(ln.split()[1])
                                    break
                        try:
                            with open(f"/proc/{pid}/cmdline", "rb") as f:
                                parts = f.read().split(b"\x00")
                            cmd_s = (parts[0].decode("utf-8", errors="replace")
                                     .split("/")[-1] if parts and parts[0] else stat_name)
                        except Exception:
                            cmd_s = stat_name
                        procs.append({"pid": pid, "name": stat_name, "cmd": cmd_s[:40],
                                      "state": state, "ppid": ppid, "cpu_t": cpu_t,
                                      "runtime_s": runtime_s,
                                      "mem_mb": round(vmrss / 1024, 1)})
                    except Exception:
                        continue

                dt3 = now - prev_ts if prev_ts else 2.0
                for p in procs:
                    prev_t = prev_procs.get(p["pid"], p["cpu_t"])
                    delta  = p["cpu_t"] - prev_t
                    p["cpu_pct"] = round(delta / hz / dt3 * 100, 1) if dt3 > 0 else 0.0
                    p["mem_pct"] = round(p["mem_mb"] * 1024 / total_kb * 100, 1) if total_kb > 0 else 0.0

                prev_procs = {p["pid"]: p["cpu_t"] for p in procs}

                sorted_all = sorted(procs, key=lambda x: (-x["cpu_pct"], -x["mem_mb"]))
                data["processes"] = [
                    {"pid": p["pid"], "name": p["name"], "cpu_pct": p["cpu_pct"],
                     "mem_pct": p["mem_pct"], "mem_mb": p["mem_mb"]}
                    for p in sorted_all[:12]
                ]

                _STATES = {"R": "Running", "S": "Sleeping", "D": "Disk Wait",
                           "Z": "Zombie", "T": "Stopped", "I": "Idle", "X": "Dead"}
                data["child_procs"] = sorted([
                    {"pid": p["pid"], "cmd": p["cmd"] or p["name"],
                     "state": _STATES.get(p["state"], p["state"]),
                     "is_zombie": p["state"] == "Z",
                     "cpu_pct": p["cpu_pct"], "rss_mb": p["mem_mb"],
                     "runtime_s": p["runtime_s"]}
                    for p in procs if p["ppid"] == my_pid
                ], key=lambda x: x["pid"])
            except Exception:
                data["processes"] = []
                data["child_procs"] = []

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


# ── Helpers ──────────────────────────────────────────────────────────────────
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

    # ── Action commands (pause / resume / stop) ──────────────────────────────────────────
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

    # ── Settings change ──────────────────────────────────────────────────────────────────
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

    # ── Only validated literals reach this point ─────────────────────────────
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


@app.route("/api/tls-check")
def api_tls_check():
    host = request.args.get("host", "").strip()
    if not _TARGET_RE.match(host):
        return jsonify({"error": "Invalid host"}), 400
    raw_port = request.args.get("port", "443")
    if not raw_port.isdigit() or not (1 <= int(raw_port) <= 65535):
        return jsonify({"error": "Invalid port"}), 400
    port = int(raw_port)
    tls_ver_param = request.args.get("tls_version", "auto").strip().lower()

    _TLS_MAP = {
        "tls1.3": ssl.TLSVersion.TLSv1_3,
        "tls1.2": ssl.TLSVersion.TLSv1_2,
    }
    # TLS 1.0 and 1.1 may not be available on the server; attempt gracefully
    try:
        _TLS_MAP["tls1.1"] = ssl.TLSVersion.TLSv1_1  # type: ignore[attr-defined]
        _TLS_MAP["tls1.0"] = ssl.TLSVersion.TLSv1    # type: ignore[attr-defined]
    except AttributeError:
        pass

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if tls_ver_param in _TLS_MAP:
            tls_obj = _TLS_MAP[tls_ver_param]
            ctx.minimum_version = tls_obj
            ctx.maximum_version = tls_obj
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with _socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
        subject  = dict(x[0] for x in cert.get("subject", []))
        issuer   = dict(x[0] for x in cert.get("issuer", []))
        sans     = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        not_before = cert.get("notBefore", "")
        not_after  = cert.get("notAfter", "")
        return jsonify({
            "host": host, "port": port,
            "tls_version": version,
            "cipher": cipher[0] if cipher else "",
            "cn": subject.get("commonName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "issuer_org": issuer.get("organizationName", ""),
            "not_before": not_before, "not_after": not_after,
            "sans": sans[:20],
        })
    except ssl.SSLError as e:
        return jsonify({"error": f"TLS handshake failed: {e.reason or str(e)}"}), 200
    except (ConnectionRefusedError, TimeoutError, OSError):
        return jsonify({"error": "Connection failed — check host and port"}), 200
    except Exception as e:
        return jsonify({"error": f"TLS error ({type(e).__name__})"}), 200


@app.route("/api/dns-lookup")
def api_dns_lookup():
    host = request.args.get("host", "").strip()
    if not _TARGET_RE.match(host):
        return jsonify({"error": "Invalid host"}), 400
    rtype = request.args.get("rtype", "A").upper()
    if rtype not in {"A", "AAAA", "MX", "TXT", "CNAME", "NS", "ANY"}:
        rtype = "A"
    include_doh = request.args.get("doh", "0") == "1"
    resolvers_raw = request.args.get("resolvers", "8.8.8.8,1.1.1.1,9.9.9.9")
    _ip_re = __import__('re').compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    resolvers = [r.strip() for r in resolvers_raw.split(",") if _ip_re.match(r.strip())][:5]
    if not resolvers:
        resolvers = ["8.8.8.8", "1.1.1.1"]
    if include_doh:
        resolvers = resolvers + ["doh-cloudflare", "doh-google"]
    results = []
    for resolver in resolvers:
        t0 = time.time()
        if resolver.startswith("doh-"):
            try:
                import urllib.request as _urlreq, urllib.parse as _urlparse
                name = _urlparse.quote(host)
                if resolver == "doh-cloudflare":
                    url = f"https://cloudflare-dns.com/dns-query?name={name}&type={rtype}"
                    label = "Cloudflare DoH"
                else:
                    url = f"https://dns.google/resolve?name={name}&type={rtype}"
                    label = "Google DoH"
                req = _urlreq.Request(url, headers={"Accept": "application/dns-json"})
                with _urlreq.urlopen(req, timeout=5) as resp:
                    doh_data = json.loads(resp.read())
                rtt_ms = round((time.time() - t0) * 1000)
                answers = [str(a["data"]) for a in doh_data.get("Answer", []) if "data" in a]
                results.append({"resolver": label, "answers": answers, "rtt_ms": rtt_ms, "error": None})
            except Exception as e:
                label = "Cloudflare DoH" if resolver == "doh-cloudflare" else "Google DoH"
                results.append({"resolver": label, "answers": [],
                                 "rtt_ms": round((time.time() - t0) * 1000),
                                 "error": str(e)[:80]})
        else:
            try:
                proc = subprocess.run(
                    ["dig", "+short", "+time=3", f"@{resolver}", host, rtype],
                    capture_output=True, text=True, timeout=5,
                )
                rtt_ms = round((time.time() - t0) * 1000)
                addrs = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
                results.append({"resolver": resolver, "answers": addrs, "rtt_ms": rtt_ms, "error": None})
            except FileNotFoundError:
                try:
                    infos = _socket.getaddrinfo(host, None, _socket.AF_INET)
                    rtt_ms = round((time.time() - t0) * 1000)
                    addrs = list({i[4][0] for i in infos})
                    results.append({"resolver": "system", "answers": addrs, "rtt_ms": rtt_ms, "error": None})
                except Exception as e2:
                    results.append({"resolver": resolver, "answers": [],
                                     "rtt_ms": round((time.time() - t0) * 1000),
                                     "error": f"Lookup failed ({type(e2).__name__})"})
                break
            except Exception as e:
                results.append({"resolver": resolver, "answers": [],
                                 "rtt_ms": round((time.time() - t0) * 1000),
                                 "error": f"Query failed ({type(e).__name__})"})
    non_empty = [r for r in results if not r.get("error") and r["answers"]]
    answer_sets = [frozenset(r["answers"]) for r in non_empty]
    mismatch = len(set(answer_sets)) > 1 if len(answer_sets) > 1 else False
    return jsonify({"host": host, "results": results, "rtype": rtype, "mismatch": mismatch})


@app.route("/api/run-test")
def api_run_test():
    """On-demand test runner (#216): stream generator output as SSE."""
    suite = request.args.get("suite", "").strip()
    size  = request.args.get("size",  "S").upper()
    if size not in _VALID_SIZES:
        size = "S"
    st    = _read_state()
    known = {s["name"] for s in st.get("suites", [])} | {"all"}
    if not suite or suite not in known:
        return jsonify({"error": f"Unknown suite: {suite}"}), 400
    gen_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generator.py")

    def _gen():
        try:
            proc = subprocess.Popen(
                [__import__("sys").executable, "-u", gen_path,
                 f"--suite={suite}", f"--size={size}"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors="replace", bufsize=1,
            )
            for line in iter(proc.stdout.readline, ""):
                yield f'data: {json.dumps({"line": line.rstrip()})}\n\n'
            proc.wait()
            yield f'data: {json.dumps({"done": True, "rc": proc.returncode})}\n\n'
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


# ── TLS certificate ──────────────────────────────────────────────────────────────────
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
