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

            # Network I/O
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
                        net_rx += int(p[1])
                        net_tx += int(p[9])
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
