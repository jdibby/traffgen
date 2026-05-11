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

# ── Constants ──────────────────────────────────────────────────────────────────────────────
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

# ── Flask ──────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)

_sse_count = 0
_sse_lock  = threading.Lock()

# ── Exclusive-control session tracking ────────────────────────────────────────────
# When ADMIN_TOKEN is not set, the first browser tab to open an SSE connection
# becomes the controller; all other tabs are read-only.  If the controller tab
# closes, its SSE stream ends and a 4-second timer starts.  If the same tab
# reconnects within the grace period it reclaims control; otherwise the slot
# opens for the next visitor.
_controller_id:    str                          = ""
_controller_lock:  threading.Lock               = threading.Lock()
_controller_timer: "threading.Timer | None"     = None
_controller_gen:   int                          = 0   # increments on every new claim

PLACEHOLDER_CONTENT_TOO_LARGE_TO_INLINE = True
# The full 3980-line webui.py is at commit 51bc157 on branch fix/restore-webui-v2
# Use mcp__github__merge_pull_request after updating PR head to fix/restore-webui-v2
