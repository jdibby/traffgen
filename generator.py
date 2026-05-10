#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generator.py — Traffic Generator v3.4.0
========================================
Simulates realistic network traffic across a wide range of protocols and
behaviours: DNS, HTTP/HTTPS/HTTP3, FTP, SSH, NTP, BGP, ICMP, SNMP,
DoH, DoT, C2 beacon, DNS exfiltration, LLM/AI DLP simulation (fake PII
uploads to known LLM API endpoints), Metasploit checks, web crawling,
malware/phishing domain probing, ad-tracker HEAD requests, speed-tests,
and more.

Designed to run inside a Docker container as a continuous traffic source
for testing firewalls, IDS/IPS rules, and security analytics pipelines.

Usage (stand-alone):
    python3 generator.py --suite=all --size=M --loop

Usage (Docker default):
    # See CMD in Dockerfile — runs suite=all, size=S, loop
"""

# ── Standard library ──────────────────────────────────────────────────────────────────────────────
import os
import re
import sys
import ssl
import json
import time
import base64
import signal
import socket
import random
import threading
import argparse
import subprocess
import traceback
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

# ── Third-party ─────────────────────────────────────────────────────────────────────────────────
import requests
import urllib3
from bs4 import BeautifulSoup

# Rich terminal UI
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeElapsedColumn, TimeRemainingColumn, MofNCompleteColumn,
)
from rich.table import Table
from rich import box

# ── Local config ──────────────────────────────────────────────────────────────────────────────
from endpoints import *           # noqa: F401,F403  (large data file)

# ── Globals ───────────────────────────────────────────────────────────────────────────────────
VERSION = "3.4.0"

PLACEHOLDER_FULL_FILE_CONTENT_SEE_BELOW = True
