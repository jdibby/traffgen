#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Traffic Generator with Rich UI + Reporting

Adds:
- Consistent panels/banners (Rich)
- Live progress/status spinners (Rich)
- Per-test timing and pass/fail based on subprocess exit codes
- Final summary table of all tests with durations
- Optional JSON artifact via --json-out
"""

import os, sys, time, random, threading, argparse, subprocess, socket, ssl, traceback, json
import urllib.request
from urllib.parse import urljoin

import requests
import urllib3
from bs4 import BeautifulSoup

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from endpoints import *  # your existing endpoints file

# ---- Rich UI imports ----
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, MofNCompleteColumn
from rich.table import Table
from rich import box

console = Console(highlight=False)

# Disable SSL warning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context

# Global test results
TEST_RESULTS = []  # list of dicts: {name, status, duration, details}


# ==========================
# UI helpers
# ==========================

def ui_banner(title: str, subtitle: str = "", style: str = "green"):
    content = f"[bold {style}]{title}[/]"
    if subtitle:
        content += f"\n{subtitle}"
    console.print(Panel.fit(content, border_style=style))

def ui_status(msg: str, style: str = "cyan"):
    return console.status(f"[{style}]{msg}[/]")

def ui_error(msg: str):
    console.print(f"[bold red]❌ {msg}[/]")

def ui_ok(msg: str):
    console.print(f"[bold green]✅ {msg}[/]")

def ui_warn(msg: str):
    console.print(f"[bold yellow]⚠ {msg}[/]")

def progress_wait(seconds: int, label: str = "Waiting"):
    if seconds <= 0:
        return
    with Progress(
        SpinnerColumn(),
        TextColumn(f"[cyan]{label}[/]"),
        BarColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("wait", total=seconds)
        start = time.time()
        while not progress.finished:
            elapsed = time.time() - start
            progress.update(task, completed=min(elapsed, seconds))
            time.sleep(0.1)


# ==========================
# Watchdog
# ==========================
class watchdog:
    def __init__(self, timeout_seconds):
        self.timeout = timeout_seconds
        self.last_kick = time.time()
        self.thread = threading.Thread(target=self._watch, daemon=True)
        self.thread.start()

    def kick(self):
        self.last_kick = time.time()

    def _watch(self):
        while True:
            if time.time() - self.last_kick > self.timeout:
                ui_warn("WATCHDOG: No activity detected. Exiting to force container restart...")
                os._exit(1)
            time.sleep(1)


# ==========================
# Utilities
# ==========================

def get_container_ip():
    try:
        result = subprocess.run(
            ["sh", "-lc", "ip route get 1 | awk '{for(i=1;i<=NF;i++) if ($i==\"src\") {print $(i+1); exit}}'"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        output = result.stdout.decode().strip()
        return output if output else "127.0.0.1"
    except Exception as e:
        ui_warn(f"Failed to determine container IP: {e}")
        return "127.0.0.1"


def run_shell(cmd, details, timeout=None, quiet=True):
    """Run a shell command, capture return code; append errors to details.
    Returns True on success, False on failure.
    """
    try:
        res = subprocess.run(
            cmd,
            shell=True,
            timeout=timeout,
            stdout=subprocess.DEVNULL if quiet else None,
            stderr=subprocess.STDOUT if quiet else None
        )
        if res.returncode != 0:
            details.append(f"cmd failed ({res.returncode}): {cmd[:160]}")
            return False
        return True
    except subprocess.TimeoutExpired:
        details.append(f"cmd timeout: {cmd[:160]}")
        return False
    except Exception as e:
        details.append(f"cmd exception {e.__class__.__name__}: {cmd[:160]}")
        return False


def record_test(name):
    """Decorator to time a test and record status/details to TEST_RESULTS.
    The wrapped function should return a dict like:
        {"status": "pass"|"fail", "details": [lines ...]}
    If it returns None, 'pass' is assumed.
    """
    def deco(fn):
        def inner():
            start = time.time()
            status = "pass"
            details = []
            try:
                ret = fn()
                if isinstance(ret, dict):
                    status = ret.get("status", "pass")
                    details = ret.get("details", [])
            except Exception as e:
                status = "fail"
                details.append(f"exception: {e.__class__.__name__}: {e}")
            finally:
                duration = time.time() - start
                TEST_RESULTS.append({
                    "name": name,
                    "status": status,
                    "duration": duration,
                    "details": details,
                })
            return None
        return inner
    return deco


def _size_to_limits(size, s, m, l, xl):
    return {'S': s, 'M': m, 'L': l, 'XL': xl}.get(size, m)


# ==========================
# Tests
# ==========================

@record_test("BGP Peering")
def bgp_peering():
    ui_banner("BGP Peering", "Starting gobgpd and configuring neighbors", "magenta")
    details = []
    gobgpd_proc = None
    try:
        with ui_status("Starting gobgpd..."):
            try:
                gobgpd_proc = subprocess.Popen(
                    ["gobgpd", "--api-hosts", "127.0.0.1:50051"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                ui_ok("gobgpd started")
            except Exception as e:
                ui_warn(f"Failed to start gobgpd: {e}")
                details.append(f"start gobgpd: {e}")
                gobgpd_proc = None

        def gobgp_wait_api(host, port, timeout=15):
            start = time.time()
            while time.time() - start < timeout:
                try:
                    with socket.create_connection((host, port), timeout=1):
                        return True
                except OSError:
                    time.sleep(0.3)
            return False

        failures = 0

        if gobgpd_proc and gobgp_wait_api("127.0.0.1", 50051, timeout=15):
            try:
                router_id = get_container_ip()
                with ui_status("Configuring global BGP instance..."):
                    ok = run_shell(
                        f"gobgp -u 127.0.0.1 -p 50051 global as 65555 router-id {router_id}",
                        details, timeout=10
                    )
                    if not ok: failures += 1
                for neighbor_ip in bgp_neighbors:
                    ok = run_shell(
                        f"gobgp -u 127.0.0.1 -p 50051 neighbor add {neighbor_ip} as 65555",
                        details, timeout=10
                    )
                    if not ok:
                        failures += 1
            except Exception as e:
                details.append(f"config exception: {e}")
                failures += 1
        else:
            ui_warn("gobgpd not ready — skipping BGP setup")
            details.append("gobgpd not ready; skipped")

        with ui_status("Terminating gobgpd in 10s..."):
            time.sleep(10)
        if gobgpd_proc:
            gobgpd_proc.terminate()
            try:
                gobgpd_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                gobgpd_proc.kill()

        ui_ok("BGP Peering test complete")
        return {"status": "pass" if failures == 0 else "fail", "details": details}
    except Exception as e:
        details.append(f"unexpected: {e}")
        return {"status": "fail", "details": details}


@record_test("Bigfile")
def bigfile():
    url = 'http://ipv4.download.thinkbroadband.com/5GB.zip'
    ui_banner("Bigfile", f"Downloading 5GB ZIP: {url}")
    details = []
    try:
        with requests.get(url, stream=True, verify=False, timeout=5) as response:
            response.raise_for_status()
            total = int(response.headers.get('content-length', 0))
            with Progress(
                SpinnerColumn(), TextColumn("[cyan]Downloading[/]"),
                BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
                TimeElapsedColumn(), TimeRemainingColumn(), console=console,
            ) as progress:
                task = progress.add_task("download", total=total if total > 0 else None)
                for chunk in response.iter_content(chunk_size=1024 * 64):
                    if chunk:
                        progress.update(task, advance=len(chunk))
        ui_ok("Bigfile download test complete")
        return {"status": "pass", "details": details}
    except Exception as e:
        details.append(f"download error: {e}")
        return {"status": "fail", "details": details}


@record_test("DNS dig")
def dig_random():
    ui_banner("DNS", "Random dig queries")
    details = []
    try:
        target_ips = _size_to_limits(ARGS.size, 1, 2, 4, len(dns_endpoints))
        target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(dns_urls))
        random.shuffle(dns_endpoints)
        random.shuffle(dns_urls)

        failures = 0
        with Progress(SpinnerColumn(), TextColumn("[cyan]dig[/]"), MofNCompleteColumn(),
                      BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("dig", total=target_ips * target_urls)
            for i, ip in enumerate(dns_endpoints[:target_ips], 1):
                for j, url in enumerate(dns_urls[:target_urls], 1):
                    cmd = f"dig {url} @{ip} +time=1 +tries=1 +short"
                    ok = run_shell(cmd, details, timeout=5)
                    if not ok: failures += 1
                    progress.update(task, advance=1)
        return {"status": "pass" if failures == 0 else "fail", "details": details}
    except Exception as e:
        details.append(f"unexpected: {e}")
        return {"status": "fail", "details": details}


@record_test("FTP")
def ftp_random():
    ui_banner("FTP", "Rate-limited download via curl")
    details = []
    try:
        target = _size_to_limits(ARGS.size, '1MB', '10MB', '100MB', '1GB')
        cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 5 -o /dev/null ftp://speedtest:speedtest@ftp.otenet.gr/test{target}.db"
        ok = run_shell(cmd, details, timeout=60)
        return {"status": "pass" if ok else "fail", "details": details}
    except Exception as e:
        details.append(f"error: {e}")
        return {"status": "fail", "details": details}


def _head_many(urls, label):
    details = []
    failures = 0
    with Progress(SpinnerColumn(), TextColumn(f"[cyan]{label}[/]"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task(label, total=len(urls))
        for url in urls:
            user_agent = random.choice(user_agents)
            cmd = f"curl -k -s --show-error --connect-timeout 5 -I -L -o /dev/null --max-time 5 -A '{user_agent}' {url}"
            ok = run_shell(cmd, details, timeout=10)
            if not ok: failures += 1
            progress.update(task, advance=1)
    return (failures == 0), details


@record_test("HTTP HEAD")
def http_random():
    ui_banner("HTTP HEAD", "Random endpoints + DNS URLs")
    try:
        target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(http_endpoints + dns_urls))
        pool = (http_endpoints[:] + dns_urls[:])
        random.shuffle(pool)
        ok, details = _head_many(pool[:target_urls], "HTTP")
        return {"status": "pass" if ok else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"unexpected: {e}"]}


@record_test("HTTP ZIP download")
def http_download_zip():
    try:
        user_agent = random.choice(user_agents)
        targets = {'S': '15MB', 'M': '30MB', 'L': '100MB', 'XL': '1GB'}
        target = targets.get(ARGS.size, '30MB')
        url = f"https://link.testfile.org/{target}"
        ui_banner("HTTP Download (ZIP)", f"{target} from {url}")
        cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 5 -L -o /dev/null -A '{user_agent}' {url}"
        details = []
        ok = run_shell(cmd, details, timeout=120)
        return {"status": "pass" if ok else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("HTTP tar.gz download")
def http_download_targz():
    ui_banner("HTTP Download (tar.gz)", "WordPress latest.tar.gz")
    details = []
    try:
        cmd = "curl --limit-rate 3M -k --show-error --connect-timeout 5 -o /dev/null http://wordpress.org/latest.tar.gz"
        ok = run_shell(cmd, details, timeout=120)
        return {"status": "pass" if ok else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("Nikto Web Scanner")
def web_scanner():
    timeout = _size_to_limits(ARGS.size, 60, 120, 180, 240)
    url = random.choice(webscan_endpoints)
    ui_banner("Nikto Web Scanner", f"Target: {url} (maxtime {timeout}s)")
    details = []
    try:
        cmd = f"echo y | nikto -h '{url}' -maxtime '{timeout}' -timeout 1 -nointeractive"
        ok = run_shell(cmd, details, timeout=timeout + 30, quiet=False)
        return {"status": "pass" if ok else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("HTTPS HEAD")
def https_random():
    ui_banner("HTTPS HEAD", "Random endpoints")
    try:
        target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(https_endpoints))
        pool = https_endpoints[:]
        random.shuffle(pool)
        ok, details = _head_many(pool[:target_urls], "HTTPS")
        return {"status": "pass" if ok else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("AI HTTPS HEAD")
def ai_https_random():
    ui_banner("AI HTTPS HEAD", "AI endpoints")
    try:
        target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(ai_endpoints))
        pool = ai_endpoints[:]
        random.shuffle(pool)
        ok, details = _head_many(pool[:target_urls], "AI HTTPS")
        return {"status": "pass" if ok else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("Ads HEAD")
def ads_random():
    ui_banner("Ad Endpoints (HEAD)", "Ad/tracker endpoints")
    try:
        target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(ad_endpoints))
        pool = ad_endpoints[:]
        random.shuffle(pool)
        ok, details = _head_many(pool[:target_urls], "ADS")
        return {"status": "pass" if ok else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("HTTPS Crawl")
def https_crawl():
    iterations = _size_to_limits(ARGS.size, 1, 3, 5, 10)
    target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(https_endpoints))
    ui_banner("HTTPS Crawl", f"{iterations} deep across {target_urls} starts")
    try:
        random.shuffle(https_endpoints)
        for url in https_endpoints[:target_urls]:
            scrape_iterative(url, iterations)
        return {"status": "pass", "details": []}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("Pornography Crawl")
def pornography_crawl():
    iterations = _size_to_limits(ARGS.size, 1, 3, 5, 10)
    target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(pornography_endpoints))
    ui_banner("Pornography Crawl", f"{iterations} deep across {target_urls} starts", style="red")
    try:
        random.shuffle(pornography_endpoints)
        for url in pornography_endpoints[:target_urls]:
            scrape_iterative(url, iterations)
        return {"status": "pass", "details": []}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("Malware Agents HEAD")
def malware_random():
    ui_banner("Malware Agents (HEAD)", "Known malware domains (safe HEAD)")
    try:
        target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(malware_endpoints))
        pool = malware_endpoints[:]
        random.shuffle(pool)
        details = []
        failures = 0
        with Progress(SpinnerColumn(), TextColumn("[cyan]MALWARE AGENTS[/]"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("malagents", total=target_urls)
            for url in pool[:target_urls]:
                ua = random.choice(malware_user_agents)
                cmd = f"curl -k -s --show-error --connect-timeout 3 -I -o /dev/null --max-time 5 -A '{ua}' {url}"
                ok = run_shell(cmd, details, timeout=10)
                if not ok: failures += 1
                progress.update(task, advance=1)
        return {"status": "pass" if failures == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("ICMP Ping")
def ping_random():
    target_ips = _size_to_limits(ARGS.size, 1, 2, 5, len(icmp_endpoints))
    ui_banner("ICMP Ping", f"{target_ips} hosts")
    details = []
    try:
        random.shuffle(icmp_endpoints)
        fails = 0
        for ip in icmp_endpoints[:target_ips]:
            cmd = f"ping -c2 -i1 -s64 -W1 -w2 {ip}"
            if not run_shell(cmd, details, timeout=10):
                fails += 1
        return {"status": "pass" if fails == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("Traceroute")
def traceroute_random():
    target_ips = _size_to_limits(ARGS.size, 1, 2, 5, len(icmp_endpoints))
    ui_banner("Traceroute", f"{target_ips} hosts")
    details = []
    try:
        random.shuffle(icmp_endpoints)
        fails = 0
        for ip in icmp_endpoints[:target_ips]:
            cmd = f"traceroute {ip} -w1 -q1 -m5"
            if not run_shell(cmd, details, timeout=30):
                fails += 1
        return {"status": "pass" if fails == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("Netflix Fast.com")
def speedtest_fast():
    ui_banner("Netflix Fast.com", "Running fastcli multiple times")
    details = []
    try:
        duration = _size_to_limits(ARGS.size, 1, 2, 3, 4)
        timeout_per_test = 20
        fails = 0
        for i in range(duration):
            ok = run_shell('python3 -m fastcli', details, timeout=timeout_per_test, quiet=False)
            if not ok: fails += 1
        return {"status": "pass" if fails == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("Nmap 1-1024")
def nmap_1024os():
    target_ips = _size_to_limits(ARGS.size, 1, 2, 5, len(nmap_endpoints))
    ui_banner("Nmap 1-1024", f"{target_ips} hosts")
    details = []
    try:
        random.shuffle(nmap_endpoints)
        fails = 0
        for ip in nmap_endpoints[:target_ips]:
            cmd = ('nmap -Pn -p 1-1024 %s -T4 --max-retries 0 --max-parallelism 2 '
                   '--randomize-hosts --host-timeout 1m --script-timeout 1m '
                   '--script-args http.useragent="Mozilla/5.0" -debug') % ip
            if not run_shell(cmd, details):
                fails += 1
        return {"status": "pass" if fails == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("Nmap CVE")
def nmap_cve():
    target_ips = _size_to_limits(ARGS.size, 1, 2, 5, len(nmap_endpoints))
    ui_banner("Nmap CVE (scripts)", f"{target_ips} hosts")
    details = []
    try:
        random.shuffle(nmap_endpoints)
        fails = 0
        for ip in nmap_endpoints[:target_ips]:
            cmd = ('nmap -sV --script=ALL %s -T4 --max-retries 0 --max-parallelism 2 '
                   '--randomize-hosts --host-timeout 1m --script-timeout 1m '
                   '--script-args http.useragent="Mozilla/5.0" -debug') % ip
            if not run_shell(cmd, details):
                fails += 1
        return {"status": "pass" if fails == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("NTP")
def ntp_random():
    target_urls = _size_to_limits(ARGS.size, 1, 2, 5, len(ntp_endpoints))
    ui_banner("NTP (UDP/123)", f"{target_urls} servers")
    details = []
    try:
        random.shuffle(ntp_endpoints)
        fails = 0
        for url in ntp_endpoints[:target_urls]:
            cmd = f"(printf '\\x1b'; head -c 47 < /dev/zero) | nc -u -w1 {url} 123"
            if not run_shell(cmd, details, timeout=5):
                fails += 1
        return {"status": "pass" if fails == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("SSH")
def ssh_random():
    target_ips = _size_to_limits(ARGS.size, 1, 2, 5, len(ssh_endpoints))
    ui_banner("SSH Connect", f"{target_ips} hosts (non-interactive)")
    details = []
    try:
        random.shuffle(ssh_endpoints)
        fails = 0
        for ip in ssh_endpoints[:target_ips]:
            cmd = f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 {ip}"
            if not run_shell(cmd, details, timeout=5):
                fails += 1
        return {"status": "pass" if fails == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("HTTPS Response Time")
def urlresponse_random():
    target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(https_endpoints))
    ui_banner("HTTPS Response Time", f"{target_urls} URLs")
    try:
        random.shuffle(https_endpoints)
        details = []
        with Progress(SpinnerColumn(), TextColumn("[cyan]RESP TIME[/]"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("resp", total=target_urls)
            for url in https_endpoints[:target_urls]:
                try:
                    t = requests.get(url, timeout=3, verify=False).elapsed.total_seconds()
                    details.append(f"{url} -> {t:.3f}s")
                except Exception as e:
                    details.append(f"{url} -> skip ({e.__class__.__name__})")
                progress.update(task, advance=1)
        return {"status": "pass", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("Virus Simulation")
def virus_sim():
    target_urls = _size_to_limits(ARGS.size, 1, 2, 3, len(virus_endpoints))
    ui_banner("Virus Simulation (downloads)", f"{target_urls} files")
    details = []
    try:
        random.shuffle(virus_endpoints)
        fails = 0
        for url in virus_endpoints[:target_urls]:
            cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 4 -o /dev/null {url}"
            if not run_shell(cmd, details, timeout=20):
                fails += 1
        return {"status": "pass" if fails == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("DLP Simulation HTTPS")
def dlp_sim_https():
    target_urls = _size_to_limits(ARGS.size, 1, 2, 3, len(dlp_https_endpoints))
    ui_banner("DLP Simulation (HTTPS)", f"{target_urls} files")
    details = []
    try:
        random.shuffle(dlp_https_endpoints)
        fails = 0
        for url in dlp_https_endpoints[:target_urls]:
            cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 4 -o /dev/null {url}"
            if not run_shell(cmd, details, timeout=20):
                fails += 1
        return {"status": "pass" if fails == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("Malware File Download")
def malware_download():
    target_urls = _size_to_limits(ARGS.size, 1, 2, 3, len(malware_files))
    ui_banner("Malware File Download (HTTPS)", f"{target_urls} files")
    details = []
    try:
        random.shuffle(malware_files)
        fails = 0
        for url in malware_files[:target_urls]:
            cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 4 -o /dev/null {url}"
            if not run_shell(cmd, details, timeout=20):
                fails += 1
        return {"status": "pass" if fails == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("Typosquatting (dnstwist)")
def squatting_domains():
    target_domains = _size_to_limits(ARGS.size, 1, 2, 3, 4)
    ui_banner("Typosquatting Generator", f"{target_domains} base domains")
    details = []
    try:
        random.shuffle(squatting_endpoints)
        fails = 0
        for url in squatting_endpoints[:target_domains]:
            cmd = f"dnstwist --registered {url}"
            if not run_shell(cmd, details, timeout=None, quiet=False):
                fails += 1
        return {"status": "pass" if fails == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("Web Crawl")
def webcrawl():
    iterations = _size_to_limits(ARGS.size, 10, 20, 50, 100)
    attempts = _size_to_limits(ARGS.size, 1, 3, 5, 10)
    ui_banner("Web Crawl", f"Start: {ARGS.crawl_start} | depth {iterations} | attempts {attempts}")
    try:
        for _ in range(attempts):
            scrape_iterative(ARGS.crawl_start, iterations)
        return {"status": "pass", "details": []}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


@record_test("IPS (BlackSun)")
def ips():
    ui_banner("IPS Trigger", "BlackSun user-agent to testmyids.com")
    details = []
    try:
        cmd = "curl -k -s --show-error --connect-timeout 3 -I --max-time 5 -A BlackSun www.testmyids.com"
        ok = run_shell(cmd, details, timeout=10)
        return {"status": "pass" if ok else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


# ==========================
# GitHub domain checks
# ==========================

def github_domain_check_download_file(url, local_filename):
    try:
        with requests.get(url, stream=True, verify=False, timeout=5) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        return True
    except Exception as e:
        return False

def _github_read_and_probe(local_filename, num_random_domains=10):
    try:
        with open(local_filename, 'r', encoding='utf-8') as f:
            all_domains = f.readlines()
        valid = [d.strip() for d in all_domains if d.strip() and not d.strip().startswith('#')]
    except Exception:
        return 0, ["failed reading local file"]

    selected = valid if len(valid) < num_random_domains else random.sample(valid, num_random_domains)
    failures = 0
    details = []
    for domain in selected:
        url = f"https://{domain}"
        try:
            r = requests.get(url, timeout=1, verify=False, allow_redirects=True)
            details.append(f"{url} -> {r.status_code}")
        except Exception as e:
            details.append(f"{url} -> error ({e.__class__.__name__})")
            failures += 1
    return failures, details

@record_test("GitHub Domain Check")
def github_domain_check():
    ui_banner("GitHub Domain Check", "Hagezi domain blocklist sample")
    details = []
    try:
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt"
        local = "git-domains-list"
        if not os.path.exists(local):
            if not github_domain_check_download_file(url, local):
                details.append("download failed")
                return {"status": "fail", "details": details}
        failures, details = _github_read_and_probe(local, num_random_domains=10)
        return {"status": "pass" if failures == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}

@record_test("GitHub Phishing Domain Check")
def github_phishing_domain_check():
    ui_banner("GitHub Phishing Domain Check", "Active phishing list")
    details = []
    try:
        url = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt"
        local = "git-phishing-list"
        if not os.path.exists(local):
            if not github_domain_check_download_file(url, local):
                details.append("download failed")
                return {"status": "fail", "details": details}
        failures, details = _github_read_and_probe(local, num_random_domains=10)
        return {"status": "pass" if failures == 0 else "fail", "details": details}
    except Exception as e:
        return {"status": "fail", "details": [f"error: {e}"]}


# ==========================
# Scraper helpers
# ==========================

def replace_all_endpoints(url):
    response = urllib.request.urlopen(url)
    data = response.read()
    text = data.decode('utf-8')
    with open('endpoints.py', 'w') as f:
        f.write(text)

def scrape_single_link(url):
    time.sleep(random.uniform(0.2, 2))
    user_agent = random.choice(user_agents)
    try:
        response = requests.get(
            url=url, timeout=2, allow_redirects=True,
            headers={'User-Agent': user_agent}, verify=False
        )
        response.raise_for_status()
        response.encoding = response.apparent_encoding or 'utf-8'
        html = response.text
    except Exception:
        return None
    soup = BeautifulSoup(html, 'html.parser')
    all_links = soup.find_all("a")
    random.shuffle(all_links)
    for link in all_links:
        href = link.get('href')
        if not href or '#' in href:
            continue
        if href.startswith('//') or href.startswith('/'):
            return urljoin(url, href)
        elif href.startswith('http'):
            return href
    return None

def scrape_iterative(base_url, iterations=3):
    next_link = scrape_single_link(base_url)
    for _ in range(iterations):
        if next_link:
            next_link = scrape_single_link(next_link)
        else:
            break


# ==========================
# Runner / CLI / Summary
# ==========================

def run_test(func_list):
    size_name = {'S': 'SMALL', 'M': 'MEDIUM', 'L': 'LARGE', 'XL': 'EXTRA-LARGE'}.get(ARGS.size, 'MEDIUM')
    cfg = Table.grid(padding=(0, 2))
    cfg.add_row("[bold]Suite[/]:", ARGS.suite.upper())
    cfg.add_row("[bold]Size[/]:", size_name)
    cfg.add_row("[bold]Loop[/]:", str(ARGS.loop))
    cfg.add_row("[bold]Max Wait (s)[/]:", str(ARGS.max_wait_secs))
    cfg.add_row("[bold]No Wait[/]:", str(ARGS.nowait))
    cfg.add_row("[bold]Crawl Start[/]:", ARGS.crawl_start)
    console.print(Panel(cfg, title="Run Configuration", border_style="blue", box=box.ROUNDED))
    time.sleep(0.3)

    if ARGS.loop:
        while True:
            func = random.choice(func_list)
            func()
            WATCHDOG.kick()
            finish_test()
    else:
        random.shuffle(func_list)
        for func in func_list:
            func()
            WATCHDOG.kick()
            finish_test()


def finish_test():
    if ARGS.loop and not ARGS.nowait:
        wait_sec = random.randint(2, int(ARGS.max_wait_secs))
        progress_wait(wait_sec, label="Pause between loop iterations")


def parse_cli():
    parser = argparse.ArgumentParser(
        description="Traffic Generator with Rich UI and Reporting",
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS
    )

    suite_choices = [
        'all', 'ads', 'ai', 'bigfile', 'bgp', 'crawl', 'dlp', 'dns', 'ftp',
        'domain-check', 'http', 'https', 'icmp', 'ips', 'malware-agents', 'malware-download',
        'metasploit-check', 'netflix', 'nmap', 'ntp', 'phishing-domains',
        'pornography', 'snmp', 'ssh', 'squatting', 'url-response', 'virus', 'web-scanner',
    ]
    size_choices = ['S', 'M', 'L', 'XL']

    traffic_group = parser.add_argument_group('Traffic Generation Options')
    traffic_group.add_argument('--suite', type=str.lower, choices=suite_choices, default='all',
        help="Specify the test suite to run. Default: all")
    traffic_group.add_argument('--size', type=str.upper, choices=size_choices, default='M',
        help="Size/volume of tests (S/M/L/XL)")

    timing_group = parser.add_argument_group('Timing and Loop Options')
    timing_group.add_argument('--loop', action='store_true', help='Continuously loop the selected suite(s)')
    timing_group.add_argument('--max-wait-secs', type=int, default=20, help='Max pause between loop iterations')
    timing_group.add_argument('--nowait', action='store_true', help='No pause between tests when looping')

    specific_suite_group = parser.add_argument_group('Suite-Specific Options')
    specific_suite_group.add_argument('--crawl-start', default='https://data.commoncrawl.org',
        help='Initial URL for crawl suite')

    output_group = parser.add_argument_group('Output')
    output_group.add_argument('--json-out', default=None, help='Write machine-readable JSON results to this path')

    return parser.parse_args()


def build_testsuite():
    if ARGS.suite == 'all':
        testsuite = [
            bigfile, webcrawl, dig_random, bgp_peering, ftp_random,
            http_download_targz, http_download_zip, http_random,
            https_random, https_crawl, pornography_crawl, metasploit_check,
            malware_random, ai_https_random, ping_random, traceroute_random,
            snmp_random, ips, ads_random, github_domain_check,
            github_phishing_domain_check, squatting_domains, speedtest_fast,
            web_scanner, nmap_1024os, nmap_cve, ntp_random, ssh_random,
            urlresponse_random, virus_sim, dlp_sim_https, malware_download,
        ]
        random.shuffle(testsuite)
        return testsuite

    mapping = {
        'bigfile': [bigfile],
        'crawl': [webcrawl],
        'dns': [dig_random],
        'bgp': [bgp_peering],
        'ftp': [ftp_random],
        'http': [http_download_targz, http_download_zip, http_random],
        'https': [https_random, https_crawl],
        'pornography': [pornography_crawl],
        'metasploit-check': [metasploit_check],
        'malware-agents': [malware_random],
        'ai': [ai_https_random],
        'icmp': [ping_random, traceroute_random],
        'snmp': [snmp_random],
        'ips': [ips],
        'ads': [ads_random],
        'domain-check': [github_domain_check],
        'phishing-domains': [github_phishing_domain_check],
        'squatting': [squatting_domains],
        'netflix': [speedtest_fast],
        'web-scanner': [web_scanner],
        'nmap': [nmap_1024os, nmap_cve],
        'ntp': [ntp_random],
        'ssh': [ssh_random],
        'url-response': [urlresponse_random],
        'virus': [virus_sim],
        'dlp': [dlp_sim_https],
        'malware-download': [malware_download],
    }
    return mapping.get(ARGS.suite, [https_random])


def print_summary(start_time):
    total_time = time.time() - start_time
    table = Table(title="Test Summary", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Test", style="bold")
    table.add_column("Status")
    table.add_column("Duration (s)", justify="right")
    for r in TEST_RESULTS:
        status_icon = "✅ pass" if r["status"] == "pass" else "❌ fail"
        table.add_row(r["name"], status_icon, f"{r['duration']:.2f}")
    console.print(table)
    console.print(Panel.fit(f"[bold]Total Run Time:[/] {time.strftime('%H:%M:%S', time.gmtime(total_time))}", border_style="blue"))

    if ARGS.json_out:
        payload = {
            "started_at": start_time,
            "ended_at": time.time(),
            "total_seconds": total_time,
            "results": TEST_RESULTS,
        }
        try:
            with open(ARGS.json_out, "w") as f:
                json.dump(payload, f, indent=2)
            console.print(f"[green]Wrote JSON results to[/] {ARGS.json_out}")
        except Exception as e:
            ui_warn(f"Failed writing JSON: {e}")


# ==========================
# Main
# ==========================

if __name__ == "__main__":
    try:
        STARTTIME = time.time()
        ARGS = parse_cli()
        WATCHDOG = watchdog(timeout_seconds=600)

        testsuite = build_testsuite()
        run_test(testsuite)

        print_summary(STARTTIME)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        ui_error(f"An error occurred: {e}\n{traceback.format_exc()}")
