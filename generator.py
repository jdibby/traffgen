#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generator with Rich UI:
- Consistent panels/banners instead of manual hashes
- Live progress bars where useful (downloads, waits)
- Status spinners for 'in progress' operations
- Structured startup summary
- Keeps your watchdog logic and arguments
- Drops Colorama/tqdm; uses Rich everywhere
"""

import os, sys, time, random, threading, argparse, subprocess, socket, ssl, traceback
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

# Disable SSL warning for self-signed certs (as in your original script)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context


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
    """Rich-based countdown wait used between looped tests."""
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
# Watchdog (unchanged logic)
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


# ==========================
# Tests
# ==========================

def bgp_peering():
    ui_banner("BGP Peering", "Starting gobgpd and configuring neighbors", "magenta")
    gobgpd_proc = None
    try:
        # Start gobgpd
        with ui_status("Starting gobgpd..."):
            try:
                gobgpd_proc = subprocess.Popen(
                    ["gobgpd", "--api-hosts", "127.0.0.1:50051"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                ui_ok("gobgpd started")
            except Exception as e:
                ui_warn(f"Failed to start gobgpd: {e}")
                gobgpd_proc = None

        # Wait for API
        def gobgp_wait_api(host, port, timeout=15):
            start = time.time()
            while time.time() - start < timeout:
                try:
                    with socket.create_connection((host, port), timeout=1):
                        return True
                except OSError:
                    time.sleep(0.3)
            return False

        # Configure BGP if up
        if gobgpd_proc and gobgp_wait_api("127.0.0.1", 50051, timeout=15):
            try:
                router_id = get_container_ip()
                with ui_status("Configuring global BGP instance..."):
                    subprocess.run(
                        ["gobgp", "-u", "127.0.0.1", "-p", "50051", "global", "as", "65555", "router-id", router_id],
                        check=True
                    )
                ui_ok(f"Global BGP configured (router-id: {router_id})")

                # Add neighbors
                for neighbor_ip in bgp_neighbors:
                    with ui_status(f"Adding neighbor {neighbor_ip}..."):
                        result = subprocess.run(
                            ["gobgp", "-u", "127.0.0.1", "-p", "50051", "neighbor", "add", neighbor_ip, "as", "65555"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE
                        )
                    if result.returncode != 0:
                        ui_warn(f"Error adding neighbor {neighbor_ip}: {result.stderr.decode().strip()}")
                    else:
                        ui_ok(f"Neighbor added: {neighbor_ip}")
            except Exception as e:
                ui_error(f"BGP configuration failed: {e}")
        else:
            ui_warn("gobgpd not ready — skipping BGP setup")
    except Exception as e:
        ui_error(f"[bgp_peering] unexpected exception error: {e}")
    finally:
        # Give it a moment and terminate
        with ui_status("Terminating gobgpd in 10s..."):
            time.sleep(10)
        if gobgpd_proc:
            gobgpd_proc.terminate()
            try:
                gobgpd_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                gobgpd_proc.kill()
        ui_ok("BGP Peering test complete")


def bigfile():
    url = 'http://ipv4.download.thinkbroadband.com/5GB.zip'
    ui_banner("Bigfile", f"Downloading 5GB ZIP: {url}")
    try:
        with requests.get(url, stream=True, verify=False, timeout=5) as response:
            response.raise_for_status()
            total = int(response.headers.get('content-length', 0))

            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Downloading[/]"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("download", total=total if total > 0 else None)
                for chunk in response.iter_content(chunk_size=1024 * 64):
                    if chunk:
                        progress.update(task, advance=len(chunk))
        ui_ok("Bigfile download test complete")
    except (requests.exceptions.RequestException, socket.error, ssl.SSLError, OSError) as e:
        ui_error(f"[bigfile] network/file exception error: {e}")
    except Exception as e:
        ui_error(f"[bigfile] unexpected exception error: {e}")


def _size_to_limits(size, s, m, l, xl):
    return {'S': s, 'M': m, 'L': l, 'XL': xl}.get(size, m)


def dig_random():
    ui_banner("DNS", "Random dig queries")
    try:
        target_ips = _size_to_limits(ARGS.size, 1, 2, 4, len(dns_endpoints))
        target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(dns_urls))

        random.shuffle(dns_endpoints)
        random.shuffle(dns_urls)

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]dig[/]"),
            MofNCompleteColumn(),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("dig", total=target_ips * target_urls)
            for i, ip in enumerate(dns_endpoints[:target_ips], 1):
                for j, url in enumerate(dns_urls[:target_urls], 1):
                    console.log(f"[bold]DNS:[/] {url} @ {ip} ({j}/{target_urls} on server {i}/{target_ips})")
                    cmd = f"dig {url} @{ip} +time=1 +tries=1 +short"
                    try:
                        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                    except Exception as e:
                        console.log(f"[yellow]dig error[/]: {e}")
                    finally:
                        progress.update(task, advance=1)
    except Exception as e:
        ui_error(f"[dig_random] unexpected error: {e}")


def ftp_random():
    ui_banner("FTP", "Rate-limited download via curl")
    try:
        target = _size_to_limits(ARGS.size, '1MB', '10MB', '100MB', '1GB')
        cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 5 -o /dev/null ftp://speedtest:speedtest@ftp.otenet.gr/test{target}.db"
        console.log(f"curl FTP {target}")
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=60)
        ui_ok("FTP test complete")
    except Exception as e:
        ui_error(f"[ftp_random] error: {e}")


def http_random():
    ui_banner("HTTP HEAD", "Random endpoints + DNS URLs")
    try:
        target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(http_endpoints + dns_urls))
        pool = http_endpoints[:] + dns_urls[:]
        random.shuffle(pool)

        with Progress(SpinnerColumn(), TextColumn("[cyan]HTTP[/]"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("http", total=target_urls)
            for count, url in enumerate(pool[:target_urls], 1):
                user_agent = random.choice(user_agents)
                cmd = f"curl -k -s --show-error --connect-timeout 5 -I -L -o /dev/null --max-time 5 -A '{user_agent}' {url}"
                console.log(f"HTTP ({count}/{target_urls}) {url} | UA: {user_agent[:50]}")
                try:
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=10)
                finally:
                    progress.update(task, advance=1)
        ui_ok("HTTP random complete")
    except Exception as e:
        ui_error(f"[http_random] unexpected exception error: {e}")


def http_download_zip():
    try:
        user_agent = random.choice(user_agents)
        targets = {'S': '15MB', 'M': '30MB', 'L': '100MB', 'XL': '1GB'}
        target = targets.get(ARGS.size, '30MB')
        url = f"https://link.testfile.org/{target}"
        ui_banner("HTTP Download (ZIP)", f"{target} from {url}")
        cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 5 -L -o /dev/null -A '{user_agent}' {url}"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=120)
        ui_ok("HTTP ZIP download complete")
    except Exception as e:
        ui_error(f"[http_download_zip] error: {e}")


def http_download_targz():
    ui_banner("HTTP Download (tar.gz)", "WordPress latest.tar.gz")
    try:
        cmd = "curl --limit-rate 3M -k --show-error --connect-timeout 5 -o /dev/null http://wordpress.org/latest.tar.gz"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=120)
        ui_ok("HTTP tar.gz download complete")
    except Exception as e:
        ui_error(f"[http_download_targz] error: {e}")


def web_scanner():
    timeout = _size_to_limits(ARGS.size, 60, 120, 180, 240)
    url = random.choice(webscan_endpoints)
    ui_banner("Nikto Web Scanner", f"Target: {url} (maxtime {timeout}s)")
    try:
        cmd = f"echo y | nikto -h '{url}' -maxtime '{timeout}' -timeout 1 -nointeractive"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=timeout + 30)
        ui_ok("Nikto scan complete")
    except Exception as e:
        ui_error(f"[web_scanner] error: {e}")


def https_random():
    ui_banner("HTTPS HEAD", "Random endpoints")
    try:
        target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(https_endpoints))
        random.shuffle(https_endpoints)

        with Progress(SpinnerColumn(), TextColumn("[cyan]HTTPS[/]"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("https", total=target_urls)
            for count, url in enumerate(https_endpoints[:target_urls], 1):
                user_agent = random.choice(user_agents)
                cmd = f"curl -k -s --show-error --connect-timeout 5 -I -o /dev/null --max-time 5 -A '{user_agent}' {url}"
                console.log(f"HTTPS ({count}/{target_urls}) {url}")
                try:
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=10)
                finally:
                    progress.update(task, advance=1)
        ui_ok("HTTPS random complete")
    except Exception as e:
        ui_error(f"[https_random] error: {e}")
        
def kyber_random():
    ui_banner("Kyber HEAD", "Random endpoints")
    try:
        target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(https_endpoints))
        random.shuffle(https_endpoints)

        with Progress(SpinnerColumn(), TextColumn("[cyan]HTTPS[/]"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("kyber", total=target_urls)
            for count, url in enumerate(https_endpoints[:target_urls], 1):
                user_agent = random.choice(user_agents)
                cmd = f"curl -k -s --curves X25519:X25519MLKEM768 --show-error --connect-timeout 5 -I -o /dev/null --max-time 2 --retry 0 -A '{user_agent}' {url}"
                console.log(f"HTTPS ({count}/{target_urls}) {url}")
                try:
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=10)
                finally:
                    progress.update(task, advance=1)
        ui_ok("Kyber random complete")
    except Exception as e:
        ui_error(f"[kyber_random] error: {e}")


def ai_https_random():
    ui_banner("AI HTTPS HEAD", "AI endpoints")
    try:
        target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(ai_endpoints))
        random.shuffle(ai_endpoints)

        with Progress(SpinnerColumn(), TextColumn("[cyan]AI HTTPS[/]"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("aihttps", total=target_urls)
            for count, url in enumerate(ai_endpoints[:target_urls], 1):
                user_agent = random.choice(user_agents)
                cmd = f"curl -k -s --show-error --connect-timeout 3 -I -o /dev/null --max-time 5 -A '{user_agent}' {url}"
                console.log(f"AI HTTPS ({count}/{target_urls}) {url}")
                try:
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=10)
                finally:
                    progress.update(task, advance=1)
        ui_ok("AI HTTPS random complete")
    except Exception as e:
        ui_error(f"[ai_https_random] error: {e}")


def ads_random():
    ui_banner("Ad Endpoints (HEAD)", "Ad/tracker endpoints")
    try:
        target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(ad_endpoints))
        random.shuffle(ad_endpoints)
        with Progress(SpinnerColumn(), TextColumn("[cyan]ADS[/]"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("ads", total=target_urls)
            for count, url in enumerate(ad_endpoints[:target_urls], 1):
                user_agent = random.choice(user_agents)
                cmd = f"curl -k -s --show-error --connect-timeout 3 -I -o /dev/null --max-time 5 -A '{user_agent}' {url}"
                console.log(f"ADS ({count}/{target_urls}) {url}")
                try:
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=10)
                finally:
                    progress.update(task, advance=1)
        ui_ok("Ads random complete")
    except Exception as e:
        ui_error(f"[ads_random] error: {e}")


def https_crawl():
    iterations = _size_to_limits(ARGS.size, 1, 3, 5, 10)
    target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(https_endpoints))
    ui_banner("HTTPS Crawl", f"{iterations} deep across {target_urls} starts")
    try:
        random.shuffle(https_endpoints)
        for count, url in enumerate(https_endpoints[:target_urls], 1):
            console.log(f"Crawl start ({count}/{target_urls}): {url}")
            scrape_iterative(url, iterations)
        ui_ok("HTTPS crawl complete")
    except Exception as e:
        ui_error(f"[https_crawl] error: {e}")


def pornography_crawl():
    iterations = _size_to_limits(ARGS.size, 1, 3, 5, 10)
    target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(pornography_endpoints))
    ui_banner("Pornography Crawl", f"{iterations} deep across {target_urls} starts", style="red")
    try:
        random.shuffle(pornography_endpoints)
        for count, url in enumerate(pornography_endpoints[:target_urls], 1):
            console.log(f"Crawl start ({count}/{target_urls}): {url}")
            scrape_iterative(url, iterations)
        ui_ok("Pornography crawl complete")
    except Exception as e:
        ui_error(f"[pornography_crawl] error: {e}")


def malware_random():
    ui_banner("Malware Agents (HEAD)", "Known malware domains (safe HEAD)")
    try:
        target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(malware_endpoints))
        random.shuffle(malware_endpoints)
        with Progress(SpinnerColumn(), TextColumn("[cyan]MALWARE AGENTS[/]"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("malagents", total=target_urls)
            for count, url in enumerate(malware_endpoints[:target_urls], 1):
                ua = random.choice(malware_user_agents)
                cmd = f"curl -k -s --show-error --connect-timeout 3 -I -o /dev/null --max-time 5 -A '{ua}' {url}"
                console.log(f"Malware Agent ({count}/{target_urls}) {url}")
                try:
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=10)
                finally:
                    progress.update(task, advance=1)
        ui_ok("Malware agent HEAD complete")
    except Exception as e:
        ui_error(f"[malware_random] error: {e}")


def ping_random():
    target_ips = _size_to_limits(ARGS.size, 1, 2, 5, len(icmp_endpoints))
    ui_banner("ICMP Ping", f"{target_ips} hosts")
    try:
        random.shuffle(icmp_endpoints)
        with Progress(SpinnerColumn(), TextColumn("[cyan]PING[/]"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("ping", total=target_ips)
            for count, ip in enumerate(icmp_endpoints[:target_ips], 1):
                cmd = f"ping -c2 -i1 -s64 -W1 -w2 {ip}"
                console.log(f"Ping ({count}/{target_ips}) {ip}")
                try:
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=10)
                finally:
                    progress.update(task, advance=1)
        ui_ok("Ping complete")
    except Exception as e:
        ui_error(f"[ping_random] error: {e}")


def metasploit_check():
    ui_banner("Metasploit Checks", "Running .rc files")
    try:
        ms_checks = _size_to_limits(ARGS.size, 1, 3, 5, 7)
        rc_dir = '/opt/metasploit-framework/ms_checks/checks'
        rc_files = [f for f in os.listdir(rc_dir) if f.endswith('.rc')]
        random.shuffle(rc_files)
        rc_files = rc_files[:ms_checks]

        with Progress(SpinnerColumn(), TextColumn("[cyan]MSF[/]"), MofNCompleteColumn(), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("msf", total=len(rc_files))
            for idx, rc in enumerate(rc_files, 1):
                cmd = f"msfconsole -q -r '{os.path.join(rc_dir, rc)}'"
                console.log(f"MSF ({idx}/{len(rc_files)}): {rc}")
                try:
                    subprocess.run(cmd, shell=True)
                finally:
                    progress.update(task, advance=1)
        ui_ok("Metasploit checks complete")
    except Exception as e:
        ui_error(f"[metasploit_check] error: {e}")


def snmp_random():
    target_ips = _size_to_limits(ARGS.size, 1, 2, 5, len(snmp_endpoints))
    ui_banner("SNMP Walk", f"{target_ips} hosts")
    try:
        random.shuffle(snmp_endpoints)
        random.shuffle(snmp_strings)
        with Progress(SpinnerColumn(), TextColumn("[cyan]SNMP[/]"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("snmp", total=target_ips)
            for idx, ip in enumerate(snmp_endpoints[:target_ips], 1):
                community = snmp_strings[idx % len(snmp_strings)]
                cmd = f"snmpwalk -v2c -t1 -r1 -c {community} {ip} 1.3.6"
                console.log(f"SNMP ({idx}/{target_ips}) {ip} community={community}")
                try:
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=15)
                finally:
                    progress.update(task, advance=1)
        ui_ok("SNMP complete")
    except Exception as e:
        ui_error(f"[snmp_random] error: {e}")


def traceroute_random():
    target_ips = _size_to_limits(ARGS.size, 1, 2, 5, len(icmp_endpoints))
    ui_banner("Traceroute", f"{target_ips} hosts")
    try:
        random.shuffle(icmp_endpoints)
        with Progress(SpinnerColumn(), TextColumn("[cyan]TRACEROUTE[/]"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("trace", total=target_ips)
            for idx, ip in enumerate(icmp_endpoints[:target_ips], 1):
                cmd = f"traceroute {ip} -w1 -q1 -m5"
                console.log(f"Traceroute ({idx}/{target_ips}) {ip}")
                try:
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=30)
                finally:
                    progress.update(task, advance=1)
        ui_ok("Traceroute complete")
    except Exception as e:
        ui_error(f"[traceroute_random] error: {e}")

def speedtest_fast():
    try:
        # Map size -> duration
        if ARGS.size == 'S':
            duration = 1
        elif ARGS.size == 'M':
            duration = 2
        elif ARGS.size == 'L':
            duration = 3
        elif ARGS.size == 'XL':
            duration = 4
        else:
            duration = 2

        timeout_per_test = 20
        console = Console(highlight=False)

        console.print(Panel.fit("Netflix Fast.com\nRunning fastcli tests", 
                                title="Speed Test", border_style="green"))

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]FAST.com[/]"),
            MofNCompleteColumn(),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("fast", total=duration)

            for i in range(1, duration + 1):
                console.log(f"Starting Fast.com test {i}/{duration} (timeout {timeout_per_test}s)")
                try:
                    result = subprocess.run(
                        "python3 -m fastcli",
                        shell=True,
                        check=True,
                        timeout=timeout_per_test,
                        capture_output=True,
                        text=True
                    )
                    console.log(f"[green]Test {i} completed successfully.[/]")
                    if result.stdout.strip():
                        console.log(f"stdout:\n{result.stdout.strip()[:400]}")
                    if result.stderr.strip():
                        console.log(f"stderr:\n{result.stderr.strip()[:400]}")
                except subprocess.TimeoutExpired:
                    console.log(f"[yellow]Test {i} timed out after {timeout_per_test}s.[/]")
                except subprocess.CalledProcessError as e:
                    console.log(f"[red]Test {i} failed: {e}[/]")
                    if e.stdout:
                        console.log(f"stdout:\n{e.stdout.strip()[:400]}")
                    if e.stderr:
                        console.log(f"stderr:\n{e.stderr.strip()[:400]}")
                except Exception as e:
                    console.log(f"[red]Unexpected error during test {i}: {e}[/]")

                progress.update(task, advance=1)

        console.print("[bold green]All Fast.com tests attempted.[/]")
    except (ssl.SSLError, socket.error) as e:
        print(f"[speedtest_fast] network/ssl exception error: {e}")
    except Exception as e:
        print(f"[speedtest_fast] unexpected exception error: {e}")


def nmap_1024os():
    target_ips = _size_to_limits(ARGS.size, 1, 2, 5, len(nmap_endpoints))
    ui_banner("Nmap 1-1024", f"{target_ips} hosts")
    try:
        random.shuffle(nmap_endpoints)
        for idx, ip in enumerate(nmap_endpoints[:target_ips], 1):
            cmd = ('nmap -Pn -p 1-1024 %s -T4 --max-retries 0 --max-parallelism 2 '
                   '--randomize-hosts --host-timeout 1m --script-timeout 1m '
                   '--script-args http.useragent="Mozilla/5.0" -debug') % ip
            console.log(f"Nmap 1-1024 ({idx}/{target_ips}) {ip}")
            subprocess.run(cmd, shell=True)
        ui_ok("Nmap 1-1024 complete")
    except Exception as e:
        ui_error(f"[nmap_1024os] error: {e}")


def nmap_cve():
    target_ips = _size_to_limits(ARGS.size, 1, 2, 5, len(nmap_endpoints))
    ui_banner("Nmap CVE (scripts)", f"{target_ips} hosts")
    try:
        random.shuffle(nmap_endpoints)
        for idx, ip in enumerate(nmap_endpoints[:target_ips], 1):
            cmd = ('nmap -sV --script=ALL %s -T4 --max-retries 0 --max-parallelism 2 '
                   '--randomize-hosts --host-timeout 1m --script-timeout 1m '
                   '--script-args http.useragent="Mozilla/5.0" -debug') % ip
            console.log(f"Nmap CVE ({idx}/{target_ips}) {ip}")
            subprocess.run(cmd, shell=True)
        ui_ok("Nmap CVE complete")
    except Exception as e:
        ui_error(f"[nmap_cve] error: {e}")


def ntp_random():
    target_urls = _size_to_limits(ARGS.size, 1, 2, 5, len(ntp_endpoints))
    ui_banner("NTP (UDP/123)", f"{target_urls} servers")
    try:
        random.shuffle(ntp_endpoints)
        for idx, url in enumerate(ntp_endpoints[:target_urls], 1):
            cmd = f"(printf '\\x1b'; head -c 47 < /dev/zero) | nc -u -w1 {url} 123"
            console.log(f"NTP ({idx}/{target_urls}) {url}")
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        ui_ok("NTP complete")
    except Exception as e:
        ui_error(f"[ntp_random] error: {e}")


def ssh_random():
    target_ips = _size_to_limits(ARGS.size, 1, 2, 5, len(ssh_endpoints))
    ui_banner("SSH Connect", f"{target_ips} hosts (non-interactive)")
    try:
        random.shuffle(ssh_endpoints)
        for idx, ip in enumerate(ssh_endpoints[:target_ips], 1):
            cmd = f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 {ip}"
            console.log(f"SSH ({idx}/{target_ips}) {ip}")
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=5)
        ui_ok("SSH test complete")
    except Exception as e:
        ui_error(f"[ssh_random] error: {e}")


def urlresponse_random():
    target_urls = _size_to_limits(ARGS.size, 10, 20, 50, len(https_endpoints))
    ui_banner("HTTPS Response Time", f"{target_urls} URLs")
    try:
        random.shuffle(https_endpoints)
        with Progress(SpinnerColumn(), TextColumn("[cyan]RESP TIME[/]"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("resp", total=target_urls)
            for count, url in enumerate(https_endpoints[:target_urls], 1):
                try:
                    t = requests.get(url, timeout=3, verify=False).elapsed.total_seconds()
                    console.log(f"HTTPS ({count}/{target_urls}) {url} -> {t:.3f}s")
                except Exception:
                    console.log(f"[yellow]Skip[/] {url}")
                finally:
                    progress.update(task, advance=1)
        ui_ok("HTTPS response time test complete")
    except Exception as e:
        ui_error(f"[urlresponse_random] error: {e}")


def virus_sim():
    target_urls = _size_to_limits(ARGS.size, 1, 2, 3, len(virus_endpoints))
    ui_banner("Virus Simulation (downloads)", f"{target_urls} files")
    try:
        random.shuffle(virus_endpoints)
        for idx, url in enumerate(virus_endpoints[:target_urls], 1):
            cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 4 -o /dev/null {url}"
            console.log(f"Virus sim ({idx}/{target_urls}) {url}")
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=20)
        ui_ok("Virus simulation complete")
    except Exception as e:
        ui_error(f"[virus_sim] error: {e}")


def dlp_sim_https():
    target_urls = _size_to_limits(ARGS.size, 1, 2, 3, len(dlp_https_endpoints))
    ui_banner("DLP Simulation (HTTPS)", f"{target_urls} files")
    try:
        random.shuffle(dlp_https_endpoints)
        for idx, url in enumerate(dlp_https_endpoints[:target_urls], 1):
            cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 4 -o /dev/null {url}"
            console.log(f"DLP sim ({idx}/{target_urls}) {url}")
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=20)
        ui_ok("DLP HTTPS simulation complete")
    except Exception as e:
        ui_error(f"[dlp_sim_https] error: {e}")


def malware_download():
    target_urls = _size_to_limits(ARGS.size, 1, 2, 3, len(malware_files))
    ui_banner("Malware File Download (HTTPS)", f"{target_urls} files")
    try:
        random.shuffle(malware_files)
        for idx, url in enumerate(malware_files[:target_urls], 1):
            cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 4 -o /dev/null {url}"
            console.log(f"Malware file ({idx}/{target_urls}) {url}")
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=20)
        ui_ok("Malware file download complete")
    except Exception as e:
        ui_error(f"[malware_download] error: {e}")


def squatting_domains():
    target_domains = _size_to_limits(ARGS.size, 1, 2, 3, 4)
    ui_banner("Typosquatting Generator", f"{target_domains} base domains")
    try:
        random.shuffle(squatting_endpoints)
        for idx, url in enumerate(squatting_endpoints[:target_domains], 1):
            cmd = f"dnstwist --registered {url}"
            console.log(f"dnstwist ({idx}/{target_domains}) {url}")
            subprocess.run(cmd, shell=True)
        ui_ok("Squatting domains generation complete")
    except Exception as e:
        ui_error(f"[squatting_domains] error: {e}")


def webcrawl():
    iterations = _size_to_limits(ARGS.size, 10, 20, 50, 100)
    attempts = _size_to_limits(ARGS.size, 1, 3, 5, 10)
    ui_banner("Web Crawl", f"Start: {ARGS.crawl_start} | depth {iterations} | attempts {attempts}")
    try:
        for attempt in range(1, attempts + 1):
            console.log(f"Crawl attempt {attempt}/{attempts}")
            scrape_iterative(ARGS.crawl_start, iterations)
        ui_ok("Web crawl complete")
    except Exception as e:
        ui_error(f"[webcrawl] error: {e}")


def ips():
    ui_banner("IPS Trigger", "BlackSun user-agent to testmyids.com")
    try:
        cmd = "curl -k -s --show-error --connect-timeout 3 -I --max-time 5 -A BlackSun www.testmyids.com"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=10)
        ui_ok("IPS trigger complete")
    except Exception as e:
        ui_error(f"[ips] error: {e}")


# ==========================
# GitHub domain checks
# ==========================

def github_domain_check_download_file(url, local_filename):
    console.log(f"Download {url} -> {local_filename}")
    try:
        with requests.get(url, stream=True, verify=False, timeout=5) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        return True
    except Exception as e:
        ui_error(f"Domain list download failed: {e}")
        return False

def _github_read_and_probe(local_filename, num_random_domains=10):
    console.log(f"Reading domains from: {local_filename}")
    try:
        with open(local_filename, 'r', encoding='utf-8') as f:
            all_domains = f.readlines()
        valid = [d.strip() for d in all_domains if d.strip() and not d.strip().startswith('#')]
    except Exception as e:
        ui_error(f"Read file failed: {e}")
        return

    if len(valid) < num_random_domains:
        selected = valid
    else:
        selected = random.sample(valid, num_random_domains)

    with Progress(SpinnerColumn(), TextColumn("[cyan]Query[/]"), MofNCompleteColumn(), BarColumn(), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("probe", total=len(selected))
        for i, domain in enumerate(selected, 1):
            url = f"https://{domain}"
            try:
                r = requests.get(url, timeout=1, verify=False, allow_redirects=True)
                console.log(f"[{i}/{len(selected)}] {url} -> {r.status_code}")
            except Exception as e:
                console.log(f"[{i}/{len(selected)}] {url} -> error ({e.__class__.__name__})")
            finally:
                progress.update(task, advance=1)

def github_domain_check():
    ui_banner("GitHub Domain Check", "Hagezi domain blocklist sample")
    try:
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt"
        local = "git-domains-list"
        if not os.path.exists(local):
            if not github_domain_check_download_file(url, local):
                ui_error("Failed to download domain list")
                return
        else:
            console.log(f"Using cached list: {local}")
        _github_read_and_probe(local, num_random_domains=10)
        ui_ok("GitHub domain check complete")
    except Exception as e:
        ui_error(f"[github_domain_check] error: {e}")


def github_phishing_domain_check():
    ui_banner("GitHub Phishing Domain Check", "Active phishing list")
    try:
        url = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt"
        local = "git-phishing-list"
        if not os.path.exists(local):
            if not github_domain_check_download_file(url, local):
                ui_error("Failed to download phishing list")
                return
        else:
            console.log(f"Using cached list: {local}")
        _github_read_and_probe(local, num_random_domains=10)
        ui_ok("GitHub phishing domain check complete")
    except Exception as e:
        ui_error(f"[github_phishing_domain_check] error: {e}")


# ==========================
# Scraper helpers (mostly same logic, nicer logs)
# ==========================

def replace_all_endpoints(url):
    console.log(f"Replacing endpoints.py with {url}")
    response = urllib.request.urlopen(url)
    data = response.read()
    text = data.decode('utf-8')
    with open('endpoints.py', 'w') as f:
        f.write(text)
    ui_ok("endpoints.py updated")

def scrape_single_link(url):
    time.sleep(random.uniform(0.2, 2))
    user_agent = random.choice(user_agents)
    console.log(f"Visiting: {url} | UA: {user_agent[:60]}")

    try:
        response = requests.get(
            url=url,
            timeout=2,
            allow_redirects=True,
            headers={'User-Agent': user_agent},
            verify=False
        )
        response.raise_for_status()
        response.encoding = response.apparent_encoding or 'utf-8'
        html = response.text
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return None
        ui_warn(f"HTTP error for {url}: {e}")
        return None
    except (requests.exceptions.SSLError, requests.exceptions.Timeout, requests.exceptions.TooManyRedirects) as e:
        ui_warn(f"Request issue for {url}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        ui_warn(f"General failure for {url}: {e}")
        return None

    soup = BeautifulSoup(html, 'html.parser')
    all_links = soup.find_all("a")
    random.shuffle(all_links)

    for link in all_links:
        href = link.get('href')
        if not href or '#' in href:
            continue
        if href.startswith('//') or href.startswith('/'):
            resolved = urljoin(url, href)
            console.log(f"Found: {resolved}")
            return resolved
        elif href.startswith('http'):
            console.log(f"Found: {href}")
            return href

    console.log("No Links Found")
    return None

def scrape_iterative(base_url, iterations=3):
    next_link = scrape_single_link(base_url)
    for _ in range(iterations):
        if next_link:
            next_link = scrape_single_link(next_link)
        else:
            break


# ==========================
# Runner / CLI
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

    time.sleep(0.5)

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
    if ARGS.loop:
        if not ARGS.nowait:
            max_wait = int(ARGS.max_wait_secs)
            wait_sec = random.randint(2, max_wait)
            progress_wait(wait_sec, label="Pause between loop iterations")
        console.print("")  # spacer


def parse_cli():
    parser = argparse.ArgumentParser(
        description="""Traffic Generator with Rich UI
A versatile tool for simulating various network traffic types with a clean terminal UI.
""",
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS
    )

    suite_choices = [
        'all', 'ads', 'ai', 'bigfile', 'bgp', 'crawl', 'dlp', 'dns', 'ftp',
        'domain-check', 'http', 'https', 'kyber', 'icmp', 'ips', 'malware-agents', 'malware-download',
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

    return parser.parse_args()


def build_testsuite():
    if ARGS.suite == 'all':
        testsuite = [
            webcrawl,
            dig_random,
            bgp_peering,
            ftp_random,
            http_download_targz,
            http_download_zip,
            http_random,
            https_random,
            kyber_random,
            https_crawl,
            pornography_crawl,
            metasploit_check,
            malware_random,
            ai_https_random,
            ping_random,
            traceroute_random,
            snmp_random,
            ips,
            ads_random,
            github_domain_check,
            github_phishing_domain_check,
            squatting_domains,
            speedtest_fast,
            web_scanner,
            nmap_1024os,
            nmap_cve,
            ntp_random,
            ssh_random,
            urlresponse_random,
            virus_sim,
            dlp_sim_https,
            malware_download,
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
        'kyber': [kyber_random],
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

        ENDTIME = time.time() - STARTTIME
        console.print(Panel.fit(f"[bold]Total Run Time:[/] {time.strftime('%H:%M:%S', time.gmtime(ENDTIME))}", border_style="blue"))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        ui_error(f"An error occurred: {e}\n{traceback.format_exc()}")
