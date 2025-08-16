#!/usr/bin/env python3
"""
Generator with Rich Progress UI, per-test timing, and final summaries.
- Live Progress UI using Rich
- Captures status and duration per test
- Prints an end-of-run summary table
- Writes JSON and Markdown summary artifacts
- Keeps your watchdog logic and arguments
- Silences old Colorama banners without requiring colorama
"""

import time, os, sys, argparse, random, threading, signal, urllib.request, urllib3, requests, runpy, socket, ssl, subprocess, traceback
from bs4 import BeautifulSoup
from time import sleep
from urllib.parse import urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from endpoints import *

# ---- Rich UI imports ----
from dataclasses import dataclass, asdict
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.panel import Panel

console = Console()

# ---- Disable SSL warning for self-signed certs ----
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context

# ---- Colorama shim (no-op) so legacy print lines don't break even if present in functions ----
class _NoColor:
    def __getattr__(self, name):
        return ""
Fore = Back = Style = _NoColor()

# ---- Watchdog used for restarting container if no activity is detected ----
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
                console.print("[bold red][WATCHDOG][/bold red] No activity detected. Exiting to force container restart...")
                os._exit(1)
            time.sleep(1)

# ---- Grab container IP address ----
def get_container_ip():
    try:
        result = subprocess.run(
            ["ip", "route", "get", "1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        output = result.stdout.decode()
        return output.split("src")[1].split()[0]
    except Exception as e:
        console.print(f"[yellow]Failed to determine container IP:[/] {e}")
        return "127.0.0.1"

# ---- Result model + UI helpers ----
@dataclass
class TestResult:
    name: str
    start_ts: float
    end_ts: float
    duration_s: float
    status: str          # "ok" | "error" | "skipped"
    error: str = ""      # short message if error

RUN_RESULTS: list[TestResult] = []

class SuiteUI:
    """Thin wrapper around rich.Progress to show per-test progress and capture results."""
    def __init__(self):
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}[/]"),
            BarColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            expand=True,
            transient=True  # clears the progress display when it finishes
        )

    def __enter__(self):
        self.progress.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.progress.__exit__(exc_type, exc, tb)

    def run_test_callable(self, func):
        console.line()
        fname = getattr(func, "__name__", str(func))
        task_id = self.progress.add_task(f"{fname}", total=100, start=False)

        start = time.time()
        status = "ok"
        err_msg = ""

        self.progress.start_task(task_id)
        self.progress.update(task_id, advance=5)

        try:
            func()
        except KeyboardInterrupt:
            raise
        except Exception as e:
            status = "error"
            err_msg = f"{type(e).__name__}: {e}".strip()[:300]
        finally:
            self.progress.update(task_id, advance=95)
            end = time.time()
            RUN_RESULTS.append(TestResult(
                name=fname,
                start_ts=start,
                end_ts=end,
                duration_s=round(end - start, 3),
                status=status,
                error=err_msg
            ))
            console.line()

def _write_summary_files(suite_name: str, started_at: float):
    """Write JSON and Markdown summaries to disk."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"run_summary_{suite_name}_{stamp}"

    # JSON
    try:
        import json
        with open(f"{base}.json", "w") as f:
            json.dump([asdict(r) for r in RUN_RESULTS], f, indent=2)
        console.print(f"[green]Saved JSON summary → {base}.json[/]")
    except Exception as e:
        console.print(f"[yellow]Could not write JSON summary: {e}[/]")

    # Markdown
    try:
        lines = [
            f"# Run Summary: {suite_name}",
            "",
            f"**Started:** {datetime.fromtimestamp(started_at).isoformat()}",
            f"**Tests:** {len(RUN_RESULTS)}",
            "",
            "| Test | Status | Duration (s) | Error |",
            "|---|---|---:|---|",
        ]
        for r in RUN_RESULTS:
            err = (r.error or "").replace("|", "\\|")
            lines.append(f"| `{r.name}` | {r.status} | {r.duration_s:.3f} | {err} |")
        with open(f"{base}.md", "w") as f:
            f.write("\n".join(lines) + "\n")
        console.print(f"[green]Saved Markdown summary → {base}.md[/]")
    except Exception as e:
        console.print(f"[yellow]Could not write Markdown summary: {e}[/]")

def _print_summary_table(total_runtime_s: float):
    ok = sum(1 for r in RUN_RESULTS if r.status == "ok")
    err = sum(1 for r in RUN_RESULTS if r.status == "error")
    skp = sum(1 for r in RUN_RESULTS if r.status == "skipped")

    table = Table(title="Test Summary", expand=True, show_lines=True)
    table.add_column("Test", style="bold")
    table.add_column("Status")
    table.add_column("Duration (s)", justify="right")
    table.add_column("Error (truncated)")

    for r in sorted(RUN_RESULTS, key=lambda x: x.duration_s, reverse=True):
        table.add_row(
            r.name,
            ("✅ ok" if r.status == "ok" else "❌ error" if r.status == "error" else "⏭️ skipped"),
            f"{r.duration_s:.3f}",
            (r.error[:120] + "…") if len(r.error) > 120 else r.error
        )

    console.rule("[bold green]Run Complete")
    console.line()
    console.print(table)
    console.line()
    console.print(
        Panel(
            f"[green]OK:[/green] {ok}   [red]ERRORS:[/red] {err}   [yellow]SKIPPED:[/yellow] {skp}   "
            f"[cyan]Total Runtime:[/cyan] {time.strftime('%H:%M:%S', time.gmtime(total_runtime_s))}",
            title="Totals",
            border_style="green",
            expand=False
        )
    )

def banner(title: str):
    console.line()
    console.rule(f"[bold]{title}[/]")
    console.line()

def spacer(n: int = 1):
    for _ in range(max(1, n)):
        console.line()

# ------------------------
# Original test functions
# (left mostly intact; banners are subdued by the color shim)
# ------------------------

# Continue with the rest of the generator (always runs even if BGP initialization fails)
def bgp_peering():
    gobgpd_proc = None
    try:
        banner("BGP Peering")
        # Start gobgpd in the background
        try:
            gobgpd_proc = subprocess.Popen([
                "gobgpd", "--api-hosts", "127.0.0.1:50051"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            console.log("Started gobgpd")
        except Exception as e:
            console.print(f"[yellow]Failed to start gobgpd:[/] {e}")
            gobgpd_proc = None  # keep going

        # Wait for gobgpd API to come up
        def gobgp_wait_api(host, port, timeout=10):
            start = time.time()
            while time.time() - start < timeout:
                try:
                    with socket.create_connection((host, port), timeout=1):
                        return True
                except OSError:
                    time.sleep(0.5)
            return False

        # Configure BGP
        if gobgpd_proc and gobgp_wait_api("127.0.0.1", 50051, timeout=15):
            try:
                console.log("Configuring global BGP instance...")
                router_id = get_container_ip()
                console.log(f"Using container IP {router_id} as BGP router-id")
                subprocess.run([
                    "gobgp", "-u", "127.0.0.1", "-p", "50051",
                    "global", "as", "65555", "router-id", router_id
                ], check=True)

                # Add neighbors using gobgp CLI
                for neighbor_ip in bgp_neighbors:
                    console.log(f"Adding BGP neighbor: {neighbor_ip}")
                    result = subprocess.run([
                        "gobgp", "-u", "127.0.0.1", "-p", "50051",
                        "neighbor", "add", neighbor_ip, "as", "65555"
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                    if result.returncode != 0:
                        console.print(f"[yellow]Error adding neighbor {neighbor_ip}:[/]\n{result.stderr.decode().strip()}")
                    else:
                        console.log(f"Successfully added neighbor {neighbor_ip}")
            except Exception as e:
                console.print(f"[red]BGP configuration failed:[/] {e}")
        else:
            console.print("[yellow]WARNING:[/] gobgpd not ready — skipping BGP setup")
    except (subprocess.SubprocessError, FileNotFoundError, TimeoutError) as e:
        console.print(f"[red][bgp_peering] subprocess exception error:[/] {e}")
    except (socket.error, OSError) as e:
        console.print(f"[red][bgp_peering] socket/os exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][bgp_peering] unexpected exception error:[/] {e}")

    # Wait then terminate
    console.print("Waiting 10 seconds before terminating gobgpd...")
    time.sleep(10)
    if gobgpd_proc:
        gobgpd_proc.terminate()
        try:
            gobgpd_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            gobgpd_proc.kill()

# Bigfile download via http

# Bigfile download via http (Rich progress; no legacy banners)
def bigfile():
    try:
        url = 'http://ipv4.download.thinkbroadband.com/5GB.zip'
        response = requests.get(url, stream=True, timeout=10)
        total_size = int(response.headers.get('content-length', 0))

        console.line()
        console.rule("[bold cyan]Bigfile Download[/]")

        if total_size > 0:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold]Downloading 5GB.zip[/]"),
                BarColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                transient=False,
                expand=True
            ) as prog:
                task = prog.add_task("download", total=total_size)
                for chunk in response.iter_content(chunk_size=1024 * 64):
                    if chunk:
                        prog.update(task, advance=len(chunk))
        else:
            # Unknown size; show spinner and count downloaded bytes
            downloaded = 0
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold]Downloading 5GB.zip (streaming)[/]"),
                TimeElapsedColumn(),
                transient=False,
                expand=True
            ) as prog:
                task = prog.add_task("download", total=None)
                for chunk in response.iter_content(chunk_size=1024 * 64):
                    if chunk:
                        downloaded += len(chunk)
                        # No total to advance against; just keep spinner alive
                        prog.refresh()
        console.line()
    except (requests.exceptions.RequestException, socket.error, ssl.SSLError, OSError) as e:
        console.print(f"[red][bigfile] network/file exception error:[/] {e}")
        console.line()
    except Exception as e:
        console.print(f"[red][bigfile] unexpected exception error:[/] {e}")
        console.line()

# DNS Test suites
def dig_random():
    try:
        if ARGS.size == 'S':
            target_ips = 1
            target_urls = 10
        elif ARGS.size == 'M':
            target_ips = 2
            target_urls = 20
        elif ARGS.size == 'L':
            target_ips = 4
            target_urls = 50
        elif ARGS.size == 'XL':
            target_ips = len(dns_endpoints)
            target_urls = len(dns_urls)
        random.shuffle(dns_endpoints)
        for count_ips, ip in enumerate(dns_endpoints):
            if count_ips < target_ips:
                random.shuffle(dns_urls)
                for count_urls, url in enumerate(dns_urls):
                    if count_urls < target_urls:
                        cmd = "dig %s @%s +time=1" % (url, ip)
                        banner(f"DNS: Query {url} ({count_urls+1}/{target_urls}) against {ip} ({count_ips+1}/{target_ips})")
                        subprocess.call(cmd, shell=True)
        console.line()
                        time.sleep(0.25)
    except subprocess.CalledProcessError as e:
        console.print(f"[red][dig_random] dig exit {e.returncode}:[/] {e.stderr or e.stdout or e}")
    except subprocess.TimeoutExpired as e:
        console.print(f"[red][dig_random] dig timed out:[/] {e}")
    except (FileNotFoundError, PermissionError) as e:
        console.print(f"[red][dig_random] dig not runnable:[/] {e}")
    except (socket.timeout, socket.gaierror, OSError) as e:
        console.print(f"[red][dig_random] network/os error:[/] {e}")
    except UnicodeDecodeError as e:
        console.print(f"[red][dig_random] decode error:[/] {e}")
    except ValueError as e:
        console.print(f"[red][dig_random] parse error:[/] {e}")
    except Exception as e:
        console.print(f"[red][dig_random] unexpected error:[/] {e}")

# FTP Test suites
def ftp_random():
    try:
        if ARGS.size == 'S':
            target = '1MB'
        elif ARGS.size == 'M':
            target = '10MB'
        elif ARGS.size == 'L':
            target = '100MB'
        elif ARGS.size == 'XL':
            target = '1GB'
        cmd = 'curl --limit-rate 3M -k --show-error --connect-timeout 5 -o /dev/null ftp://speedtest:speedtest@ftp.otenet.gr/test' + target + '.db'
        banner(f"FTP: Download {target} DB File")
        subprocess.call(cmd, shell=True)
        console.line()
    except subprocess.CalledProcessError as e:
        msg = e.stderr or e.stdout or str(e)
        console.print(f"[red][ftp_random] curl exit {e.returncode}:[/] {msg}")
    except subprocess.TimeoutExpired as e:
        console.print(f"[red][ftp_random] curl timed out:[/] {e}")
    except (FileNotFoundError, PermissionError) as e:
        console.print(f"[red][ftp_random] curl not runnable:[/] {e}")
    except (socket.timeout, socket.gaierror, OSError) as e:
        console.print(f"[red][ftp_random] network/os error:[/] {e}")
    except UnicodeDecodeError as e:
        console.print(f"[red][ftp_random] decode error:[/] {e}")
    except ValueError as e:
        console.print(f"[red][ftp_random] parse error:[/] {e}")
    except Exception as e:
        console.print(f"[red][ftp_random] unexpected error:[/] {e}")

# HTTP Test suites
def http_random():
    try:
        if ARGS.size == 'S':
            target_urls = 10
        elif ARGS.size == 'M':
            target_urls = 20
        elif ARGS.size == 'L':
            target_urls = 50
        elif ARGS.size == 'XL':
            target_urls = len(http_endpoints + dns_urls)
        random.shuffle(http_endpoints)
        random.shuffle(dns_urls)
        for count_urls, url in enumerate(http_endpoints + dns_urls):
            if count_urls < target_urls:
                random.shuffle(user_agents)
                user_agent = user_agents[0]
                cmd = f"curl -k -s --show-error --connect-timeout 5 -I -L -o /dev/null --max-time 5 -A '{user_agent}' {url}"
                banner(f"HTTP ({count_urls+1}/{target_urls}): {url} | Agent: {user_agent}")
                subprocess.call(cmd, shell=True)
        console.line()
    except (requests.exceptions.RequestException, socket.error, ssl.SSLError) as e:
        console.print(f"[red][http_random] http exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][http_random] unexpected exception error:[/] {e}")

# HTTP downloads
def http_download_zip():
    try:
        random.shuffle(user_agents)
        user_agent = user_agents[0]
        if ARGS.size == 'S':
            target = '15MB'
            cmd = f"curl --limit-rate 3M -k  --show-error --connect-timeout 5 -L -o /dev/null -A '{user_agent}' https://link.testfile.org/{target}"
        elif ARGS.size == 'M':
            target = '30MB'
            cmd = f"curl --limit-rate 3M -k  --show-error --connect-timeout 5 -L -o /dev/null -A '{user_agent}' https://link.testfile.org/{target}"
        elif ARGS.size == 'L':
            target = '100MB'
            cmd = f"curl --limit-rate 3M -k  --show-error --connect-timeout 5 -L -o /dev/null -A '{user_agent}' https://link.testfile.org/{target}"
        elif ARGS.size == 'XL':
            target = '1GB'
            cmd = f"curl --limit-rate 3M -k  --show-error --connect-timeout 5 -L -o /dev/null -A '{user_agent}' https://link.testfile.org/{target}"
        banner(f"HTTP: Download {target} ZIP File | Agent: {user_agent}")
        subprocess.call(cmd, shell=True)
        console.line()
    except (requests.exceptions.RequestException, socket.error, ssl.SSLError) as e:
        console.print(f"[red][http_download_zip] http exception error:[/] {e}")
    except (OSError, IOError) as e:
        console.print(f"[red][http_download_zip] file I/O exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][http_download_zip] unexpected exception error:[/] {e}")

# HTTP downloads of targz files
def http_download_targz():
    try:
        cmd = 'curl --limit-rate 3M -k  --show-error --connect-timeout 5 -o /dev/null http://wordpress.org/latest.tar.gz'
        banner("HTTP: Download Wordpress File")
        subprocess.call(cmd, shell=True)
        console.line()
    except (requests.exceptions.RequestException, socket.error, ssl.SSLError) as e:
        console.print(f"[red][http_download_targz] http exception error:[/] {e}")
    except (OSError, IOError) as e:
        console.print(f"[red][http_download_targz] file I/O exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][http_download_targz] unexpected exception error:[/] {e}")

# Nikto Scans
def web_scanner():
    try:
        if ARGS.size == 'S':
            timeout = 60
        elif ARGS.size == 'M':
            timeout = 120
        elif ARGS.size == 'L':
            timeout = 180
        elif ARGS.size == 'XL':
            timeout = 240

        random.shuffle(webscan_endpoints)
        url = webscan_endpoints[0]

        cmd = f"echo y | nikto -h '{url}' -maxtime '{timeout}' -timeout 1 -nointeractive"
        banner(f"Nikto Scanning: {url} (maxtime {timeout}s)")
        subprocess.call(cmd, shell=True)
        console.line()
    except (subprocess.SubprocessError, FileNotFoundError, TimeoutError) as e:
        console.print(f"[red][web_scanner] subprocess exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][web_scanner] unexpected exception error:[/] {e}")

# HTTPS Test suites
def https_random():
    try:
        if ARGS.size == 'S':
            target_urls = 10
        elif ARGS.size == 'M':
            target_urls = 20
        elif ARGS.size == 'L':
            target_urls = 50
        elif ARGS.size == 'XL':
            target_urls = len(https_endpoints)
        random.shuffle(https_endpoints)
        for count_urls, url in enumerate(https_endpoints):
            if count_urls < target_urls:
                random.shuffle(user_agents)
                user_agent = user_agents[0]
                cmd = f"curl -k -s --show-error --connect-timeout 5 -I -o /dev/null --max-time 5 -A '{user_agent}' {url}"
                banner(f"HTTPS ({count_urls+1}/{target_urls}): {url} | Agent: {user_agent}")
                subprocess.call(cmd, shell=True)
        console.line()
    except (requests.exceptions.RequestException, ssl.SSLError, socket.error) as e:
        console.print(f"[red][https_random] https exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][https_random] unexpected exception error:[/] {e}")

# AI Test suite
def ai_https_random():
    try:
        if ARGS.size == 'S':
            target_urls = 10
        elif ARGS.size == 'M':
            target_urls = 20
        elif ARGS.size == 'L':
            target_urls = 50
        elif ARGS.size == 'XL':
            target_urls = len(ai_endpoints)
        random.shuffle(ai_endpoints)
        for count_urls, url in enumerate(ai_endpoints):
            if count_urls < target_urls:
                random.shuffle(user_agents)
                user_agent = user_agents[0]
                cmd = f"curl -k -s --show-error --connect-timeout 3 -I -o /dev/null --max-time 5 -A '{user_agent}' {url}"
                banner(f"AI URLs ({count_urls+1}/{target_urls}): {url} | Agent: {user_agent}")
                subprocess.call(cmd, shell=True)
        console.line()
    except (requests.exceptions.RequestException, ssl.SSLError, socket.error) as e:
        console.print(f"[red][ai_https_random] https exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][ai_https_random] unexpected exception error:[/] {e}")

# Test ad filtering
def ads_random():
    try:
        if ARGS.size == 'S':
            target_urls = 10
        elif ARGS.size == 'M':
            target_urls = 20
        elif ARGS.size == 'L':
            target_urls = 50
        elif ARGS.size == 'XL':
            target_urls = len(ad_endpoints)
        random.shuffle(ad_endpoints)
        for count_urls, url in enumerate(ad_endpoints):
            if count_urls < target_urls:
                random.shuffle(user_agents)
                user_agent = user_agents[0]
                cmd = f"curl -k -s --show-error --connect-timeout 3 -I -o /dev/null --max-time 5 -A '{user_agent}' {url}"
                banner(f"Ads URLs ({count_urls+1}/{target_urls}): {url} | Agent: {user_agent}")
                subprocess.call(cmd, shell=True)
        console.line()
    except (requests.exceptions.RequestException, socket.error, ssl.SSLError) as e:
        console.print(f"[red][ads_random] http exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][ads_random] unexpected exception error:[/] {e}")

# HTTPS crawl through URLs
def https_crawl():
    try:
        if ARGS.size == 'S':
            target_urls = 10
            iterations = 1
        elif ARGS.size == 'M':
            target_urls = 20
            iterations = 3
        elif ARGS.size == 'L':
            target_urls = 50
            iterations = 5
        elif ARGS.size == 'XL':
            target_urls = len(https_endpoints)
            iterations = 10
        random.shuffle(https_endpoints)
        for count_urls, url in enumerate(https_endpoints):
            if count_urls < target_urls:
                random.shuffle(user_agents)
                user_agent = user_agents[0]
                banner(f"Crawling HTTPS ({iterations} deep, site {count_urls+1}/{target_urls}) from {url} | Agent: {user_agent}")
                scrape_iterative(url, iterations)
        console.line()
    except (requests.exceptions.RequestException, ssl.SSLError, socket.error) as e:
        console.print(f"[red][https_crawl] https exception error:[/] {e}")
    except ValueError as e:
        console.print(f"[red][https_crawl] parse exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][https_crawl] unexpected exception error:[/] {e}")

# Pornography crawl through URLs
def pornography_crawl():
    try:
        if ARGS.size == 'S':
            target_urls = 10
            iterations = 1
        elif ARGS.size == 'M':
            target_urls = 20
            iterations = 3
        elif ARGS.size == 'L':
            target_urls = 50
            iterations = 5
        elif ARGS.size == 'XL':
            target_urls = len(pornography_endpoints)
            iterations = 10
        random.shuffle(pornography_endpoints)
        for count_urls, url in enumerate(pornography_endpoints):
            if count_urls < target_urls:
                random.shuffle(user_agents)
                user_agent = user_agents[0]
                banner(f"Crawling Pornography ({iterations} deep, site {count_urls+1}/{target_urls}) from {url} | Agent: {user_agent}")
                scrape_iterative(url, iterations)
        console.line()
    except (requests.exceptions.RequestException, ssl.SSLError, socket.error) as e:
        console.print(f"[red][pornography_crawl] http exception error:[/] {e}")
    except ValueError as e:
        console.print(f"[red][pornography_crawl] parse exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][pornography_crawl] unexpected exception error:[/] {e}")

# Malware Test suites
def malware_random():
    try:
        if ARGS.size == 'S':
            target_urls = 10
        elif ARGS.size == 'M':
            target_urls = 20
        elif ARGS.size == 'L':
            target_urls = 50
        elif ARGS.size == 'XL':
            target_urls = len(malware_endpoints)
        random.shuffle(malware_endpoints)
        for count_urls, url in enumerate(malware_endpoints):
            if count_urls < target_urls:
                random.shuffle(malware_user_agents)
                malware_user_agent = malware_user_agents[0]
                cmd = f"curl -k -s --show-error --connect-timeout 3 -I -o /dev/null --max-time 5 -A '{malware_user_agent}' {url}"
                banner(f"Malware Site ({count_urls+1}/{target_urls}): {url} | Agent: {malware_user_agent}")
                subprocess.call(cmd, shell=True)
        console.line()
    except (requests.exceptions.RequestException, ssl.SSLError, socket.error) as e:
        console.print(f"[red][malware_random] http exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][malware_random] unexpected exception error:[/] {e}")

# ICMP Test
def ping_random():
    try:
        if ARGS.size == 'S':
            target_ips = 1
        elif ARGS.size == 'M':
            target_ips = 2
        elif ARGS.size == 'L':
            target_ips = 5
        elif ARGS.size == 'XL':
            target_ips = len(icmp_endpoints)
        random.shuffle(icmp_endpoints)
        for count_ips, ip in enumerate(icmp_endpoints):
            if count_ips < target_ips:
                cmd = "ping -c2 -i1 -s64 -W1 -w2 %s" % ip
                banner(f"ICMP ({count_ips+1}/{target_ips}): Ping {ip}")
                subprocess.call(cmd, shell=True)
        console.line()
    except (subprocess.SubprocessError, FileNotFoundError, TimeoutError) as e:
        console.print(f"[red][ping_random] subprocess exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][ping_random] unexpected exception error:[/] {e}")

# Metasploit Checks
def metasploit_check():
    try:
        if ARGS.size == 'S':
            ms_checks = 1
        elif ARGS.size == 'M':
            ms_checks = 3
        elif ARGS.size == 'L':
            ms_checks = 5
        elif ARGS.size == 'XL':
            ms_checks = 7

        rc_dir = '/opt/metasploit-framework/ms_checks/checks'
        rc_files = [f for f in os.listdir(rc_dir) if f.endswith('.rc')]
        random.shuffle(rc_files)

        for count_ms, rc_file in enumerate(rc_files):
            if count_ms < ms_checks:
                cmd = "msfconsole -q -r '%s'" % os.path.join(rc_dir, rc_file)
                banner(f"Metasploit Check ({count_ms+1}/{ms_checks}): {rc_file}")
                subprocess.call(cmd, shell=True)
        console.line()
    except Exception as e:
        console.print(f"[red][metasploit_check] unexpected exception error:[/] {e}")

# SNMP test
def snmp_random():
    try:
        if ARGS.size == 'S':
            target_ips = 1
        elif ARGS.size == 'M':
            target_ips = 2
        elif ARGS.size == 'L':
            target_ips = 5
        elif ARGS.size == 'XL':
            target_ips = len(snmp_endpoints)
        random.shuffle(snmp_endpoints)
        random.shuffle(snmp_strings)
        for count_ips, ip in enumerate(snmp_endpoints):
            if count_ips < target_ips:
                community = snmp_strings[count_ips % len(snmp_strings)]
                cmd = f"snmpwalk -v2c -t1 -r1 -c {community} {ip}"
                banner(f"SNMP ({count_ips+1}/{target_ips}): Poll {ip} (community '{community}')")
                subprocess.call(cmd, shell=True)
        console.line()
    except subprocess.CalledProcessError as e:
        console.print(f"[red][snmp_random] snmp tool exit {e.returncode}:[/] {e.stderr or e.stdout or e}")
    except subprocess.TimeoutExpired as e:
        console.print(f"[red][snmp_random] snmp tool timed out:[/] {e}")
    except (FileNotFoundError, PermissionError) as e:
        console.print(f"[red][snmp_random] snmp tool not runnable:[/] {e}")
    except (socket.timeout, socket.gaierror, OSError) as e:
        console.print(f"[red][snmp_random] network/os error:[/] {e}")
    except UnicodeDecodeError as e:
        console.print(f"[red][snmp_random] decode error:[/] {e}")
    except ValueError as e:
        console.print(f"[red][snmp_random] parse error:[/] {e}")
    except Exception as e:
        console.print(f"[red][snmp_random] unexpected error:[/] {e}")

# Traceroute test
def traceroute_random():
    try:
        if ARGS.size == 'S':
            target_ips = 1
        elif ARGS.size == 'M':
            target_ips = 2
        elif ARGS.size == 'L':
            target_ips = 5
        elif ARGS.size == 'XL':
            target_ips = len(icmp_endpoints)
        random.shuffle(icmp_endpoints)
        for count_ips, ip in enumerate(icmp_endpoints):
            if count_ips < target_ips:
                cmd = "traceroute %s -w1 -q1 -m5" % (ip)
                banner(f"Traceroute ({count_ips+1}/{target_ips}): to {ip}")
                subprocess.call(cmd, shell=True)
        console.line()
    except (subprocess.SubprocessError, FileNotFoundError, TimeoutError) as e:
        console.print(f"[red][traceroute_random] subprocess exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][traceroute_random] unexpected exception error:[/] {e}")

# Netflix Test
def speedtest_fast():
    try:
        if ARGS.size == 'S':
            duration = 1
        elif ARGS.size == 'M':
            duration = 2
        elif ARGS.size == 'L':
            duration = 3
        elif ARGS.size == 'XL':
            duration = 4

        banner("Netflix: Fast.com Speedtest")

        timeout_per_test = 20

        for i in range(1, duration + 1):
            console.print(f"Starting Fast.com test {i} of {duration} (timeout: {timeout_per_test}s)...")
            try:
                result = subprocess.run(
                    'python3 -m fastcli',
                    shell=True,
                    check=True,
                    timeout=timeout_per_test,
                    capture_output=True,
                    text=True
                )
                console.print(f"Test {i} completed successfully.")
                if result.stdout:
                    console.print(f"[dim]{result.stdout}[/]")
                if result.stderr:
                    console.print(f"[dim]{result.stderr}[/]")
            except subprocess.TimeoutExpired:
                console.print(f"[yellow]Test {i} timed out after {timeout_per_test} seconds. Moving on.[/]")
            except subprocess.CalledProcessError as e:
                console.print(f"[red]Test {i} failed:[/] {e}")
                if e.stdout:
                    console.print(f"[dim]{e.stdout}[/]")
                if e.stderr:
                    console.print(f"[dim]{e.stderr}[/]")
            except Exception as e:
                console.print(f"[red]Unexpected error during test {i}:[/] {e}")

        console.print("All Speedtest Tests Attempted.")
    except (ssl.SSLError, socket.error) as e:
        console.print(f"[red][speedtest_fast] network/ssl exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][speedtest_fast] unexpected exception error:[/] {e}")

# NMAP Test (1024 ports)
def nmap_1024os():
    try:
        if ARGS.size == 'S':
            target_ips = 1
        elif ARGS.size == 'M':
            target_ips = 2
        elif ARGS.size == 'L':
            target_ips = 5
        elif ARGS.size == 'XL':
            target_ips = len(nmap_endpoints)
        random.shuffle(nmap_endpoints)
        for count_ips, ip in enumerate(nmap_endpoints):
            if count_ips < target_ips:
                cmd = 'nmap -Pn -p 1-1024 %s -T4 --max-retries 0 --max-parallelism 2 --randomize-hosts --host-timeout 1m --script-timeout 1m --script-args http.useragent "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" -debug' % ip
                banner(f"NMAP (first 1024 ports): {ip}")
                subprocess.call(cmd, shell=True)
        console.line()
    except (subprocess.SubprocessError, FileNotFoundError, TimeoutError) as e:
        console.print(f"[red][nmap_1024os] subprocess exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][nmap_1024os] unexpected exception error:[/] {e}")

# NMAP Test (CVE)
def nmap_cve():
    try:
        if ARGS.size == 'S':
            target_ips = 1
        elif ARGS.size == 'M':
            target_ips = 2
        elif ARGS.size == 'L':
            target_ips = 5
        elif ARGS.size == 'XL':
            target_ips = len(nmap_endpoints)
        random.shuffle(nmap_endpoints)
        for count_ips, ip in enumerate(nmap_endpoints):
            if count_ips < target_ips:
                cmd = 'nmap -sV --script=ALL %s -T4 --max-retries 0 --max-parallelism 2 --randomize-hosts --host-timeout 1m --script-timeout 1m --script-args http.useragent "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" -debug' % ip
                banner(f"NMAP (CVE/scripts): {ip}")
                subprocess.call(cmd, shell=True)
        console.line()
    except (subprocess.SubprocessError, FileNotFoundError, TimeoutError) as e:
        console.print(f"[red][nmap_cve] subprocess exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][nmap_cve] unexpected exception error:[/] {e}")

# NTP Test
def ntp_random():
    try:
        if ARGS.size == 'S':
            target_urls = 1
        elif ARGS.size == 'M':
            target_urls = 2
        elif ARGS.size == 'L':
            target_urls = 5
        elif ARGS.size == 'XL':
            target_urls = len(ntp_endpoints)
        random.shuffle(ntp_endpoints)
        for count_urls, url in enumerate(ntp_endpoints):
            if count_urls < target_urls:
                cmd = f"(printf '\\x1b'; head -c 47 < /dev/zero) | nc -u -w1 {url} 123"
                banner(f"NTP: Update time against {url}")
                subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        console.line()
    except subprocess.CalledProcessError as e:
        console.print(f"[red][ntp_random] ntp tool exit {e.returncode}:[/] {e.stderr or e.stdout or e}")
    except subprocess.TimeoutExpired as e:
        console.print(f"[red][ntp_random] ntp tool timed out:[/] {e}")
    except (FileNotFoundError, PermissionError) as e:
        console.print(f"[red][ntp_random] ntp tool not runnable:[/] {e}")
    except (socket.timeout, socket.gaierror, OSError) as e:
        console.print(f"[red][ntp_random] network/os error:[/] {e}")
    except UnicodeDecodeError as e:
        console.print(f"[red][ntp_random] decode error:[/] {e}")
    except ValueError as e:
        console.print(f"[red][ntp_random] parse error:[/] {e}")
    except Exception as e:
        console.print(f"[red][ntp_random] unexpected error:[/] {e}")

# SSH Test
def ssh_random():
    try:
        if ARGS.size == 'S':
            target_ips = 1
        elif ARGS.size == 'M':
            target_ips = 2
        elif ARGS.size == 'L':
            target_ips = 5
        elif ARGS.size == 'XL':
            target_ips = len(ssh_endpoints)
        random.shuffle(ssh_endpoints)
        for count_ips, ip in enumerate(ssh_endpoints):
            if count_ips < target_ips:
                cmd = "ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 %s" % (ip)
                banner(f"SSH ({count_ips+1}/{target_ips}): {ip}")
                subprocess.call(cmd, shell=True)
        console.line()
    except subprocess.CalledProcessError as e:
        console.print(f"[red][ssh_random] ssh exit {e.returncode}:[/] {e.stderr or e.stdout or e}")
    except subprocess.TimeoutExpired as e:
        console.print(f"[red][ssh_random] ssh timed out:[/] {e}")
    except (FileNotFoundError, PermissionError) as e:
        console.print(f"[red][ssh_random] ssh not runnable:[/] {e}")
    except (socket.error, ssl.SSLError) as e:
        console.print(f"[red][ssh_random] network/ssl exception error:[/] {e}")
    except OSError as e:
        console.print(f"[red][ssh_random] OS exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][ssh_random] unexpected exception error:[/] {e}")

# URL Response Time Test
def urlresponse_random():
    try:
        if ARGS.size == 'S':
            target_urls = 10
        elif ARGS.size == 'M':
            target_urls = 20
        elif ARGS.size == 'L':
            target_urls = 50
        elif ARGS.size == 'XL':
            target_urls = len(https_endpoints)
        random.shuffle(https_endpoints)
        for count_urls, url in enumerate(https_endpoints):
            if count_urls < target_urls:
                try:
                    t = requests.get(url, timeout=3).elapsed.total_seconds()
                except requests.ConnectionError:
                    continue
                except requests.ReadTimeout:
                    continue
                except requests.ChunkedEncodingError:
                    continue
                except urllib3.ProtocolError:
                    continue
                except Exception:
                    continue
                banner(f"HTTPS ({count_urls+1}/{target_urls}): {url}")
                console.print(f"Total Transaction Time -- {t}")
    except (requests.exceptions.RequestException, ssl.SSLError, socket.error) as e:
        console.print(f"[red][urlresponse_random] http exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][urlresponse_random] unexpected exception error:[/] {e}")

# Virus Simulation
def virus_sim():
    try:
        if ARGS.size == 'S':
            target_urls = 1
        elif ARGS.size == 'M':
            target_urls = 2
        elif ARGS.size == 'L':
            target_urls = 3
        elif ARGS.size == 'XL':
            target_urls = len(virus_endpoints)
        random.shuffle(virus_endpoints)
        for count_urls, url in enumerate(virus_endpoints):
            if count_urls < target_urls:
                cmd = "curl --limit-rate 3M -k --show-error --connect-timeout 4 -o /dev/null %s" % url
                banner(f"Virus Simulation: Download {url}")
                subprocess.call(cmd, shell=True)
        console.line()
    except (requests.exceptions.RequestException, ssl.SSLError, socket.error) as e:
        console.print(f"[red][virus_sim] http exception error:[/] {e}")
    except (OSError, IOError) as e:
        console.print(f"[red][virus_sim] file I/O exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][virus_sim] unexpected exception error:[/] {e}")

# DLP Tests
def dlp_sim_https():
    try:
        if ARGS.size == 'S':
            target_urls = 1
        elif ARGS.size == 'M':
            target_urls = 2
        elif ARGS.size == 'L':
            target_urls = 3
        elif ARGS.size == 'XL':
            target_urls = len(dlp_https_endpoints)
        random.shuffle(dlp_https_endpoints)
        for count_urls, url in enumerate(dlp_https_endpoints):
            if count_urls < target_urls:
                cmd = "curl --limit-rate 3M -k --show-error --connect-timeout 4 -o /dev/null %s" % url
                banner(f"DLP Simulation (HTTPS): Download {url}")
                subprocess.call(cmd, shell=True)
        console.line()
    except (requests.exceptions.RequestException, ssl.SSLError, socket.error) as e:
        console.print(f"[red][dlp_sim_https] https exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][dlp_sim_https] unexpected exception error:[/] {e}")

# Malware Tests
def malware_download():
    try:
        if ARGS.size == 'S':
            target_urls = 1
        elif ARGS.size == 'M':
            target_urls = 2
        elif ARGS.size == 'L':
            target_urls = 3
        elif ARGS.size == 'XL':
            target_urls = len(malware_files)
        random.shuffle(malware_files)
        for count_urls, url in enumerate(malware_files):
            if count_urls < target_urls:
                cmd = "curl --limit-rate 3M -k --show-error --connect-timeout 4 -o /dev/null %s" % url
                banner(f"Malware File Download (HTTPS): Download {url}")
                subprocess.call(cmd, shell=True)
        console.line()
    except (requests.exceptions.RequestException, ssl.SSLError, socket.error) as e:
        console.print(f"[red][malware_download] http exception error:[/] {e}")
    except (OSError, IOError) as e:
        console.print(f"[red][malware_download] file I/O exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][malware_download] unexpected exception error:[/] {e}")

# Squatting Tests
def squatting_domains():
    try:
        if ARGS.size == 'S':
            target_domains = 1
        elif ARGS.size == 'M':
            target_domains = 2
        elif ARGS.size == 'L':
            target_domains  = 3
        elif ARGS.size == 'XL':
            target_domains  = 4
        random.shuffle(squatting_endpoints)
        for count_urls, url in enumerate(squatting_endpoints):
            if count_urls < target_domains :
                cmd = "dnstwist --registered %s" % url
                banner(f"Generating Squatting Domains Based On {url}")
                subprocess.call(cmd, shell=True)
        console.line()
    except (requests.exceptions.RequestException, socket.error, ssl.SSLError) as e:
        console.print(f"[red][squatting_domains] http exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][squatting_domains] unexpected exception error:[/] {e}")

# Web Crawl helpers
def scrape_single_link(url):
    sleep(random.uniform(0.2, 2))
    random.shuffle(user_agents)
    user_agent = user_agents[0]

    console.print(f"[bold white]Visiting:[/] [bold]{url}[/]")
    console.print(f"[dim]Agent: {user_agent}[/]\n")

    try:
        response = requests.request(
            method="GET",
            url=url,
            timeout=2,
            allow_redirects=True,
            headers={'User-Agent': user_agents[0]},
            verify=False
        )
        response.raise_for_status()
        response.encoding = response.apparent_encoding or 'utf-8'
        html = response.text

    except requests.exceptions.HTTPError as e:
        if e.response and e.response.status_code == 404:
            return None
        console.print(f"[yellow]HTTP error for {url}:[/] {e}")
        return None
    except requests.exceptions.SSLError as e:
        console.print(f"[yellow]SSL error for {url}:[/] {e}")
        return None
    except requests.exceptions.Timeout:
        console.print(f"[yellow]Timeout for {url}[/]")
        return None
    except requests.exceptions.TooManyRedirects:
        console.print(f"[yellow]Too many redirects for {url}[/]")
        return None
    except requests.exceptions.RequestException as e:
        console.print(f"[yellow]General failure for {url}:[/] {e}")
        return None

    soup = BeautifulSoup(html, 'html.parser')
    all_links = soup.find_all("a")
    random.shuffle(all_links)

    for link in all_links:
        href = link.get('href')
        if not href or '#' in href:
            continue
        if href.startswith("//") or href.startswith("/"):
            resolved = urljoin(url, href)
            console.print(f"[bold green]Found:[/] [bold]{resolved}[/]")
            return resolved
        elif href.startswith("http"):
            console.print(f"[bold green]Found:[/] [bold]{href}[/]")
            return href

    console.print("[dim]No Links Found[/]")
    console.line()
    return None

def scrape_iterative(base_url, iterations=3):
    next_link = scrape_single_link(base_url)
    for _ in range(iterations):
        if next_link:
            next_link = scrape_single_link(next_link)
        else:
            break

def webcrawl():
    try:
        if ARGS.size == 'S':
            iterations = 10
            attempts = 1
        elif ARGS.size == 'M':
            iterations = 20
            attempts = 3
        elif ARGS.size == 'L':
            iterations = 50
            attempts = 5
        elif ARGS.size == 'XL':
            iterations = 100
            attempts = 10
        for count, attempt in enumerate(range(attempts)):
            banner(f"Crawling from {ARGS.crawl_start} ({iterations} deep, attempt {count+1} of {attempts})")
            scrape_iterative(ARGS.crawl_start, iterations)
        console.line()
    except (requests.exceptions.RequestException, socket.error, ssl.SSLError, ValueError) as e:
        console.print(f"[red][webcrawl] http/parse exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][webcrawl] unexpected exception error:[/] {e}")

# Trigger an IPS system
def ips():
    try:
        cmd = 'curl -k -s --show-error --connect-timeout 3 -I --max-time 5 -A BlackSun www.testmyids.com'
        banner("IPS: BlackSun")
        subprocess.call(cmd, shell=True)
        console.line()
    except (subprocess.SubprocessError, FileNotFoundError, TimeoutError) as e:
        console.print(f"[red][ips] subprocess exception error:[/] {e}")
    except (requests.exceptions.RequestException, socket.error, ssl.SSLError) as e:
        console.print(f"[red][ips] http/socket exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][ips] unexpected exception error:[/] {e}")

# GITHUB Bad Domains Testing
def github_domain_check_download_file(url, local_filename):
    console.print(f"Attempting to download '{url}' to '{local_filename}'...")
    try:
        with requests.get(url, stream=True, verify=False, timeout=5) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        console.print(f"[green]Successfully downloaded '{local_filename}'.[/]")
        return True
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error downloading file:[/] {e}")
        return False
    except IOError as e:
        console.print(f"[red]Error writing file to disk:[/] {e}")
        return False

def github_domain_check_read_file(local_filename, num_random_domains=10):
    console.print(f"\nReading domains from local file: {local_filename}")
    try:
        with open(local_filename, 'r', encoding='utf-8') as f:
            all_domains = f.readlines()
        valid_domains = [
            domain.strip() for domain in all_domains
            if domain.strip() and not domain.strip().startswith('#')
        ]
        console.print(f"Successfully read {len(valid_domains)} domains from local file")
    except FileNotFoundError:
        console.print(f"[red]Error: file '{local_filename}' not found[/]")
        return
    except Exception as e:
        console.print(f"[red]Error reading file:[/] {e}")
        return

    if len(valid_domains) < num_random_domains:
        console.print(f"[yellow]Warning:[/] Only {len(valid_domains)} domains available, selecting all of them")
        selected_domains = valid_domains
    else:
        selected_domains = random.sample(valid_domains, num_random_domains)
        console.print(f"Selected {len(selected_domains)} random domains for querying")

    console.print("\nStarting query operations for selected domains...\n")
    for i, domain in enumerate(selected_domains):
        url = f"https://{domain}"
        console.print(f"[{i+1}/{len(selected_domains)}] Attempting to query: {url}")

        try:
            response = requests.get(url, timeout=1, verify=False, allow_redirects=True)
            console.print(f"  Status: {response.status_code} - OK (Redirected to: {response.url if response.history else 'N/A'})")
        except requests.exceptions.ConnectionError:
            console.print(f"  [yellow]Error:[/] Connection failed for {url}")
        except requests.exceptions.Timeout:
            console.print(f"  [yellow]Error:[/] Timeout reached for {url}")
        except requests.exceptions.HTTPError as e:
            console.print(f"  [yellow]Error:[/] HTTP error {e.response.status_code} for {url}")
        except requests.exceptions.RequestException as e:
            console.print(f"  [yellow]Error:[/] An unexpected request error occurred for {url}: {e}")
        except Exception as e:
            console.print(f"  [yellow]Error:[/] An unhandled error occurred for {url}: {e}")
        time.sleep(0.3)

    console.print("\nQuery operations completed for selected domains.")

def github_domain_check():
    try:
        github_domain_list = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt"
        local_domains_filename = "git-domains-list"

        if not os.path.exists(local_domains_filename):
            console.print("Local domain file not found. Downloading now...")
            if not github_domain_check_download_file(github_domain_list, local_domains_filename):
                console.print("[red]Failed to download the domain list. Exiting.[/]")
                return
        else:
            console.print(f"Local domain file '{local_domains_filename}' already exists. Skipping download.")

        github_domain_check_read_file(local_domains_filename, num_random_domains=10)
    except (requests.exceptions.RequestException, socket.error, ssl.SSLError) as e:
        console.print(f"[red][github_domain_check] http exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][github_domain_check] unexpected exception error:[/] {e}")

# GITHUB Phishing Domains Testing
def github_phishing_domain_check_download_file(url, local_filename):
    console.print(f"Attempting to download '{url}' to '{local_filename}'...")
    try:
        with requests.get(url, stream=True, verify=False, timeout=5) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        console.print(f"[green]Successfully downloaded '{local_filename}'.[/]")
        return True
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error downloading file:[/] {e}")
        return False
    except IOError as e:
        console.print(f"[red]Error writing file to disk:[/] {e}")
        return False

def github_phishing_domain_check_read_file(local_filename, num_random_domains=10):
    console.print(f"\nReading domains from local file: {local_filename}")
    try:
        with open(local_filename, 'r', encoding='utf-8') as f:
            all_domains = f.readlines()
        valid_domains = [
            domain.strip() for domain in all_domains
            if domain.strip() and not domain.strip().startswith('#')
        ]
        console.print(f"Successfully read {len(valid_domains)} domains from local file")
    except FileNotFoundError:
        console.print(f"[red]Error: file '{local_filename}' not found[/]")
        return
    except Exception as e:
        console.print(f"[red]Error reading file:[/] {e}")
        return

    if len(valid_domains) < num_random_domains:
        console.print(f"[yellow]Warning:[/] Only {len(valid_domains)} domains available, selecting all of them")
        selected_domains = valid_domains
    else:
        selected_domains = random.sample(valid_domains, num_random_domains)
        console.print(f"Selected {len(selected_domains)} random domains for querying")

    console.print("\nStarting query operations for selected domains...\n")
    for i, domain in enumerate(selected_domains):
        url = f"https://{domain}"
        console.print(f"[{i+1}/{len(selected_domains)}] Attempting to query: {url}")

        try:
            response = requests.get(url, timeout=1, verify=False, allow_redirects=True)
            console.print(f"  Status: {response.status_code} - OK (Redirected to: {response.url if response.history else 'N/A'})")
        except requests.exceptions.ConnectionError:
            console.print(f"  [yellow]Error:[/] Connection failed for {url}")
        except requests.exceptions.Timeout:
            console.print(f"  [yellow]Error:[/] Timeout reached for {url}")
        except requests.exceptions.HTTPError as e:
            console.print(f"  [yellow]Error:[/] HTTP error {e.response.status_code} for {url}")
        except requests.exceptions.RequestException as e:
            console.print(f"  [yellow]Error:[/] An unexpected request error occurred for {url}: {e}")
        except Exception as e:
            console.print(f"  [yellow]Error:[/] An unhandled error occurred for {url}: {e}")
        time.sleep(0.3)

    console.print("\nQuery operations completed for selected domains.")

def github_phishing_domain_check():
    try:
        github_domain_list = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt"
        local_domains_filename = "git-phishing-list"

        if not os.path.exists(local_domains_filename):
            console.print("Local domain file not found. Downloading now...")
            if not github_phishing_domain_check_download_file(github_domain_list, local_domains_filename):
                console.print("[red]Failed to download the phishing domain list. Exiting.[/]")
                return
        else:
            console.print(f"Local domain file '{local_domains_filename}' already exists. Skipping download.")

        github_phishing_domain_check_read_file(local_domains_filename, num_random_domains=10)
    except (requests.exceptions.RequestException, socket.error, ssl.SSLError) as e:
        console.print(f"[red][github_phishing_domain_check] http exception error:[/] {e}")
    except Exception as e:
        console.print(f"[red][github_phishing_domain_check] unexpected exception error:[/] {e}")

# Wait timer progress bar (kept minimal; SuiteUI handles main visuals)
def progressbar(it, prefix="", size=60, file=sys.stdout):
    count = len(it)
    def show(j):
        x = int(size*j/count)
        file.write("%s[%s%s] %is \r" % (prefix, "#"*x, "."*(size-x), (count - j)))
        file.flush()
    show(0)
    for i, item in enumerate(it):
        yield item
        show(i+1)
    file.write("\n")
    file.flush()

# Randomize and run tests (Rich-enabled)
def run_test(func_list):
    size_map = {'S': 'small', 'M': 'medium', 'L': 'large', 'XL': 'extra-large'}
    size = size_map.get(ARGS.size, ARGS.size)

    console.rule(f"[bold blue]Running suite: {ARGS.suite.upper()} (size: {size.upper()})")
    meta_lines = [
        f"Loop: {ARGS.loop}",
        f"Max Wait: {ARGS.max_wait_secs}s",
        f"NoWait: {ARGS.nowait}",
        f"Crawl Start: {ARGS.crawl_start}",
    ]
    console.print(Panel("\n".join(meta_lines), title="Run Config", border_style="blue", expand=False))

    with SuiteUI() as ui:
        if ARGS.loop:
            while True:
                func = random.choice(func_list)
                ui.run_test_callable(func)
                WATCHDOG.kick()
                finish_test()
        else:
            shuffled = func_list[:]
            random.shuffle(shuffled)
            for func in shuffled:
                ui.run_test_callable(func)
                WATCHDOG.kick()
                finish_test()

# Randomize a wait time between 2 and max seconds
def finish_test():
    if ARGS.loop:
        if not ARGS.nowait:
            max_wait = int(ARGS.max_wait_secs)
            wait_sec = random.randint(2, max_wait)
            console.print(f"[dim]Sleeping {wait_sec}s before next loop…[/]")
            for _ in range(wait_sec):
                time.sleep(1)
        console.print("[dim]Looping…[/]")

# Pull an updated list of colocated containers to test against
def replace_all_endpoints(url):
    console.print(f"[i] Replacing endpoints.py with {url}")
    response = urllib.request.urlopen(url)
    data = response.read()
    text = data.decode('utf-8')
    with open('endpoints.py', 'w') as filetowrite:
        filetowrite.write(text)

# ------------------------
# Menus / Main
# ------------------------
if __name__ == "__main__":
    try:
        # Start time measured since the epoch
        STARTTIME = time.time()

        # Argument Parsing (CLI variables)
        parser = argparse.ArgumentParser(
            description="""Traffic Generator: A versatile tool for simulating various network traffic types.
Use this script to generate realistic network activity for testing,
performance analysis, or security simulations.
""",
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

        parser.add_argument('--_spacer1', action='store_true', help=argparse.SUPPRESS)
        parser.add_argument('--_spacer2', action='store_true', help=argparse.SUPPRESS)

        traffic_group = parser.add_argument_group('Traffic Generation Options')
        traffic_group.add_argument(
            '--suite',
            type=str.lower,
            choices=suite_choices,
            action="store",
            required=False,
            default='all',
            help=(
                'Specify the test suite to run.\n'
                'Available suites:\n'
                '  ' + '\n  '.join(sorted(suite_choices)) + '\n'
                'Default: "all" (runs all available test suites).\n\n'
            )
        )
        traffic_group.add_argument(
            '--size',
            type=str.upper,
            choices=size_choices,
            action="store",
            required=False,
            default='M',
            help=(
                'Determines the scale/volume of tests to run.\n'
                'Choices:\n'
                '  S (Small): Minimal traffic generation.\n'
                '  M (Medium): Moderate traffic (default).\n'
                '  L (Large): Significant traffic volume.\n'
                '  XL (Extra Large): High-intensity traffic. Use carefully!\n\n'
            )
        )

        timing_group = parser.add_argument_group('Timing and Loop Options')
        timing_group.add_argument(
            '--loop',
            action="store_true",
            required=False,
            help='Continuously loop the selected test suite(s).\n\n'
        )
        timing_group.add_argument(
            '--max-wait-secs',
            type=int,
            action="store",
            required=False,
            default=20,
            help='Maximum possible time (in seconds) for random intervals between tests or loops. Default: 20 seconds.\n\n'
        )
        timing_group.add_argument(
            '--nowait',
            action="store_true",
            required=False,
            help='Disable random waiting intervals between tests or loops, making them run consecutively.\n\n'
        )

        specific_suite_group = parser.add_argument_group('Suite-Specific Options')
        specific_suite_group.add_argument(
            '--crawl-start',
            action="store",
            required=False,
            default='https://data.commoncrawl.org',
            help='For the "crawl" suite: initial URL to start web crawling from. Default: https://data.commoncrawl.org'
        )

        ARGS = parser.parse_args()

        WATCHDOG = watchdog(timeout_seconds=600)

        # Output Summary (concise)
        console.rule("[bold green]Starting Run")
        cfg = Table(show_lines=False, show_header=False, box=None, expand=False)
        cfg.add_row("Suite", ARGS.suite)
        cfg.add_row("Size", ARGS.size)
        cfg.add_row("Loop", str(ARGS.loop))
        cfg.add_row("Max Wait (s)", str(ARGS.max_wait_secs))
        cfg.add_row("No Wait", str(ARGS.nowait))
        cfg.add_row("Crawl Start", ARGS.crawl_start)
        console.print(cfg)
        console.line()

        # All tests and the functions they call
        if ARGS.suite == 'all':
            testsuite = [
                bigfile,
                webcrawl,
                dig_random,
                bgp_peering,
                ftp_random,
                http_download_targz,
                http_download_zip,
                http_random,
                https_random,
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
                malware_download
            ]
            random.shuffle(testsuite)
        elif ARGS.suite == 'bigfile':
            testsuite = [bigfile]
        elif ARGS.suite == 'crawl':
            testsuite = [webcrawl]
        elif ARGS.suite == 'dns':
            testsuite = [dig_random]
        elif ARGS.suite == 'bgp':
            testsuite = [bgp_peering]
        elif ARGS.suite == 'ftp':
            testsuite = [ftp_random]
        elif ARGS.suite == 'http':
            testsuite = [http_download_targz, http_download_zip, http_random]
        elif ARGS.suite == 'https':
            testsuite = [https_random, https_crawl]
        elif ARGS.suite == 'pornography':
            testsuite = [pornography_crawl]
        elif ARGS.suite == 'metasploit-check':
            testsuite = [metasploit_check]
        elif ARGS.suite == 'malware-agents':
            testsuite = [malware_random]
        elif ARGS.suite == 'ai':
            testsuite = [ai_https_random]
        elif ARGS.suite == 'icmp':
            testsuite = [ping_random, traceroute_random]
        elif ARGS.suite == 'snmp':
            testsuite = [snmp_random]
        elif ARGS.suite == 'ips':
            testsuite = [ips]
        elif ARGS.suite == 'ads':
            testsuite = [ads_random]
        elif ARGS.suite == 'domain-check':
            testsuite = [github_domain_check]
        elif ARGS.suite == 'phishing-domains':
            testsuite = [github_phishing_domain_check]
        elif ARGS.suite == 'squatting':
            testsuite = [squatting_domains]
        elif ARGS.suite == 'netflix':
            testsuite = [speedtest_fast]
        elif ARGS.suite == 'web-scanner':
            testsuite = [web_scanner]
        elif ARGS.suite == 'nmap':
            testsuite = [nmap_1024os, nmap_cve]
        elif ARGS.suite == 'ntp':
            testsuite = [ntp_random]
        elif ARGS.suite == 'ssh':
            testsuite = [ssh_random]
        elif ARGS.suite == 'url-response':
            testsuite = [urlresponse_random]
        elif ARGS.suite == 'virus':
            testsuite = [virus_sim]
        elif ARGS.suite == 'dlp':
            testsuite = [dlp_sim_https]
        elif ARGS.suite == 'malware-download':
            testsuite = [malware_download]
        else:
            console.print(f"[red]Unknown suite: {ARGS.suite}[/]")
            sys.exit(2)

        # SEND IT!
        run_test(testsuite)

        # End time & summaries
        ENDTIME = time.time() - STARTTIME
        _print_summary_table(ENDTIME)
        _write_summary_files(ARGS.suite, STARTTIME)

        console.print(f"[bold blue]Total Run Time:[/] {time.strftime('%H:%M:%S', time.gmtime(ENDTIME))}")

    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]An error occurred:[/] {e}")
