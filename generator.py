#!/usr/bin/env python3
"""
Traffic Generator with Rich Progress UI and Summaries
- Uses Rich Progress for each test (spinner + bar + timers)
- Quiet subprocess execution (no noisy stdout/stderr)
- Clear spacing and panels between sections
- Final summary table + optional JSON/Markdown artifacts
- No tqdm; no legacy colorama banners
"""

import os, sys, time, random, threading, argparse, socket, ssl, subprocess, urllib.request, urllib3, requests, traceback
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Callable, Optional

from bs4 import BeautifulSoup
from urllib.parse import urljoin

# ---- Rich UI ----
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel

console = Console()

# ---- External config ----
from endpoints import *  # provides endpoints lists & user agents, etc.

# ---- Network warnings ----
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context

# --------------------------------------------------------------------------------------------------
# Utility + UI Scaffolding
# --------------------------------------------------------------------------------------------------

@dataclass
class TestResult:
    name: str
    start_ts: float
    end_ts: float
    duration_s: float
    status: str              # "ok" | "error"
    error: str = ""


class Watchdog:
    """Simple activity watchdog that exits the process if no .kick() within timeout seconds."""
    def __init__(self, timeout_seconds: int = 600):
        self.timeout = timeout_seconds
        self.last_kick = time.time()
        t = threading.Thread(target=self._watch, daemon=True)
        t.start()

    def kick(self):
        self.last_kick = time.time()

    def _watch(self):
        while True:
            if time.time() - self.last_kick > self.timeout:
                console.print("[bold red][WATCHDOG][/bold red] No activity; exiting to force container restart…")
                os._exit(1)
            time.sleep(1)


class SuiteUI:
    """Manager that runs tests with Rich Progress and collects results."""
    def __init__(self):
        self.results: List[TestResult] = []

    @staticmethod
    def run_quiet(cmd: str, timeout: Optional[int] = None, check: bool = False) -> int:
        """Run shell command quietly; return returncode."""
        try:
            res = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=check
            )
            return res.returncode
        except subprocess.TimeoutExpired:
            return 124
        except Exception:
            return 1

    def banner(self, title: str):
        console.line()
        console.rule(f"[bold]{title}[/]")
        console.line()

    def run_one(self, func: Callable, name: Optional[str] = None):
        """Run a single test inside its own transient progress UI and capture timing/status."""
        fname = name or getattr(func, "__name__", str(func))
        start_ts = time.time()
        status = "ok"
        err_msg = ""

        # headline panel
        console.print(Panel(f"[bold cyan]{fname}[/]", expand=False))

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}[/]"),
            BarColumn(complete_style="green"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            expand=True,
            transient=True,
            console=console
        ) as prog:
            task = prog.add_task(f"{fname}", total=100)
            try:
                prog.update(task, advance=5)
                func()
                prog.update(task, completed=100)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                status = "error"
                err_msg = f"{type(e).__name__}: {e}".strip()[:300]
                prog.update(task, completed=100)
            finally:
                end_ts = time.time()
                self.results.append(TestResult(
                    name=fname,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    duration_s=round(end_ts - start_ts, 3),
                    status=status,
                    error=err_msg
                ))
                console.line()

    def print_summary(self):
        ok = sum(1 for r in self.results if r.status == "ok")
        err = sum(1 for r in self.results if r.status == "error")
        total_runtime = sum(r.duration_s for r in self.results)

        table = Table(title="Run Summary", expand=True, show_lines=True)
        table.add_column("Test", style="bold")
        table.add_column("Status")
        table.add_column("Duration (s)", justify="right")
        table.add_column("Error (truncated)")

        for r in sorted(self.results, key=lambda x: x.duration_s, reverse=True):
            table.add_row(
                r.name,
                ("✅ ok" if r.status == "ok" else "❌ error"),
                f"{r.duration_s:.3f}",
                (r.error[:120] + "…") if len(r.error) > 120 else r.error
            )

        console.rule("[bold green]Run Complete")
        console.print(table)
        console.print(
            Panel(
                f"[green]OK:[/green] {ok}   [red]ERRORS:[/red] {err}   "
                f"[cyan]Total Runtime:[/cyan] {time.strftime('%H:%M:%S', time.gmtime(total_runtime))}",
                title="Totals",
                border_style="green",
                expand=False
            )
        )
        console.line()

    def write_summaries(self, suite_name: str, started_at: float):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"run_summary_{suite_name}_{stamp}"
        # JSON
        try:
            import json
            with open(f"{base}.json", "w") as f:
                json.dump([asdict(r) for r in self.results], f, indent=2)
            console.print(f"[green]Saved JSON summary → {base}.json[/]")
        except Exception as e:
            console.print(f"[yellow]Could not write JSON summary: {e}[/]")
        # Markdown
        try:
            lines = [
                f"# Run Summary: {suite_name}",
                "",
                f"**Started:** {datetime.fromtimestamp(started_at).isoformat()}",
                f"**Tests:** {len(self.results)}",
                "",
                "| Test | Status | Duration (s) | Error |",
                "|---|---:|---:|---|",
            ]
            for r in self.results:
                err = (r.error or "").replace("|", "\\|")
                lines.append(f"| `{r.name}` | {r.status} | {r.duration_s:.3f} | {err} |")
            with open(f"{base}.md", "w") as f:
                f.write("\n".join(lines) + "\n")
            console.print(f"[green]Saved Markdown summary → {base}.md[/]")
        except Exception as e:
            console.print(f"[yellow]Could not write Markdown summary: {e}[/]")


# --------------------------------------------------------------------------------------------------
# Helpers used by tests
# --------------------------------------------------------------------------------------------------

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


def spacer(n: int = 1):
    for _ in range(max(1, n)):
        console.line()


def scrape_single_link(url):
    # Friendly delay to avoid hammering
    time.sleep(random.uniform(0.2, 2))
    random.shuffle(user_agents)
    user_agent = user_agents[0]

    console.print(f"[bold white]Visiting:[/] [bold]{url}[/]")
    console.print(f"[dim]Agent: {user_agent}[/]")
    console.line()

    try:
        response = requests.request(
            method="GET",
            url=url,
            timeout=2,
            allow_redirects=True,
            headers={'User-Agent': user_agents[0]},
            verify=False  # intentionally allow self-signed in this test rig
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


# --------------------------------------------------------------------------------------------------
# Test functions (silenced outputs via SuiteUI.run_quiet)
# --------------------------------------------------------------------------------------------------

UI = SuiteUI()  # used for run_quiet and central summary writing

def bgp_peering():
    gobgpd_proc = None
    try:
        # Start gobgpd if available
        try:
            gobgpd_proc = subprocess.Popen(
                ["gobgpd", "--api-hosts", "127.0.0.1:50051"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except Exception:
            gobgpd_proc = None

        # Simple wait for API
        def gobgp_wait_api(host, port, timeout=10):
            start = time.time()
            while time.time() - start < timeout:
                try:
                    with socket.create_connection((host, port), timeout=1):
                        return True
                except OSError:
                    time.sleep(0.5)
            return False

        if gobgpd_proc and gobgp_wait_api("127.0.0.1", 50051, timeout=15):
            try:
                router_id = get_container_ip()
                subprocess.run([
                    "gobgp", "-u", "127.0.0.1", "-p", "50051",
                    "global", "as", "65555", "router-id", router_id
                ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                for neighbor_ip in bgp_neighbors:
                    subprocess.run([
                        "gobgp", "-u", "127.0.0.1", "-p", "50051",
                        "neighbor", "add", neighbor_ip, "as", "65555"
                    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        # grace period, then kill
        time.sleep(5)
    finally:
        if gobgpd_proc:
            gobgpd_proc.terminate()
            try:
                gobgpd_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                gobgpd_proc.kill()


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
                BarColumn(complete_style="green"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                transient=True,
                expand=True
            ) as prog:
                task = prog.add_task("download", total=total_size)
                for chunk in response.iter_content(chunk_size=1024 * 64):
                    if chunk:
                        prog.update(task, advance=len(chunk))
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold]Downloading 5GB.zip (streaming)[/]"),
                TimeElapsedColumn(),
                transient=True,
                expand=True
            ) as prog:
                task = prog.add_task("download", total=None)
                for chunk in response.iter_content(chunk_size=1024 * 64):
                    if chunk:
                        prog.refresh()
        console.line()
    except Exception:
        # Keep quiet; errors are captured by SuiteUI
        pass


def dig_random():
    try:
        if ARGS.size == 'S':
            target_ips, target_urls = 1, 10
        elif ARGS.size == 'M':
            target_ips, target_urls = 2, 20
        elif ARGS.size == 'L':
            target_ips, target_urls = 4, 50
        else:
            target_ips, target_urls = len(dns_endpoints), len(dns_urls)

        random.shuffle(dns_endpoints)
        for count_ips, ip in enumerate(dns_endpoints):
            if count_ips < target_ips:
                random.shuffle(dns_urls)
                for count_urls, url in enumerate(dns_urls):
                    if count_urls < target_urls:
                        cmd = f"dig {url} @{ip} +time=1"
                        UI.run_quiet(cmd, timeout=5)
                        time.sleep(0.25)
    except Exception:
        pass


def ftp_random():
    try:
        target = {'S': '1MB', 'M': '10MB', 'L': '100MB'}.get(ARGS.size, '1GB')
        cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 5 -o /dev/null ftp://speedtest:speedtest@ftp.otenet.gr/test{target}.db"
        UI.run_quiet(cmd, timeout=30)
    except Exception:
        pass


def http_random():
    try:
        target_urls = {'S': 10, 'M': 20, 'L': 50}.get(ARGS.size, len(http_endpoints + dns_urls))
        random.shuffle(http_endpoints); random.shuffle(dns_urls)
        for count_urls, url in enumerate(http_endpoints + dns_urls):
            if count_urls < target_urls:
                random.shuffle(user_agents)
                user_agent = user_agents[0]
                cmd = f"curl -k -s --show-error --connect-timeout 5 -I -L -o /dev/null --max-time 5 -A '{user_agent}' {url}"
                UI.run_quiet(cmd, timeout=10)
    except Exception:
        pass


def http_download_zip():
    try:
        random.shuffle(user_agents)
        user_agent = user_agents[0]
        if ARGS.size == 'S':
            target = '15MB'
        elif ARGS.size == 'M':
            target = '30MB'
        elif ARGS.size == 'L':
            target = '100MB'
        else:
            target = '1GB'
        cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 5 -L -o /dev/null -A '{user_agent}' https://link.testfile.org/{target}"
        UI.run_quiet(cmd, timeout=60)
    except Exception:
        pass


def http_download_targz():
    try:
        cmd = 'curl --limit-rate 3M -k --show-error --connect-timeout 5 -o /dev/null http://wordpress.org/latest.tar.gz'
        UI.run_quiet(cmd, timeout=30)
    except Exception:
        pass


def web_scanner():
    try:
        timeout = {'S': 60, 'M': 120, 'L': 180}.get(ARGS.size, 240)
        random.shuffle(webscan_endpoints)
        url = webscan_endpoints[0]
        cmd = f"echo y | nikto -h '{url}' -maxtime '{timeout}' -timeout 1 -nointeractive"
        UI.run_quiet(cmd, timeout=timeout + 10)
    except Exception:
        pass


def https_random():
    try:
        target_urls = {'S': 10, 'M': 20, 'L': 50}.get(ARGS.size, len(https_endpoints))
        random.shuffle(https_endpoints)
        for count_urls, url in enumerate(https_endpoints):
            if count_urls < target_urls:
                random.shuffle(user_agents)
                user_agent = user_agents[0]
                cmd = f"curl -k -s --show-error --connect-timeout 5 -I -o /dev/null --max-time 5 -A '{user_agent}' {url}"
                UI.run_quiet(cmd, timeout=10)
    except Exception:
        pass


def ai_https_random():
    try:
        target_urls = {'S': 10, 'M': 20, 'L': 50}.get(ARGS.size, len(ai_endpoints))
        random.shuffle(ai_endpoints)
        for count_urls, url in enumerate(ai_endpoints):
            if count_urls < target_urls:
                random.shuffle(user_agents)
                user_agent = user_agents[0]
                cmd = f"curl -k -s --show-error --connect-timeout 3 -I -o /dev/null --max-time 5 -A '{user_agent}' {url}"
                UI.run_quiet(cmd, timeout=10)
    except Exception:
        pass


def ads_random():
    try:
        target_urls = {'S': 10, 'M': 20, 'L': 50}.get(ARGS.size, len(ad_endpoints))
        random.shuffle(ad_endpoints)
        for count_urls, url in enumerate(ad_endpoints):
            if count_urls < target_urls:
                random.shuffle(user_agents)
                user_agent = user_agents[0]
                cmd = f"curl -k -s --show-error --connect-timeout 3 -I -o /dev/null --max-time 5 -A '{user_agent}' {url}"
                UI.run_quiet(cmd, timeout=10)
    except Exception:
        pass


def https_crawl():
    try:
        if ARGS.size == 'S':
            target_urls, iterations = 10, 1
        elif ARGS.size == 'M':
            target_urls, iterations = 20, 3
        elif ARGS.size == 'L':
            target_urls, iterations = 50, 5
        else:
            target_urls, iterations = len(https_endpoints), 10

        random.shuffle(https_endpoints)
        for count_urls, url in enumerate(https_endpoints):
            if count_urls < target_urls:
                random.shuffle(user_agents)
                user_agent = user_agents[0]
                console.print(Panel(f"[bold]Crawling HTTPS[/] {url}  [dim](depth {iterations})[/]", expand=False))
                scrape_iterative(url, iterations)
                spacer(1)
    except Exception:
        pass


def pornography_crawl():
    try:
        if ARGS.size == 'S':
            target_urls, iterations = 10, 1
        elif ARGS.size == 'M':
            target_urls, iterations = 20, 3
        elif ARGS.size == 'L':
            target_urls, iterations = 50, 5
        else:
            target_urls, iterations = len(pornography_endpoints), 10

        random.shuffle(pornography_endpoints)
        for count_urls, url in enumerate(pornography_endpoints):
            if count_urls < target_urls:
                random.shuffle(user_agents)
                user_agent = user_agents[0]
                console.print(Panel(f"[bold]Crawling Pornography[/] {url}  [dim](depth {iterations})[/]", expand=False))
                scrape_iterative(url, iterations)
                spacer(1)
    except Exception:
        pass


def malware_random():
    try:
        target_urls = {'S': 10, 'M': 20, 'L': 50}.get(ARGS.size, len(malware_endpoints))
        random.shuffle(malware_endpoints)
        for count_urls, url in enumerate(malware_endpoints):
            if count_urls < target_urls:
                random.shuffle(malware_user_agents)
                malware_user_agent = malware_user_agents[0]
                cmd = f"curl -k -s --show-error --connect-timeout 3 -I -o /dev/null --max-time 5 -A '{malware_user_agent}' {url}"
                UI.run_quiet(cmd, timeout=10)
    except Exception:
        pass


def ping_random():
    try:
        target_ips = {'S': 1, 'M': 2, 'L': 5}.get(ARGS.size, len(icmp_endpoints))
        random.shuffle(icmp_endpoints)
        for count_ips, ip in enumerate(icmp_endpoints):
            if count_ips < target_ips:
                cmd = f"ping -c2 -i1 -s64 -W1 -w2 {ip}"
                UI.run_quiet(cmd, timeout=10)
    except Exception:
        pass


def metasploit_check():
    try:
        ms_checks = {'S': 1, 'M': 3, 'L': 5}.get(ARGS.size, 7)
        rc_dir = '/opt/metasploit-framework/ms_checks/checks'
        rc_files = [f for f in os.listdir(rc_dir) if f.endswith('.rc')] if os.path.isdir(rc_dir) else []
        random.shuffle(rc_files)
        for count_ms, rc_file in enumerate(rc_files):
            if count_ms < ms_checks:
                cmd = f"msfconsole -q -r '{os.path.join(rc_dir, rc_file)}'"
                UI.run_quiet(cmd, timeout=60)
    except Exception:
        pass


def snmp_random():
    try:
        target_ips = {'S': 1, 'M': 2, 'L': 5}.get(ARGS.size, len(snmp_endpoints))
        random.shuffle(snmp_endpoints); random.shuffle(snmp_strings)
        for count_ips, ip in enumerate(snmp_endpoints):
            if count_ips < target_ips:
                community = snmp_strings[count_ips % len(snmp_strings)]
                cmd = f"snmpwalk -v2c -t1 -r1 -c {community} {ip}"
                UI.run_quiet(cmd, timeout=10)
    except Exception:
        pass


def traceroute_random():
    try:
        target_ips = {'S': 1, 'M': 2, 'L': 5}.get(ARGS.size, len(icmp_endpoints))
        random.shuffle(icmp_endpoints)
        for count_ips, ip in enumerate(icmp_endpoints):
            if count_ips < target_ips:
                cmd = f"traceroute {ip} -w1 -q1 -m5"
                UI.run_quiet(cmd, timeout=20)
    except Exception:
        pass


def speedtest_fast():
    try:
        duration = {'S': 1, 'M': 2, 'L': 3}.get(ARGS.size, 4)
        timeout_per_test = 20
        for _ in range(duration):
            UI.run_quiet('python3 -m fastcli', timeout=timeout_per_test)
    except Exception:
        pass


def nmap_1024os():
    try:
        target_ips = {'S': 1, 'M': 2, 'L': 5}.get(ARGS.size, len(nmap_endpoints))
        random.shuffle(nmap_endpoints)
        for count_ips, ip in enumerate(nmap_endpoints):
            if count_ips < target_ips:
                cmd = ('nmap -Pn -p 1-1024 %s -T4 --max-retries 0 --max-parallelism 2 '
                       '--randomize-hosts --host-timeout 1m --script-timeout 1m '
                       '--script-args http.useragent "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" -debug') % ip
                UI.run_quiet(cmd, timeout=120)
    except Exception:
        pass


def nmap_cve():
    try:
        target_ips = {'S': 1, 'M': 2, 'L': 5}.get(ARGS.size, len(nmap_endpoints))
        random.shuffle(nmap_endpoints)
        for count_ips, ip in enumerate(nmap_endpoints):
            if count_ips < target_ips:
                cmd = ('nmap -sV --script=ALL %s -T4 --max-retries 0 --max-parallelism 2 '
                       '--randomize-hosts --host-timeout 1m --script-timeout 1m '
                       '--script-args http.useragent "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" -debug') % ip
                UI.run_quiet(cmd, timeout=180)
    except Exception:
        pass


def ntp_random():
    try:
        target_urls = {'S': 1, 'M': 2, 'L': 5}.get(ARGS.size, len(ntp_endpoints))
        random.shuffle(ntp_endpoints)
        for count_urls, url in enumerate(ntp_endpoints):
            if count_urls < target_urls:
                cmd = f"(printf '\\x1b'; head -c 47 < /dev/zero) | nc -u -w1 {url} 123"
                UI.run_quiet(cmd, timeout=5)
    except Exception:
        pass


def ssh_random():
    try:
        target_ips = {'S': 1, 'M': 2, 'L': 5}.get(ARGS.size, len(ssh_endpoints))
        random.shuffle(ssh_endpoints)
        for count_ips, ip in enumerate(ssh_endpoints):
            if count_ips < target_ips:
                cmd = f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 {ip}"
                UI.run_quiet(cmd, timeout=5)
    except Exception:
        pass


def urlresponse_random():
    try:
        target_urls = {'S': 10, 'M': 20, 'L': 50}.get(ARGS.size, len(https_endpoints))
        random.shuffle(https_endpoints)
        for count_urls, url in enumerate(https_endpoints):
            if count_urls < target_urls:
                try:
                    t = requests.get(url, timeout=3, verify=False).elapsed.total_seconds()
                    console.print(f"[bold]HTTPS:[/] {url}  [dim]time={t:.3f}s[/]")
                except Exception:
                    continue
        spacer(1)
    except Exception:
        pass


def virus_sim():
    try:
        target_urls = {'S': 1, 'M': 2, 'L': 3}.get(ARGS.size, len(virus_endpoints))
        random.shuffle(virus_endpoints)
        for count_urls, url in enumerate(virus_endpoints):
            if count_urls < target_urls:
                cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 4 -o /dev/null {url}"
                UI.run_quiet(cmd, timeout=20)
    except Exception:
        pass


def dlp_sim_https():
    try:
        target_urls = {'S': 1, 'M': 2, 'L': 3}.get(ARGS.size, len(dlp_https_endpoints))
        random.shuffle(dlp_https_endpoints)
        for count_urls, url in enumerate(dlp_https_endpoints):
            if count_urls < target_urls:
                cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 4 -o /dev/null {url}"
                UI.run_quiet(cmd, timeout=20)
    except Exception:
        pass


def malware_download():
    try:
        target_urls = {'S': 1, 'M': 2, 'L': 3}.get(ARGS.size, len(malware_files))
        random.shuffle(malware_files)
        for count_urls, url in enumerate(malware_files):
            if count_urls < target_urls:
                cmd = f"curl --limit-rate 3M -k --show-error --connect-timeout 4 -o /dev/null {url}"
                UI.run_quiet(cmd, timeout=20)
    except Exception:
        pass


def squatting_domains():
    try:
        target_domains = {'S': 1, 'M': 2, 'L': 3}.get(ARGS.size, 4)
        random.shuffle(squatting_endpoints)
        for count_urls, url in enumerate(squatting_endpoints):
            if count_urls < target_domains:
                cmd = f"dnstwist --registered {url}"
                UI.run_quiet(cmd, timeout=60)
    except Exception:
        pass


def webcrawl():
    try:
        if ARGS.size == 'S':
            iterations, attempts = 10, 1
        elif ARGS.size == 'M':
            iterations, attempts = 20, 3
        elif ARGS.size == 'L':
            iterations, attempts = 50, 5
        else:
            iterations, attempts = 100, 10

        for count in range(attempts):
            console.print(Panel(f"[bold]Crawling[/] {ARGS.crawl_start}  [dim](depth {iterations}, attempt {count+1}/{attempts})[/]", expand=False))
            scrape_iterative(ARGS.crawl_start, iterations)
            spacer(1)
    except Exception:
        pass


def ips():
    try:
        cmd = 'curl -k -s --show-error --connect-timeout 3 -I --max-time 5 -A BlackSun www.testmyids.com'
        UI.run_quiet(cmd, timeout=10)
    except Exception:
        pass


def github_domain_check_download_file(url, local_filename):
    try:
        with requests.get(url, stream=True, verify=False, timeout=5) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        return True
    except Exception:
        return False


def github_domain_check_read_file(local_filename, num_random_domains=10):
    try:
        with open(local_filename, 'r', encoding='utf-8') as f:
            all_domains = f.readlines()
        valid_domains = [d.strip() for d in all_domains if d.strip() and not d.strip().startswith('#')]
    except Exception:
        return
    selected = valid_domains if len(valid_domains) < num_random_domains else random.sample(valid_domains, num_random_domains)
    for domain in selected:
        url = f"https://{domain}"
        try:
            requests.get(url, timeout=1, verify=False, allow_redirects=True)
        except Exception:
            pass
        time.sleep(0.3)


def github_domain_check():
    try:
        github_domain_list = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt"
        local_domains_filename = "git-domains-list"
        if not os.path.exists(local_domains_filename):
            if not github_domain_check_download_file(github_domain_list, local_domains_filename):
                return
        github_domain_check_read_file(local_domains_filename, num_random_domains=10)
    except Exception:
        pass


def github_phishing_domain_check_download_file(url, local_filename):
    try:
        with requests.get(url, stream=True, verify=False, timeout=5) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        return True
    except Exception:
        return False


def github_phishing_domain_check_read_file(local_filename, num_random_domains=10):
    try:
        with open(local_filename, 'r', encoding='utf-8') as f:
            all_domains = f.readlines()
        valid_domains = [d.strip() for d in all_domains if d.strip() and not d.strip().startswith('#')]
    except Exception:
        return
    selected = valid_domains if len(valid_domains) < num_random_domains else random.sample(valid_domains, num_random_domains)
    for domain in selected:
        url = f"https://{domain}"
        try:
            requests.get(url, timeout=1, verify=False, allow_redirects=True)
        except Exception:
            pass
        time.sleep(0.3)


def github_phishing_domain_check():
    try:
        github_domain_list = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt"
        local_domains_filename = "git-phishing-list"
        if not os.path.exists(local_domains_filename):
            if not github_phishing_domain_check_download_file(github_domain_list, local_domains_filename):
                return
        github_phishing_domain_check_read_file(local_domains_filename, num_random_domains=10)
    except Exception:
        pass


# --------------------------------------------------------------------------------------------------
# CLI + Main
# --------------------------------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        STARTTIME = time.time()

        parser = argparse.ArgumentParser(
            description=(
                "Traffic Generator: simulate various network traffic types for testing, "
                "performance analysis, or security simulations."
            ),
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
        traffic_group.add_argument('--suite', type=str.lower, choices=suite_choices, default='all')
        traffic_group.add_argument('--size', type=str.upper, choices=size_choices, default='M')

        timing_group = parser.add_argument_group('Timing and Loop Options')
        timing_group.add_argument('--loop', action="store_true", required=False)
        timing_group.add_argument('--max-wait-secs', type=int, default=20)
        timing_group.add_argument('--nowait', action="store_true", required=False)

        specific_suite_group = parser.add_argument_group('Suite-Specific Options')
        specific_suite_group.add_argument('--crawl-start', default='https://data.commoncrawl.org')

        ARGS = parser.parse_args()

        WATCHDOG = Watchdog(timeout_seconds=600)

        # Run config panel
        console.rule("[bold green]Starting Run")
        cfg = Table(show_lines=False, show_header=False, box=None, expand=False)
        cfg.add_row("Suite", ARGS.suite)
        cfg.add_row("Size", ARGS.size)
        cfg.add_row("Loop", str(ARGS.loop))
        cfg.add_row("Max Wait (s)", str(ARGS.max_wait_secs))
        cfg.add_row("No Wait", str(ARGS.nowait))
        cfg.add_row("Crawl Start", ARGS.crawl_start)
        console.print(cfg)

        size_map = {'S': 'small', 'M': 'medium', 'L': 'large', 'XL': 'extra-large'}
        size_label = size_map.get(ARGS.size, ARGS.size)
        console.rule(f"[bold blue]Running suite: {ARGS.suite.upper()} (size: {size_label.upper()})")
        console.print(Panel("\n".join([
            f"Loop: {ARGS.loop}",
            f"Max Wait: {ARGS.max_wait_secs}s",
            f"NoWait: {ARGS.nowait}",
            f"Crawl Start: {ARGS.crawl_start}",
        ]), title="Run Config", border_style="blue", expand=False))

        # Build testsuite based on selection
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
            testsuite = []

        # Execute
        if ARGS.loop:
            while True:
                func = random.choice(testsuite)
                UI.run_one(func)
                WATCHDOG.kick()
                # random wait
                if not ARGS.nowait:
                    wait_sec = random.randint(2, int(ARGS.max_wait_secs))
                    console.print(f"[dim]Sleeping {wait_sec}s before next loop…[/]")
                    for _ in range(wait_sec):
                        time.sleep(1)
                console.print("[dim]Looping…[/]")
        else:
            random.shuffle(testsuite)
            for func in testsuite:
                UI.run_one(func)
                WATCHDOG.kick()
                # single-run: no waits

            # End-of-run summary
            UI.print_summary()
            UI.write_summaries(ARGS.suite, STARTTIME)
            console.print(f"[bold blue]Total Run Time:[/] {time.strftime('%H:%M:%S', time.gmtime(time.time() - STARTTIME))}")

    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        # last resort error
        try:
            console.print(f"[red]An error occurred:[/] {e}")
        except Exception:
            print(f"An error occurred: {e}")
