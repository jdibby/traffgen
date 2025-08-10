#!/usr/local/bin python3

### Import of required modules
import time, os, sys, argparse, random, threading, signal, urllib.request, urllib3, requests, runpy, socket, ssl, subprocess, ftplib, traceback
from bs4 import BeautifulSoup
from time import sleep
from urllib.parse import urljoin
from tqdm import tqdm
from colorama import Fore, Back, Style
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from endpoints import *

try:
    import requests
except Exception:
    requests = None
try:
    import paramiko
except Exception:
    class _P: class SSHException(Exception): pass
    paramiko = _P()
try:
    import dns.exception
except Exception:
    class _D: class DNSException(Exception): pass
    dns = _D()
try:
    import pysnmp.error
except Exception:
    class _S: class PySnmpError(Exception): pass
    pysnmp = _S()
try:
    import ntplib
except Exception:
    class _N: class NTPException(Exception): pass
    ntplib = _N()

### Disable SSL warning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context

### Watchdog used for restarting container if no activity is detected
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
                print("[WATCHDOG] No activity detected. Exiting to force container restart...")
                os._exit(1)
            time.sleep(1)

### Grab container IP address
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
        print(f"Failed to determine container IP: {e}")
        return "127.0.0.1"

### Continue with the rest of the generator (always runs even if BGP initialization fails)
def bgp_peering():
    try:
        print(Fore.BLACK)
        print(Back.GREEN + "##############################################################")
        print(Style.RESET_ALL)

        ### Start gobgpd in the background
        try:
            gobgpd_proc = subprocess.Popen([
                "gobgpd", "--api-hosts", "127.0.0.1:50051"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print("Started gobgpd")
        except Exception as e:
            print(f"Failed to start gobgpd: {e}")
            gobgpd_proc = None  # Let the rest of the script keep on trucking

        ### Wait for gobgpd API to come up
        def gobgp_wait_api(host, port, timeout=10):
            start = time.time()
            while time.time() - start < timeout:
                try:
                    with socket.create_connection((host, port), timeout=1):
                        return True
                except OSError:
                    time.sleep(0.5)
            return False

        ### Configure BGP
        if gobgpd_proc and gobgp_wait_api("127.0.0.1", 50051, timeout=15):
            try:
                print("Configuring global BGP instance...")
                router_id = get_container_ip()
                print(f"Using container IP {router_id} as BGP router-id")
                subprocess.run([
                    "gobgp", "-u", "127.0.0.1", "-p", "50051",
                    "global", "as", "65555", "router-id", router_id
                ], check=True)

                ### Add neighbors using gobgp CLI
                for neighbor_ip in bgp_neighbors:
                    print(f"Adding BGP neighbor: {neighbor_ip}")
                    result = subprocess.run([
                        "gobgp", "-u", "127.0.0.1", "-p", "50051",
                        "neighbor", "add", neighbor_ip, "as", "65555"
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                    if result.returncode != 0:
                        print(f"Error adding neighbor {neighbor_ip}:\n{result.stderr.decode().strip()}")
                    else:
                        print(f"Successfully added neighbor {neighbor_ip}")
            except Exception as e:
                print(f"BGP configuration failed: {e}")
        else:
            print("WARNING: gobgpd not ready — skipping BGP setup")
    except (subprocess.SubprocessError, FileNotFoundError, TimeoutError) as e:
        print(f"[bgp_peering] subprocess error: {e}")
    except (socket.error, OSError) as e:
        print(f"[bgp_peering] socket/os error: {e}")
    except Exception as e:
        print(f"[bgp_peering] unexpected error: {e}")

    ### Waiting 10 seconds before killing gobgpd
    print("Waiting 10 seconds before terminating gobgpd...")
    time.sleep(10)

    ### Silently killing gobgpd
    if gobgpd_proc:
        gobgpd_proc.terminate()
        try:
            gobgpd_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            gobgpd_proc.kill()

### Bigfile download via http
def bigfile():
    try:
        url = 'http://ipv4.download.thinkbroadband.com/5GB.zip'
        response = requests.get(url, stream=True)
        total_size = int(response.headers.get('content-length', 0))

        ### Display progress information
        print(Fore.BLACK + Back.GREEN + "##############################################################")
        print(Style.RESET_ALL)
        print("Testing Bigfile: Downloading 5GB ZIP File")
        print(Fore.BLACK + Back.GREEN + "##############################################################")
        print(Style.RESET_ALL)

        ### Progress bar
        with tqdm(total=total_size, unit='B', unit_scale=True, desc='Downloading', ascii=True) as progress_bar:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:  # Filter out keep-alive new chunks
                    progress_bar.update(len(chunk))
    except (requests.exceptions.RequestException, socket.error, ssl.SSLError, OSError) as e:
        print(f"[bigfile] network/file error: {e}")
    except Exception as e:
        print(f"[bigfile] unexpected error: {e}")    

### DNS Test suites
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
            # Size limit of DNS servers to hit
            if count_ips < target_ips:
                random.shuffle(dns_urls)
                for count_urls, url in enumerate(dns_urls):
                    # Size limit of URLs to lookup
                    if count_urls < target_urls:
                        cmd = "dig %s @%s +time=1" % (url, ip)
                        print (Fore.BLACK)
                        print (Back.GREEN + "##############################################################")
                        print (Style.RESET_ALL)
                        print ("Testing DNS: Query %s (%d of %d) against %s (%d of %d)" %(url, (count_urls+1), target_urls, ip, (count_ips+1), target_ips))
                        print (Fore.BLACK)
                        print (Back.GREEN + "##############################################################")
                        print (Style.RESET_ALL)
                        subprocess.call(cmd, shell=True)
                        time.sleep(0.25) # Rate limit to prevent tripping alarms
    except (dns.exception.DNSException, socket.error) as e:
        print(f"[dig_random] DNS error: {e}")
    except (subprocess.SubprocessError, FileNotFoundError, TimeoutError) as e:
        print(f"[dig_random] subprocess error: {e}")
    except Exception as e:
        print(f"[dig_random] unexpected error: {e}")

### FTP Test suites
def ftp_random():
    if ARGS.size == 'S':
        target = '1MB'
    elif ARGS.size == 'M':
        target = '10MB'
    elif ARGS.size == 'L':
        target = '100MB'
    elif ARGS.size == 'XL':
        target = '1GB'
    cmd = 'curl --limit-rate 3M -k --show-error --connect-timeout 5 -o /dev/null ftp://speedtest:speedtest@ftp.otenet.gr/test' + target + '.db'
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    print ("Testing FTP: Download %s DB File" %(target))
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    subprocess.call(cmd, shell=True)

### HTTP Test suites
def http_random():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing HTTP: (%d of %d): %s" %((count_urls+1), target_urls, url))
            print (f"Agent: {user_agent}")
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

### HTTP downloads
def http_download_zip():
    random.shuffle(user_agents)
    user_agent = user_agents[0]
    if ARGS.size == 'S':
        target = '15MB'
        cmd = f"curl --limit-rate 3M -k  --show-error --connect-timeout 5 -L -o /dev/null -A '{user_agent}' https://link.testfile.org/{target}"
    elif ARGS.size == 'M':
        target = '30MB'
        cmd = f"curl --limit-rate 3M -k  --show-error --connect-timeout 5 -L -o /dev/null-A '{user_agent}' https://link.testfile.org/{target}"
    elif ARGS.size == 'L':
        target = '100MB'
        cmd = f"curl --limit-rate 3M -k  --show-error --connect-timeout 5 -L -o /dev/null -A '{user_agent}' https://link.testfile.org/{target}"
    elif ARGS.size == 'XL':
        target = '1GB'
        cmd = f"curl --limit-rate 3M -k  --show-error --connect-timeout 5 -L -o /dev/null -A '{user_agent}' https://link.testfile.org/{target}"
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    print ("Testing HTTP: Download %s ZIP File" %(target))
    print (f"Agent: {user_agent}")
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    subprocess.call(cmd, shell=True)

### HTTP downloads of targz files
def http_download_targz():
    cmd = 'curl --limit-rate 3M -k  --show-error --connect-timeout 5 -o /dev/null http://wordpress.org/latest.tar.gz'
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    print ("Testing HTTP: Download Wordpress File")
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    subprocess.call(cmd, shell=True)
    
### Nikto Scans
def web_scanner():
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
    
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    print ("Nikto Scanning: testmyids.com")
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    subprocess.call(cmd, shell=True)

### HTTPS Test suites
def https_random():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing HTTPS (%d of %d): %s" %((count_urls+1), target_urls, url))
            print (f"Agent: {user_agent}")
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

### AI Test suite
def ai_https_random():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing AI URLs (%d of %d): %s" %((count_urls+1), target_urls, url))
            print (f"Agent: {user_agent}")
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)
            
### Test ad filtering
def ads_random():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing AI URLs (%d of %d): %s" %((count_urls+1), target_urls, url))
            print (f"Agent: {user_agent}")
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

### HTTPS crawl through URLs
def https_crawl():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Crawling HTTPS (%d deep, site %d of %d) starting from %s" %(iterations, (count_urls+1), target_urls, url))
            print (f"Agent: {user_agent}")
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            scrape_iterative(url, iterations)

### Pornography crawl through URLs
def pornography_crawl():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Crawling Pornography (%d deep, site %d of %d) starting from %s" %(iterations, (count_urls+1), target_urls, url))
            print (f"Agent: {user_agent}")
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            scrape_iterative(url, iterations)

### Malware Test suites
def malware_random():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing Malware Site: (%d of %d): %s" %((count_urls+1), target_urls, url))
            print (f"Agent: {malware_user_agent}")
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

### ICMP Test
def ping_random():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing ICMP (%d of %d): Ping %s" %((count_ips+1), target_ips, ip))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)
            
### Metasploit Checks
def metasploit_check():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Running Metasploit Check (%d of %d): %s" %((count_ms+1), ms_checks, rc_file))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)
            
### SNMP test
def snmp_random():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print(f"SNMP Polling ({count_ips+1} of {target_ips}): Polling {ip} with community '{community}'")
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

### Traceroute test
def traceroute_random():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing ICMP (%d of %d): Traceroute to %s" %((count_ips+1), target_ips, ip))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

### Netflix Test
def speedtest_fast():
    if ARGS.size == 'S':
        duration = 1
    elif ARGS.size == 'M':
        duration = 2
    elif ARGS.size == 'L':
        duration = 3
    elif ARGS.size == 'XL':
        duration = 4

    print(Fore.BLACK)
    print(Back.GREEN + "##############################################################")
    print(Style.RESET_ALL)
    print("Testing Netflix: Fast.com Speedtest")
    print(Fore.BLACK)
    print(Back.GREEN + "##############################################################")
    print(Style.RESET_ALL)

    timeout_per_test = 20

    for i in range(1, duration + 1):
        print(f"Starting Fast.com test {i} of {duration} (timeout: {timeout_per_test}s)...")
        try:
            result = subprocess.run(
                'python3 -m fastcli',
                shell=True,
                check=True,
                timeout=timeout_per_test,
                capture_output=True,
                text=True
            )
            print(f"Test {i} completed successfully.")
            if result.stdout:
                print(f"Output:\n{result.stdout}")
            if result.stderr:
                print(f"Error Output:\n{result.stderr}")
        except subprocess.TimeoutExpired:
            print(f"Test {i} timed out after {timeout_per_test} seconds. Moving to the next test.")
        except subprocess.CalledProcessError as e:
            print(f"Test {i} failed with error: {e}")
            print(f"Command output (stdout):\n{e.stdout}")
            print(f"Command error (stderr):\n{e.stderr}")
        except Exception as e:
            print(f"An unexpected error occurred during test {i}: {e}")

    print("All Speedtest Tests Attempted.")
    pass

### NMAP Test (1024 ports)
def nmap_1024os():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing NMAP: NMAP Scan First 1024 Ports of %s" %(ip))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)


### NMAP Test (CVE)        
def nmap_cve():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing NMAP: NMAP CVE Scan of %s" %(ip))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

### NTP Test                                   
def ntp_random():
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
            print (Fore.BLACK)         
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing NTP: Update time against %s" %(url))
            print (Fore.BLACK)            
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL) 
            subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

### SSH Test
def ssh_random():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing SSH (%d of %d): SSH to %s" %((count_ips+1), target_ips, ip))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

### URL Reponse Time Test
def urlresponse_random():
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
                time = requests.get(url, timeout=3).elapsed.total_seconds()
            except requests.ConnectionError as e:
                continue
            except requests.ReadTimeout as e:
                continue
            except requests.ChunkedEncodingError as e:
                continue
            except urllib3.ProtocolError as e:
                continue
            except:
                pass
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing HTTPS (%d of %d): %s" %((count_urls+1), target_urls, url))
            print ("Total Transaction Time -- ", time)
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)

### Virus Simulation
def virus_sim():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing Virus Simulation: Download %s" %(url))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

### DLP Tests            
def dlp_sim_https():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("DLP Simulation (HTTPS): Download %s" %(url))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

### Malware Tests            
def malware_download():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Malware File Download (HTTPS): Download %s" %(url))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

### Squatting Tests            
def squatting_domains():
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Generating Squatting Domains Based On %s" %(url))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

### Web Crawl
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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Crawling from %s (%d deep, attempt %d of %d)" %(ARGS.crawl_start, iterations, count+1, attempts))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            scrape_iterative(ARGS.crawl_start, iterations)
    except (requests.exceptions.RequestException, socket.error, ssl.SSLError, ValueError) as e:
        print(f"[webcrawl] http/parse error: {e}")
    except Exception as e:
        print(f"[webcrawl] unexpected error: {e}")

### Trigger an IPS system
def ips():
    cmd = 'curl -k -s --show-error --connect-timeout 3 -I --max-time 5 -A BlackSun www.testmyids.com'
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    print ("Testing IPS: BlackSun")
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    subprocess.call(cmd, shell=True)

### GITHUB Bad Domains Testing
def github_domain_check_download_file(url, local_filename):
    print(f"Attempting to download '{url}' to '{local_filename}'...")
    try:
        with requests.get(url, stream=True, verify=False, timeout=5) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(f"Successfully downloaded '{local_filename}'.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error downloading file: {e}")
        return False
    except IOError as e:
        print(f"Error writing file to disk: {e}")
        return False

def github_domain_check_read_file(local_filename, num_random_domains=10):
    print(f"\nReading domains from local file: {local_filename}")
    try:
        with open(local_filename, 'r', encoding='utf-8') as f:
            all_domains = f.readlines()
        valid_domains = [
            domain.strip() for domain in all_domains
            if domain.strip() and not domain.strip().startswith('#')
        ]
        print(f"Successfully read {len(valid_domains)} domains from local file")
    except FileNotFoundError:
        print(f"Error: file '{local_filename}' not found")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    if len(valid_domains) < num_random_domains:
        print(f"Warning: Only {len(valid_domains)} domains available, selecting all of them")
        selected_domains = valid_domains
    else:
        selected_domains = random.sample(valid_domains, num_random_domains)
        print(f"Selected {len(selected_domains)} random domains for querying")

    print("\nStarting query operations for selected domains...\n")
    for i, domain in enumerate(selected_domains):
        url = f"https://{domain}"
        print(f"[{i+1}/{len(selected_domains)}] Attempting to query: {url}")

        try:
            response = requests.get(url, timeout=1, verify=False, allow_redirects=True)
            print(f"  Status: {response.status_code} - OK (Redirected to: {response.url if response.history else 'N/A'})")
        except requests.exceptions.ConnectionError:
            print(f"  Error: Connection failed for {url}")
        except requests.exceptions.Timeout:
            print(f"  Error: Timeout reached for {url}")
        except requests.exceptions.HTTPError as e:
            print(f"  Error: HTTP error {e.response.status_code} for {url}")
        except requests.exceptions.RequestException as e:
            print(f"  Error: An unexpected request error occurred for {url}: {e}")
        except Exception as e:
            print(f"  Error: An unhandled error occurred for {url}: {e}")
        time.sleep(0.3)

    print("\nQuery operations completed for selected domains.")

def github_domain_check():
    github_domain_list = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt"
    local_domains_filename = "git-domains-list"

    if not os.path.exists(local_domains_filename):
        print("Local domain file not found. Downloading now...")
        if not github_domain_check_download_file(github_domain_list, local_domains_filename):
            print("Failed to download the domain list. Exiting.")
            exit()
    else:
        print(f"Local domain file '{local_domains_filename}' already exists. Skipping download.")

    github_domain_check_read_file(local_domains_filename, num_random_domains=10)

### GITHUB Phishing Domains Testing
def github_phishing_domain_check_download_file(url, local_filename):
    print(f"Attempting to download '{url}' to '{local_filename}'...")
    try:
        with requests.get(url, stream=True, verify=False, timeout=5) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(f"Successfully downloaded '{local_filename}'.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error downloading file: {e}")
        return False
    except IOError as e:
        print(f"Error writing file to disk: {e}")
        return False

def github_phishing_domain_check_read_file(local_filename, num_random_domains=10):
    print(f"\nReading domains from local file: {local_filename}")
    try:
        with open(local_filename, 'r', encoding='utf-8') as f:
            all_domains = f.readlines()
        valid_domains = [
            domain.strip() for domain in all_domains
            if domain.strip() and not domain.strip().startswith('#')
        ]
        print(f"Successfully read {len(valid_domains)} domains from local file")
    except FileNotFoundError:
        print(f"Error: file '{local_filename}' not found")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    if len(valid_domains) < num_random_domains:
        print(f"Warning: Only {len(valid_domains)} domains available, selecting all of them")
        selected_domains = valid_domains
    else:
        selected_domains = random.sample(valid_domains, num_random_domains)
        print(f"Selected {len(selected_domains)} random domains for querying")

    print("\nStarting query operations for selected domains...\n")
    for i, domain in enumerate(selected_domains):
        url = f"https://{domain}"
        print(f"[{i+1}/{len(selected_domains)}] Attempting to query: {url}")

        try:
            response = requests.get(url, timeout=1, verify=False, allow_redirects=True)
            print(f"  Status: {response.status_code} - OK (Redirected to: {response.url if response.history else 'N/A'})")
        except requests.exceptions.ConnectionError:
            print(f"  Error: Connection failed for {url}")
        except requests.exceptions.Timeout:
            print(f"  Error: Timeout reached for {url}")
        except requests.exceptions.HTTPError as e:
            print(f"  Error: HTTP error {e.response.status_code} for {url}")
        except requests.exceptions.RequestException as e:
            print(f"  Error: An unexpected request error occurred for {url}: {e}")
        except Exception as e:
            print(f"  Error: An unhandled error occurred for {url}: {e}")
        time.sleep(0.3)

    print("\nQuery operations completed for selected domains.")

def github_phishing_domain_check():
    github_domain_list = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt"
    local_domains_filename = "git-phishing-list"

    if not os.path.exists(local_domains_filename):
        print("Local domain file not found. Downloading now...")
        if not github_domain_check_download_file(github_domain_list, local_domains_filename):
            print("Failed to download the domain list. Exiting.")
            exit()
    else:
        print(f"Local domain file '{local_domains_filename}' already exists. Skipping download.")

    github_domain_check_read_file(local_domains_filename, num_random_domains=10)

### Wait timer progress bar
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

### Randomize and run tests
def run_test(list):
    if ARGS.size == 'S':
        size = 'small'
    elif ARGS.size == 'M':
        size = 'medium'
    elif ARGS.size == 'L':
        size = 'large'
    elif ARGS.size == 'XL':
        size = 'extra-large'
    print (Fore.WHITE)
    print (Back.BLUE)
    print ("  [i] Running test suite %s size %s" %(ARGS.suite.upper(), size.upper()), end=" ", flush=True)
    if ARGS.loop:
        print ("in a CONTINUOUS LOOP with MAX %i SEC interval" %(int(ARGS.max_wait_secs)), end=" ", flush=True)
        print(Style.RESET_ALL)
    if ARGS.nowait:
        print ("without waiting", end=" ", flush=True)
        print(Style.RESET_ALL)
    print(Style.RESET_ALL)
    time.sleep(1)

    if ARGS.loop:
        while True:
            ### For looping, choose a test at random from the list for each iteration
            func = random.choice(list)
            func()
            WATCHDOG.kick()
            finish_test()
    else:
        ### For single runs, run tests in random order
        random.shuffle(list)
        for func in list:
            func()
            WATCHDOG.kick()
            finish_test()

### Randomize a wait time between 2 and max seconds
def finish_test():
    if ARGS.loop:
        print ("")
        print ("  [i] Test complete", end="", flush=True)
        if not ARGS.nowait:
            max_wait = int(ARGS.max_wait_secs)
            wait_sec = random.randint(2,max_wait)
            print (". Pausing for %d seconds: " %(wait_sec))
            for i in progressbar(range(wait_sec), "      ", 32):
                time.sleep(1)
        else:
            print ("")
        print ("")
        print ("  [i] Looping...")

### Pull an updated list of colocated containers to test against
def replace_all_endpoints(url):
    print ("")
    print ("  [i] Replacing endpoints.py with %s" %(url), end=" ", flush=True)
    response = urllib.request.urlopen(url)
    data = response.read()
    text = data.decode('utf-8')
    with open('endpoints.py', 'w') as filetowrite:
        filetowrite.write(text)
    print ("")

### Grab random links from website
def scrape_single_link(url):
    sleep(random.uniform(0.2, 2))

    random.shuffle(user_agents)
    user_agent = user_agents[0]

    print(f"Visiting: {url}")
    print (f"Agent: {user_agent}")
    print ("")

    try:
        response = requests.request(
            method="GET",
            url=url,
            timeout=2,
            allow_redirects=True,
            headers={'User-Agent': user_agents[0]},
            verify=False  # Disable SSL cert verification
        )
        response.raise_for_status()

        response.encoding = response.apparent_encoding or 'utf-8'
        html = response.text

    except requests.exceptions.HTTPError as e:
        if e.response and e.response.status_code == 404:
            return None  # Not found, just skip
        print(f"HTTP error for {url}: {e}")
        return None
    except requests.exceptions.SSLError as e:
        print(f"SSL error for {url}: {e}")
        return None
    except requests.exceptions.Timeout:
        print(f"Timeout for {url}")
        return None
    except requests.exceptions.TooManyRedirects:
        print(f"Too many redirects for {url}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"General failure for {url}: {e}")
        return None

    # Parse HTML only if request was successful
    soup = BeautifulSoup(html, 'html.parser')

    all_links = soup.find_all("a")
    random.shuffle(all_links)

    for link in all_links:
        href = link.get('href')
        if not href or '#' in href:
            continue
        if href.startswith("//") or href.startswith("/"):
            resolved = urljoin(url, href)
            print(f"Found: {resolved}")
            return resolved
        elif href.startswith("http"):
            print(f"Found: {href}")
            return href

    print("No Links Found")
    return None

### Loop over scraped links
def scrape_iterative(base_url, iterations=3):
    next_link = scrape_single_link(base_url)
    for i in range(iterations):
        if next_link and next_link is not None:
            next_link = scrape_single_link(next_link)
        else:
            break

### Menus
if __name__ == "__main__":
    try:
        ### Start time measured since the epoch (floating point)
        STARTTIME = time.time()

        ### Argument Parsing (CLI variables)
        parser = argparse.ArgumentParser(
            description="""Traffic Generator: A versatile tool for simulating various network traffic types.
Use this script to generate realistic network activity for testing,
performance analysis, or security simulations.

""", ### Added an extra newline
            formatter_class=argparse.RawTextHelpFormatter,
            usage=argparse.SUPPRESS
        )

        ### Define common choices to avoid repetition
        suite_choices = [
            'all', 'ads', 'ai', 'bigfile', 'bgp', 'crawl', 'dlp', 'dns', 'ftp',
            'domain-check', 'http', 'https', 'icmp', 'ips', 'malware-agents', 'malware-download',
            'metasploit-check', 'netflix', 'nmap', 'ntp', 'phishing-domains',
            'pornography', 'snmp', 'ssh', 'squatting', 'url-response', 'virus', 'web-scanner',
        ]
        size_choices = ['S', 'M', 'L', 'XL']

        ### Add empty arguments with blank help text as separators
        parser.add_argument('--_spacer1', action='store_true', help=argparse.SUPPRESS) # Suppress this arg from appearing
        parser.add_argument('--_spacer2', action='store_true', help=argparse.SUPPRESS) # Suppress this arg from appearing

        ### Group for core traffic generation options
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

        ### Group for timing and looping options
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
            help='Maximum possible time (in seconds) for random intervals between tests or loops. Default: 40 seconds.\n\n'
        )
        timing_group.add_argument(
            '--nowait',
            action="store_true",
            required=False,
            help='Disable random waiting intervals between tests or loops, making them run consecutively.\n\n'
        )

        # Group for specific suite options
        specific_suite_group = parser.add_argument_group('Suite-Specific Options')
        specific_suite_group.add_argument(
            '--crawl-start',
            action="store",
            required=False,
            default='https://data.commoncrawl.org',
            help='For the "crawl" suite: Specifies the initial URL to start web crawling from. Default: https://data.commoncrawl.org'
        )

        ARGS = parser.parse_args()
        
        WATCHDOG = watchdog(timeout_seconds=600)

        # Output Summary
        print(Fore.BLACK + Back.GREEN + "##############################################################")
        print(Style.RESET_ALL)
        print(f"Running Suite: {ARGS.suite}")
        print(f"Test Size: {ARGS.size}")
        print(f"Looping Enabled: {ARGS.loop}")
        print(f"Max Wait Time (secs): {ARGS.max_wait_secs}")
        print(f"No Wait Enabled: {ARGS.nowait}")
        print(f"Crawl Start URL: {ARGS.crawl_start}")
        print(Fore.BLACK + Back.GREEN + "##############################################################")
        print(Style.RESET_ALL)
        time.sleep(5)

        ### All tests and the functions they call    
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
            random.shuffle(testsuite)  # Shuffle the entire suite for random execution
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

        ### SEND IT!
        run_test(testsuite)

        ### End time is time since epoch minus the start time since epoch (floating point)
        ENDTIME = time.time()-STARTTIME

        ### Print run time of script
        print (Fore.WHITE)
        print (Back.BLUE)
        print ("  [i] Total Run Time: %s" % (time.strftime("%H:%M:%S", time.gmtime(ENDTIME))))
        print (Style.RESET_ALL)

    except Exception as e:
        print(f"An error occurred: {e}")

    ### Keyboard Ctrl-C Interrupt
    except KeyboardInterrupt:
        sys.exit(0)
