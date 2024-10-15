#!/usr/local/bin python3

### Importing of required modules
import time
import sys
import subprocess
import argparse
import random
import urllib.request
import ssl
import requests

from bs4 import BeautifulSoup
from time import sleep
from urllib.parse import urljoin
from tqdm import tqdm
from colorama import Fore, Back, Style

### Bigfile Test 
def bigfile():
    url = 'http://ipv4.download.thinkbroadband.com/5GB.zip'
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))

    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    print ("Testing Bigfile: Download 5GB ZIP File")
    print (Fore.BLACK) 
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)

    with tqdm(total=total_size, unit='B', unit_scale=True, desc='Downloading', ascii=True) as progress_bar:
        for chunk in response.iter_content(chunk_size=1024):
        # Update the progress bar with the size of the chunk
            progress_bar.update(len(chunk))

### DNS Test suites
def dig_random():
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
    cmd = 'curl --limit-rate 3M --insecure  --show-error --connect-timeout 5 -o /dev/null ftp://speedtest:speedtest@ftp.otenet.gr/test' + target + '.db'
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
            user_agent = (user_agents[0]) 
            cmd = f"curl --insecure --silent --show-error --connect-timeout 5 -I --max-time 5 -A {user_agent} {url}"
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            #print ("Testing HTTP: (%d of %d): %s" %((count_urls+1), target_urls, url))
            print (f"Agent: {user_agent}")
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

def http_download_zip():
    random.shuffle(user_agents)
    user_agent = (user_agents[0])
    if ARGS.size == 'S':
        target = '15MB'
        cmd = f'curl --limit-rate 3M --insecure  --show-error --connect-timeout 5 -L -o /dev/null -A {user_agent} https://link.testfile.org/'
    elif ARGS.size == 'M':
        target = '30MB'
        cmd = f'curl --limit-rate 3M --insecure  --show-error --connect-timeout 5 -L -o /dev/null-A {user_agent} https://link.testfile.org/'
    elif ARGS.size == 'L':
        target = '100MB'
        cmd = f'curl --limit-rate 3M --insecure  --show-error --connect-timeout 5 -L -o /dev/null -A {user_agent} https://link.testfile.org/'
    elif ARGS.size == 'XL':
        target = '1GB'
        cmd = f'curl --limit-rate 3M --insecure  --show-error --connect-timeout 5 -L -o /dev/null -A {user_agent} https://link.testfile.org/'
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    #print ("Testing HTTP: Download %s ZIP File" %(target))
    print (f"Agent: {user_agent}")
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    subprocess.call(cmd, shell=True)

def http_download_targz():
    cmd = 'curl --limit-rate 3M --insecure  --show-error --connect-timeout 5 -o /dev/null http://wordpress.org/latest.tar.gz'
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    print ("Testing HTTP: Download Wordpress File")
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
            cmd = "curl --insecure --silent --show-error --connect-timeout 5 -I --max-time 5 %s" % url
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing HTTPS (%d of %d): %s" %((count_urls+1), target_urls, url))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

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
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Crawling HTTPS (%d deep, site %d of %d) starting from %s" %(iterations, (count_urls+1), target_urls, url))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            scrape_iterative(url, iterations)

### ICMP Test suites
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
         duration = 3
    elif ARGS.size == 'L':
         duration = 5
    elif ARGS.size == 'XL':
         duration = 10
    cmd = 'for i in `seq 1 %i`; do python3 -m fastcli; done' % (duration)
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    print ("Testing Netflix: Fast.com Speedtest")
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    subprocess.call(cmd, shell=True)
    pass

### NMAP Test
def nmap_1024():
    random.shuffle(nmap_endpoints)
    for ip in nmap_endpoints:
        cmd = 'nmap -p 1-1024 %s -T5' % ip
        print (Fore.BLACK)
        print (Back.GREEN + "##############################################################")
        print (Style.RESET_ALL)
        print ("Testing NMAP: NMAP Scan First 1024 Ports of %s" %(ip))
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
            if ARGS.os == 'alpine':
                cmd = "chronyd -q 'server %s iburst'" % (url)
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing NTP: Update time against %s" %(url))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

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

### EICAR Virus Simulation
def virus_sim_http():
    if ARGS.size == 'S':
        target_urls = 1
    elif ARGS.size == 'M':
        target_urls = 2
    elif ARGS.size == 'L':
        target_urls = 3
    elif ARGS.size == 'XL':
        target_urls = len(eicar_http_endpoints)
    random.shuffle(eicar_http_endpoints)
    for count_urls, url in enumerate(eicar_http_endpoints):
        if count_urls < target_urls:
            cmd = "curl --limit-rate 3M --insecure  --show-error --connect-timeout 5 -o /dev/null %s" % url
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing EICAR Virus Simulation (HTTP): Download %s" %(url))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

def virus_sim_https():
    if ARGS.size == 'S':
        target_urls = 1
    elif ARGS.size == 'M':
        target_urls = 2
    elif ARGS.size == 'L':
        target_urls = 3
    elif ARGS.size == 'XL':
        target_urls = len(eicar_https_endpoints)
    random.shuffle(eicar_https_endpoints)
    for count_urls, url in enumerate(eicar_https_endpoints):
        if count_urls < target_urls:
            cmd = "curl --limit-rate 3M --insecure --show-error --connect-timeout 5 -o /dev/null %s" % url
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing EICAR Virus Simulation (HTTPS): Download %s" %(url))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

### Web Crawl
def webcrawl():
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

def ips():
    cmd = 'curl -A BlackSun www.testmyids.com'
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    print ("Testing IPS: BlackSun")
    print (Fore.BLACK)
    print (Back.GREEN + "##############################################################")
    print (Style.RESET_ALL)
    subprocess.call(cmd, shell=True)

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
            cmd = "curl --insecure --silent --show-error --connect-timeout 5 -I --max-time 5 %s" % url
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            print ("Testing Ad Sites (%d of %d): %s" %((count_urls+1), target_urls, url))
            print (Fore.BLACK)
            print (Back.GREEN + "##############################################################")
            print (Style.RESET_ALL)
            subprocess.call(cmd, shell=True)

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
            # For looping, chose a test at random from the list for each iteration
            func = random.choice(list)
            func()
            finish_test()
    else:
        # For single runs, run tests in random order
        random.shuffle(list)
        for func in list:
            func()
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


### Package updates required for script
def apt_acquisitions():
    subprocess.call("apk add traceroute mtr nmap curl wget ntp dnsutils fping snmp", shell=True)
    subprocess.call("apk update", shell=True)

### Pull an updated list of co-located containers to test against
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
    # Randomize user agent and time between requets
    sleep(random.uniform(0.2, 2))
    random.shuffle(user_agents)

    # Get site contents
    try:
        response = requests.request(
            method="GET",
            url=url,
            timeout=2,
            allow_redirects=True,
            headers = {
                'User-Agent': user_agents[0],
            }
        )
        response.raise_for_status()
    except requests.exceptions.HTTPError as http_error:
        if http_error.response.status_code == 404:
            pass
        else:
            print(http_error)
            return None
    except requests.exceptions.Timeout:
        print(f"Error: Timeout for {url}")
        return None
    except requests.exceptions.TooManyRedirects:
        print(f"Error: Too many redirects for {url}")
        return None
    except requests.exceptions.RequestException:
        print(f"Error: General failure for {url}")
        return None

    # Parse HTML
    soup = BeautifulSoup(response.content, 'html.parser')

    # Print page URL and title
    try:
        print(f"{url} - {soup.title.string.encode('unicode_escape').decode('utf-8')}")
    except:
        print(f"{url} - no title")

    # Find and randomize all links on page
    all_links = soup.find_all("a")
    random.shuffle(all_links)

    # Pick one, format it, and return it
    for link in all_links:
        if link.has_attr('href'):
            if '#' in link['href']:
                continue
            if link['href'].startswith("/") or link['href'].startswith("//"):
                return urljoin(url, link['href'])
            if link['href'].startswith("http"):
                return link['href']
            else:
                continue
        else:
            continue
    print("Dead end.")
    return None

### Loop over scraped links
def scrape_iterative(base_url, iterations=3):
    next_link = scrape_single_link(base_url)
    for i in range(iterations):
        if next_link and next_link is not None:
            next_link = scrape_single_link(next_link)
        else:
            break

### Do the thing
if __name__ == "__main__":
    try:

        ### Start time measured since the epoch (floating point)
        STARTTIME = time.time()

        ### Argument Parsing (CLI variables)
        PARSER = argparse.ArgumentParser()
        PARSER.add_argument('--suite',
                            type=str.lower,
                            choices=[
                                'all',
                                'ads',
                                'bigfile',
                                'crawl',
                                'dns',
                                'ftp',
                                'http',
                                'https',
                                'icmp',
                                'ips',
                                'netflix',
                                'nmap',
                                'ntp',
                                'ssh',
                                'url-response',
                                'virus-sim-http',
                                'virus-sim-https',
                            ],
                            action="store",
                            required=False,
                            help='Test suite to run',
                            default='all'
                            )
        PARSER.add_argument('--size',
                            type=str.upper,
                            choices=[
                                'S',
                                'M',
                                'L',
                                'XL'
                            ],
                            action="store",
                            required=False,
                            help='Size of tests to run',
                            default='M'
                            )
        PARSER.add_argument('--loop',
                            action="store_true",
                            required=False,
                            help='Loop test continuously'
                            )
        PARSER.add_argument('--max-wait-secs',
                            action="store",
                            required=False,
                            help='Maximum possible time (in seconds) for random intervals between tests or loops',
                            default=40
                            )
        PARSER.add_argument('--nowait',
                            action="store_true",
                            required=False,
                            help='Don\'t wait random intervals between tests or loops'
                            )
        PARSER.add_argument('--os',
                            type=str.lower,
                            choices=['debian', 'alpine'],
                            action="store",
                            required=False,
                            help='Host OS running the script',
                            default='debian'
                            )
        PARSER.add_argument('--update_packages',
                            action="store_true",
                            required=False,
                            help='Install dependent packages'
                            )
        PARSER.add_argument('--crawl-start',
                            action="store",
                            required=False,
                            help='URL to start crawling from',
                            default='https://www.wikipedia.org'
                            )

        ARGS = PARSER.parse_args()

        if ARGS.update_packages:
            apt_acquisitions()

        if ARGS.suite == 'all':
            testsuite = [
                dig_random,
                ftp_random,
                http_download_targz,
                http_download_zip,
                http_random,
                https_random,
                https_crawl,
                ips,
                ads_random,
                nmap_1024,
                ntp_random,
                ping_random,
                speedtest_fast,
                ssh_random,
                traceroute_random,
                virus_sim_http,
                virus_sim_https,
                ]
            if ARGS.size == 'XL':
                testsuite.append(bigfile)
        elif ARGS.suite == 'bigfile':
            testsuite = [
                bigfile,
            ]
        elif ARGS.suite == 'crawl':
            testsuite = [
                webcrawl,
            ]
        elif ARGS.suite == 'dns':
            testsuite = [
                dig_random,
            ]
        elif ARGS.suite == 'ftp':
            testsuite = [
                ftp_random,
            ]
        elif ARGS.suite == 'http':
            testsuite = [
                http_download_targz,
                http_download_zip,
                http_random,
            ]
        elif ARGS.suite == 'https':
            testsuite = [
                https_random,
                https_crawl,
            ]
        elif ARGS.suite == 'icmp':
            testsuite = [
                ping_random,
                traceroute_random,
            ]
        elif ARGS.suite == 'ips':
            testsuite = [
                ips,
            ]
        elif ARGS.suite == 'ads':
            testsuite = [
                ads_random,
            ]            
        elif ARGS.suite == 'netflix':
            testsuite = [
                speedtest_fast,
            ]
        elif ARGS.suite == 'nmap':
            testsuite = [
                nmap_1024,
            ]
        elif ARGS.suite == 'ntp':
            testsuite = [
                ntp_random,
            ]
        elif ARGS.suite == 'ssh':
            testsuite = [
                ssh_random,
            ]
        elif ARGS.suite == 'url-response':
            testsuite = [
                urlresponse_random,
            ]
        elif ARGS.suite == 'virus-sim-http':
            testsuite = [
                virus_sim_http,
            ]
        elif ARGS.suite == 'virus-sim-https':
            testsuite = [
                virus_sim_https,
            ]

        ### Import targets from endpoints.py
        from endpoints import *

        ### Ship it
        run_test(testsuite)

        ### End time is time since epoch minus the start time since epoch (floating point)
        ENDTIME = time.time()-STARTTIME

        ### Print run time of script
        print (Fore.WHITE)
        print (Back.BLUE)
        print ("  [i] Total Run Time: %s" % (time.strftime("%H:%M:%S", time.gmtime(ENDTIME))))
        print (Style.RESET_ALL)

    ### Keyboard Ctrl-C Interupt
    except KeyboardInterrupt:
        sys.exit(0)