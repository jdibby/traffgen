
# 🧪 Traffgen: Network Traffic Generator

Traffgen is a comprehensive network traffic generator designed to test connectivity, performance, security filtering, URL filtering, and reliability across a broad range of network protocols. It supports DNS, HTTP(S), FTP, SSH, ICMP, NTP, and more.

---

## 📁 Test Categories

# Network and Security Test Suite

This document outlines the various network connectivity, web protocol, security, and file transfer tests available in this suite, along with their technical descriptions and command-line configuration flags.

---

### 🔧 Connectivity Tests

| ✅ Test | 🧩 Function | 🧩 Suite Flag |🔍 Description |
|---|---|---|---|
| **DNS Lookup** | `dig_random` | `dns` | Performs **DNS A record resolution** for a set of randomly selected domains using multiple pre-configured **DNS recursive resolvers**. This assesses **DNS service availability** and **name resolution latency**. |
| **ICMP Ping** | `ping_random` | `icmp`  | Executes **ICMP Echo Request/Reply transactions** to a range of pre-defined IP addresses. This verifies fundamental **network layer reachability** and measures **round-trip time (RTT)** and **packet loss**. |
| **SNMP Polling** | `snmp_random` | `snmp` | Executes SNMP GET requests (snmpwalk) against a list of predefined IP addresses using randomized SNMP community strings. This test verifies SNMP agent availability. |
| **Traceroute** | `traceroute_random` | `icmp` | Initiates **network path discovery** using **ICMP or UDP-based traceroute** to remote targets. This maps the **network hops** and identifies potential **routing anomalies** or **latency bottlenecks**. |
| **SSH Access** | `ssh_random` | `ssh` | Attempts **Secure Shell (SSH) protocol connections** to various remote endpoints. This validates **SSH service availability** and **TCP port 22 accessibility**. |
| **NTP Sync** | `ntp_random` | `ntp` | Verifies **Network Time Protocol (NTP) synchronization** status and offset against public NTP stratum 1 servers via the `netcat` tool. |
| **BGP Peering** | `bgp_peering` | `bgp` | Establishes BGP peering using the [GoBGP](https://github.com/osrg/gobgp) project with ASN **65555**. Attempts connections with a predefined list of neighbors to validate BGP sessions. |

---

### 🌐 Web Protocol Tests

| ✅ Test | 🧩 Function | 🧩 Suite Flag |🔍 Description |
|---|---|---|---|
| **HTTP Requests** | `http_random` | `http` | Queries with **HTTP/1.1 GET requests** to a variety of web servers, using diverse `User-Agent` headers to simulate various client types. This assesses **unencrypted web service availability** and **HTTP response codes**. |
| **ZIP File Download** | `http_download_zip` | `http` | Initiates **HTTP downloads of `.zip` archives** across multiple predefined file sizes (e.g., 1MB, 10MB, 100MB). This evaluates **data throughput**, **file integrity**, and **HTTP range request support**. |
| **TAR.GZ Download** | `http_download_targz` | `http` | Downloads the latest stable release of the **WordPress core `.tar.gz` archive** via HTTP. This specifically tests retrieval of a common compressed software distribution. |
| **HTTPS Requests** | `https_random` | `https` | Transmits **HTTPS/TLS GET requests** to secure web servers, utilizing randomized `User-Agent` strings. This validates **TLS handshake completion**, **certificate chain validation**, and **secure web content retrieval**. |
| **URL Response Timing** | `urlresponse_random` | `url-response` | Measures the **end-to-end response time** for both HTTP and HTTPS requests to a diverse set of URLs. This provides metrics on **web server latency** and **network performance** for web traffic. |
| **HTTPS Crawler** | `https_crawl` | `https` | Recursively traverses hyperlinks within **HTTPS-secured web pages** from a specified starting URL. This simulates legitimate web browsing and tests the ability to navigate secure sites. |
| **HTTP Crawler** | `webcrawl` | `crawl` | Recursively traverses hyperlinks within **HTTP-unsecured web pages** from a specified starting URL. This simulates legitimate web browsing. |

---

### 🔒 Security & Filtering Tests

| ✅ Test | 🧩 Function | 🧩 Suite Flag |🔍 Description |
|---|---|---|---|
| **EICAR Test (HTTP and HTTPS)** | `virus_sim` | `virus` | Attempts to download the **EICAR (European Institute for Computer Antivirus Research) test file** over HTTP(s). This is designed to trigger **antivirus and malware detection mechanisms** without causing actual harm. |
| **IPS Detection** | `ips` | `ips` | Sends HTTP requests containing **known malicious `User-Agent` strings** or **HTTP request patterns** designed to trigger an IPS**. This verifies signature-based IPS rules. |
| **DLP Simulation** | `dlp_sim_https` | `dlp` | Initiates downloads of files containing **simulated Personally Identifiable Information (PII)** and **Payment Card Industry (PCI) data patterns**. This evaluates the detection capabilities of **Data Loss Prevention (DLP) systems**. |
| **Malware User-Agents** | `malware_random` | `malware-agents` | Transmits HTTP requests with **`User-Agent` headers associated with known malware, botnets, or malicious scanners**. This aims to provoke responses from **web application firewalls (WAFs)** or **threat intelligence feeds**. |
| **Malware Downloads** | `malware_download` | `malware-download` | Attempts to download **non-executable, benign files specifically flagged as malware-related** by public threat intelligence feeds. This is intended for **sandbox environments** to observe security control reactions. |
| **NMAP Port Scan** | `nmap_1024os` | `nmap` | Executes a **TCP SYN port scan (stealth scan)** using Nmap against target hosts, focusing on the first 1024 well-known ports. This identifies **open ports** and potential **service enumeration**.
| **NMAP Port Scan** | `nmap_cve` | `nmap` | Executes a **vulnerability scan** using Nmap's scripting engine (`NSE`) modules specifically targeting **Common Vulnerabilities and Exposures (CVEs)**. This identifies systems with known security weaknesses. |
| **Pornography Crawl** | `pornography_crawl` | `pornography` | Initiates a web crawl targeting publicly available web pages categorized as **pornographic**. This evaluates the effectiveness of **URL filtering mechanisms**. |
| **Domain Filtering Checks** | `github_domain_check` | `domain-check` | This check executes **domain resolution and reachability test** against a verified list of unsecure and unsafe domains. This list is maintained as a **publicly accessible data stream** via GitHub. The process is designed to test security controls preventing access to known undesirable domains, encompassing categories such as **adware distribution, malicious software propagation, host-based viral infections, deceptive content delivery, and various forms of online fraud and social engineering schemes**. |
| **Phishing Domain Filtering Checks** | `github_phishing_domain_check` | `phishing-domains` | This check executes **phishing domain resolution and reachability test** against a verified list of known phishing domains. This list is maintained as a **publicly accessible data stream** via GitHub. The process is designed to test security controls preventing access to these known undesirable domains. |
| **Squatting Domain Filtering Checks** | `squatting_domains` | `squatting` | This check uses [`dnstwist`](https://github.com/elceef/dnstwist) to **generate and verify the real registration status of squatting domains**, employing various techniques such as **typosquatting**, **bitsquatting**, and **homograph attacks**. These variations are derived from a static list of real domains in endpoints.py. The goal is to test security controls that prevent access to these undesirable lookalike domains. |
| **Nikto Scans** | `web_scanner` | `web-scanner` | Launches a Nikto web vulnerability scan against `testmyids.com`, emulating attacker reconnaissance behavior. Scan intensity is configurable via the `--size` argument (`S`, `M`, `L`, `XL`), which adjusts the `-maxtime` value (60–240 seconds). All scans use a forced 1-second request timeout to simulate aggressive probing. Commonly used to validate web-based IDS detection of high-noise application-layer scans. |
| **Metasploit Checks** | `metasploit_check` | `metasploit-check` | Runs randomized **Metasploit `.rc` scripts** in `check` mode against targets listed in `targets.list`. Each script includes 2–5 modules from categories like **web**, **SSH**, **SMB**, and **fuzzing**. All modules use `check` only (no exploitation), include `THREADS 1`, and inject a `sleep 2` delay between checks to simulate slow scans. This activity is designed to **trigger IDS/IPS alerts** for lab validation and blue team exercises without causing system compromise. |
| **Kyber Tests** | `kyber_random` | `kyber` | Transmits **HTTPS/TLS GET requests** to secure web servers, utilizing randomized `User-Agent` strings. This validates **TLS handshake completion**, **certificate chain validation**, and **secure web content retrieval**. What is unique is this test simulates Kyber encrypted client hellos (ECH). |

---

### 📦 File Transfer Tests

| ✅ Test | 🧩 Function | 🧩 Suite Flag |🔍 Description |
|---|---|---|---|
| **FTP Downloads** | `ftp_random` | `ftp` | Retrieves a series of **sample files** from an FTP server using the **File Transfer Protocol (FTP)**. This assesses **FTP service availability**, **data integrity**, and **firewall egress rules** for port 21/20. |
| **Large File Download** | `bigfile` | `bigfile` | Downloads a **5 Gigabyte (GB) test file** from a designated HTTP endpoint. This is specifically designed to assess **network bandwidth**, **throughput limitations**, and **network stability** over prolonged transfers. |

---

### 🤖 AI & Ad Filtering

| ✅ Test | 🧩 Function | 🧩 Suite Flag |🔍 Description |
|---|---|---|---|
| **AI Endpoints** | `ai_https_random` | `ai` | Sends **HTTPS traffic** to common **Artificial Intelligence (AI) and Machine Learning (ML) services**. This verifies reachability and potential filtering of AI-related network communications. |
| **Ad Blocking** | `ads_random` | `ads` | Attempts to access URLs associated with **known advertising networks and tracking domains**. This test determines efficiency of **ad-blocking software or network-level content filtering**. |

---

### 🎥 Streaming & Speed Tests

| ✅ Test | 🧩 Function | 🧩 Suite Flag |🔍 Description |
|---|---|---|---|
| **Netflix Speedtest** | `speedtest_fast` | `netflix` | Utilizes the `fastcli` command-line utility to emulate **Netflix traffic**. This assesses perceived **internet throughput and latency** as experienced by streaming services, and verifies if the traffic is identified as legitimate streaming by network appliances. |

---

## ⚙️ Command-Line Flags

| Flag | Description |
|---|---|
| `--suite` | Specifies the **test suite(s)** to execute. Accepted arguments include predefined categories such as `all` (all available tests), `http`, `dns`, `nmap`. This allows for more focused testing. |
| `--size` | Defines the **scale or intensity of the test execution**. Options include `S` (Small), `M` (Medium), `L` (Large), and `XL` (Extra Large), which typically correlate to the number of iterations, concurrency, or data volume. |
| `--loop` | Activates **continuous test execution**, causing the selected test suite to run in an infinite loop until manually terminated. Ideal for long-duration network monitoring. |
| `--max-wait-secs` | Sets the **maximum randomized delay** (in seconds) that will be introduced between successive iterations when the `--loop` flag is active. This helps simulate more realistic traffic patterns and prevent overwhelming remote systems. |
| `--nowait` | Disables all **randomized delays** between individual test executions. This provides the fastest possible execution of tests, suitable for faster reporting on remote systems and stress testing of networks. |
| `--crawl-start` | Designates the **initial URL** from which the HTTP (`webcrawl`) or HTTPS (`https_crawl`) web crawlers will start their recursive link traversal. |

---

## 🧪 Full Test Suite (`--suite=all`)

The following functions are executed when running the complete suite:

```
                webcrawl
                dig_random
                bgp_peering
                ftp_random
                http_download_targz
                http_download_zip
                http_random
                https_random
                https_crawl
                pornography_crawl
                metasploit_check
                malware_random
                ai_https_random
                ping_random
                traceroute_random
                snmp_random
                kyber_random
                ips
                ads_random
                github_domain_check
                github_phishing_domain_check
                squatting_domains
                speedtest_fast
                web_scanner
                nmap_1024os
                nmap_cve        
                ntp_random
                ssh_random
                urlresponse_random
                virus_sim
                dlp_sim_https
                malware_download
```

---

## 🧰 Features

- 🔀 Randomized test execution order
- ⏱️ Optional randomized delays between test runs
- 🔁 Infinite loop mode for long-term testing or stress testing
- 🌍 Endpoints determined via `endpoints.py`
- 🎨 Colorized terminal output using `colorama`
- 📈 Download progress indicators via `tqdm`
- 🖥️ Watchdog and healthchecks for self-healing and self-restarting

---

## 🚀 Quick Deployment with `stager.sh`

To prepare a system as a test node, run the staging script as root:

```bash
sudo bash < <(curl -s https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh)
```

- 🖥️ Auto-detects hardware and operating system
- ✅ Supports Ubuntu, Rocky Linux, Raspberry Pi 4 & 5

| Image Tag              | Description                                |
|------------------------|--------------------------------------------|
| `jdibby/traffgen:latest`      | For ARMv7 (e.g., Raspberry Pi 4)           |
| `jdibby/traffgen:latest`      | For ARM64 (e.g., Raspberry Pi 5)           |
| `jdibby/traffgen:latest`      | For x86_64 and other 64-bit platforms      |

---

## 🐳 Docker Image

A pre-built containerized version is available on Docker Hub:

🔗 [Docker Hub: jdibby/traffgen:latest](https://hub.docker.com/r/jdibby/traffgen)

### View Help Menu

```bash
docker run --pull=always -it jdibby/traffgen:latest --help
```

### Run Full Suite in Loop Mode with 20s Delay in the **Backgroud**

```bash
docker run --pull=always --detach --restart unless-stopped jdibby/traffgen:latest --suite=all --size=S --max-wait-secs=20 --loop 
```
---

### Run Full Suite in Loop Mode with 20s Delay in the **Foreground**

```bash
docker run --pull=always --restart unless-stopped -it jdibby/traffgen:latest --suite=all --size=S --max-wait-secs=20 --loop 
```

---

## 📫 Feedback & Contributions

I welcome contributions and suggestions. Please open issues or submit PRs on the [GitHub repo](https://github.com/jdibby/traffgen).
