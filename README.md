
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
| **DNS Lookup** | `dig_random` | `dns` |Performs **DNS A record resolution** for a set of pseudo-random selected domains using multiple pre-configured **DNS recursive resolvers**. This assesses **DNS service availability** and **name resolution latency**. |
| **ICMP Ping** | `ping_random` | `icmp`  |Executes **ICMP Echo Request/Reply transactions** to a range of pre-defined IP addresses. This verifies fundamental **network layer reachability** and measures **round-trip time (RTT)** and **packet loss**. |
| **SNMP Polling** | `snmp_random` | `snmp` | Executes SNMP GET requests (snmpwalk) against a list of predefined IP addresses using randomized SNMP community strings. This test verifies SNMP agent availability. |
| **Traceroute** | `traceroute_random` | `icmp` | Initiates **network path discovery** using **ICMP or UDP-based traceroute** to diverse targets. This maps the **network hops** and identifies potential **routing anomalies** or **latency bottlenecks**. |
| **SSH Access** | `ssh_random` | `ssh` | Attempts **Secure Shell (SSH) protocol connections** to various remote endpoints. This validates **SSH service availability**, **TCP port 22 accessibility**, and basic **authentication mechanism functionality**. |
| **NTP Sync** | `ntp_random` | `ntp` | Verifies **Network Time Protocol (NTP) synchronization** status and offset against public NTP stratum 1 servers via the `netcat`. This ensures **accurate system clock synchronization**. |

---

### 🌐 Web Protocol Tests

| ✅ Test | 🧩 Function | 🧩 Suite Flag |🔍 Description |
|---|---|---|---|
| **HTTP Requests** | `http_random` | `http` | Queries with **HTTP/1.1 GET requests** to a variety of web servers, dynamically generating diverse `User-Agent` headers to simulate various client types. This assesses **unencrypted web service availability** and **HTTP response codes**. |
| **ZIP File Download** | `http_download_zip` | `http` | Initiates **HTTP downloads of `.zip` archives** across multiple predefined file sizes (e.g., 1MB, 10MB, 100MB). This evaluates **data throughput**, **file integrity**, and **HTTP range request support**. |
| **TAR.GZ Download** | `http_download_targz` | `http` | Downloads the latest stable release of the **WordPress core `.tar.gz` archive** via HTTP. This specifically tests retrieval of a common, large, compressed software distribution. |
| **HTTPS Requests** | `https_random` | `https` | Transmits **HTTPS/TLS GET requests** to secure web servers, utilizing randomized `User-Agent` strings. This validates **TLS handshake completion**, **certificate chain validation**, and **secure web content retrieval**. |
| **URL Response Timing** | `urlresponse_random` | `url-response` | Measures the **end-to-end response time** for both HTTP and HTTPS requests to a diverse set of URLs. This provides metrics on **web server latency** and **network performance** for web traffic. |
| **HTTPS Crawler** | `https_crawl` | `ping_random` | Recursively traverses hyperlinks within **HTTPS-secured web pages** from a specified starting URL. This simulates legitimate web browsing and tests the ability to navigate secure sites. |
| **HTTP Crawler** | `webcrawl` | `crawl` | Recursively traverses hyperlinks within **HTTP-unsecured web pages** from a specified starting URL. This simulates legitimate web browsing. |

---

### 🔒 Security & Filtering Tests

| ✅ Test | 🧩 Function | 🧩 Suite Flag |🔍 Description |
|---|---|---|---|
| **EICAR Test (HTTP)** | `virus_sim_http` | `virus-sim-http` | Attempts to download the **EICAR (European Institute for Computer Antivirus Research) test file** over HTTP. This is designed to trigger **antivirus and malware detection mechanisms** without causing actual harm. |
| **EICAR Test (HTTPS)** | `virus_sim_https` | `virus-sim-https` | Attempts to download the **EICAR test file** over HTTPS. This validates whether **TLS decryption security solutions** can detect the EICAR signature within encrypted traffic. |
| **IPS Detection** | `ips` | `ips` | Sends HTTP requests containing **known malicious `User-Agent` strings** or **HTTP request patterns** designed to trigger an IPS**. This verifies signature-based IPS rules. |
| **DLP Simulation** | `dlp_sim_https` | `dlp` | Initiates downloads of files containing **simulated Personally Identifiable Information (PII)** and **Payment Card Industry (PCI) data patterns**. This evaluates the detection capabilities of **Data Loss Prevention (DLP) systems**. |
| **Malware User-Agents** | `malware_random` | `malware-agents` | Transmits HTTP requests with **`User-Agent` headers associated with known malware, botnets, or malicious scanners**. This aims to provoke responses from **web application firewalls (WAFs)** or **threat intelligence feeds**. |
| **Malware Downloads** | `malware_download` | `malware-download` | Attempts to download **non-executable, benign files specifically flagged as malware-related** by public threat intelligence feeds. This is intended for **sandbox environments** to observe security control reactions. |
| **NMAP Port Scan** | `nmap_1024os` | `nmap` | Executes a **TCP SYN port scan (stealth scan)** using Nmap against target hosts, focusing on the first 1024 well-known ports. This identifies **open ports** and potential **service enumeration**.
| **NMAP Port Scan** | `nmap_cve` | `nmap` | Executes a **vulnerability scan** using Nmap's scripting engine (`NSE`) modules specifically targeting **Common Vulnerabilities and Exposures (CVEs)**. This identifies systems with known security weaknesses. |
| **Pornography Crawl** | `pornography_crawl` | `pornography` | Initiates a web crawl targeting publicly available web pages categorized as **pornographic**. This evaluates the effectiveness of **URL filtering mechanisms**. |
| **Domain Filtering Checks** | `github_domain_check` | `domain-check` | This check executes **domain resolution and reachability test** against a verified list of filtered domains. This list is maintained as a **publicly accessible data stream** via GitHub. The process is designed to test security controls preventing access to known undesirable domains, encompassing categories such as **adware distribution, malicious software propagation, host-based viral infections, deceptive content delivery, and various forms of online fraud and social engineering schemes**. |

---

### 📦 File Transfer Tests

| ✅ Test | 🧩 Function | 🧩 Suite Flag |🔍 Description |
|---|---|---|---|
| **FTP Downloads** | `ftp_random` | `ftp` | Retrieves a series of **sample files** from an FTP server using the **File Transfer Protocol (FTP)**. This assesses **FTP service availability**, **data integrity**, and **firewall egress rules** for port 21/20. |
| **Large File Download** | `bigfile` | `bigfile` | Downloads a **5 Gigabyte (GB) test file** from a designated HTTP endpoint. This is specifically designed to assess **sustained network bandwidth**, **throughput limitations**, and **network stability** over prolonged transfers. |

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
| `--suite` | Specifies the **test suite(s)** to execute. Accepted arguments include predefined categories such as `all` (all available tests), `http`, `dns`, `nmap`, or custom groupings. This allows for focused testing. |
| `--size` | Defines the **scale or intensity of the test execution**. Options include `S` (Small), `M` (Medium), `L` (Large), and `XL` (Extra Large), which typically correlate to the number of iterations, concurrency, or data volume. |
| `--loop` | Activates **continuous test execution**, causing the selected test suite to run indefinitely in an infinite loop until manually terminated. Ideal for long-duration network monitoring. |
| `--max-wait-secs` | Sets the **maximum randomized delay** (in seconds) that will be introduced between successive iterations when the `--loop` flag is active. This helps simulate more realistic traffic patterns and prevent overwhelming target systems. |
| `--nowait` | Disables all **randomized delays** between individual test executions. This provides the fastest possible execution of tests, suitable for rapid diagnostics or performance benchmarking. |
| `--crawl-start` | Designates the **initial URL** from which the HTTP (`webcrawl`) or HTTPS (`https_crawl`) web crawlers will commence their recursive link traversal. Must be a valid and accessible URL. |

---

## 🧪 Full Test Suite (`--suite=all`)

The following functions are executed when running the complete suite:

```
dig_random
ftp_random
http_download_targz
http_download_zip
http_random
https_random
https_crawl
malware_random
malware_download
pornography_crawl
ips
dlp_sim_https
ads_random
ai_https_random
github_domain_check
nmap_1024os
nmap_cve
ntp_random
ping_random
speedtest_fast
snmp_random
ssh_random
traceroute_random
virus_sim_http
virus_sim_https
```

---

## 🧰 Features

- 🔀 Randomized test execution order
- ⏱️ Optional randomized delays between test runs
- 🔁 Infinite loop mode for long-term testing or stress testing
- 🌍 Dynamic endpoint retrieval via `endpoints.py`
- 🎨 Colorized terminal output using `colorama`
- 📈 Download progress indicators via `tqdm`

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
docker run -it jdibby/traffgen:<version> --help
```

### Run Full Suite in Loop Mode with Minimal Delay

```bash
docker run -it jdibby/traffgen:<version> --suite=all --size=S --loop --max-wait-secs=20
```

---

## 📫 Feedback & Contributions

I welcome contributions and suggestions. Please open issues or submit PRs on the [GitHub repo](https://github.com/jdibby/traffgen).
