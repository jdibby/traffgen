
# 🧪 Traffgen: Network Traffic Generator

Traffgen is a comprehensive network traffic generator designed to test connectivity, performance, security filtering, and reliability across a broad range of network protocols. It supports DNS, HTTP(S), FTP, SSH, ICMP, NTP, and more.

---

## 📁 Test Categories

[High-level descriptions omitted for brevity. Full technical details follow below.]

---

## 🔍 Technical Details for Each Test

### 🔧 Connectivity Tests

- **`dig_random`**: Uses the `dig` command to resolve randomly generated domain names against a set of public DNS servers (e.g., 1.1.1.1, 8.8.8.8). Evaluates DNS latency, resolution success rate, and potential DNS filtering.
- **`ping_random`**: Performs ICMP echo requests to randomly selected IPs or domains. Measures round-trip time and packet loss.
- **`traceroute_random`**: Runs `traceroute` or `tracepath` to determine the routing path to random hosts. Useful for identifying network hops and bottlenecks.
- **`ssh_random`**: Attempts to establish SSH connections on port 22 using `ssh -o BatchMode=yes`. Verifies open access and banner grabbing.
- **`ntp_random`**: Uses `chronyc` to sync time with public NTP servers. Monitors offset and delay to evaluate time synchronization accuracy.

### 🌐 Web Protocol Tests

- **`http_random` / `https_random`**: Sends HTTP/HTTPS GET requests using `curl` with randomized User-Agent headers. Tests web access, SSL/TLS negotiation, and HTTP status codes.
- **`http_download_zip` / `http_download_targz`**: Downloads test archives (ZIP/TAR.GZ) to benchmark download speed and inspect content filtering.
- **`urlresponse_random`**: Measures total response time including DNS lookup, connection, TLS handshake, and content transfer.
- **`https_crawl` / `webcrawl`**: Recursively fetches web pages starting from a seed URL using a depth-limited crawler. Detects link accessibility, redirects, and broken links.

### 🔒 Security & Filtering Tests

- **`virus_sim_http` / `virus_sim_https`**: Downloads the standard EICAR test file over HTTP/HTTPS to check antivirus and malware proxy/filter reaction.
- **`ips`**: Sends HTTP requests with known malicious User-Agent headers (e.g., `sqlmap`, `Nikto`) to attempt triggering Intrusion Prevention Systems.
- **`dlp`**: Downloads files mimicking sensitive content (e.g., PII, PCI data in PDF, CSV, XLSX) to assess Data Loss Prevention tools.
- **`malware-agents`**: Rotates through a set of suspicious or blacklisted User-Agents to evaluate heuristic/blocklist-based detection.
- **`malware-download`**: Fetches non-executable malware samples hosted on GitHub to trigger sandbox or endpoint detection logging.
- **`nmap_1024os`**: Performs a TCP SYN scan on ports 1–1024 and includes OS fingerprinting using `-sS -O` flags.
- **`nmap_cve`**: Executes Nmap scripts targeting known CVEs using the `--script=vuln` option.

### 📦 File Transfer Tests

- **`ftp_random`**: Connects to FTP servers and downloads various file types using `wget` or `curl --ftp-ssl`. Detects file availability and bandwidth caps.
- **`bigfile`**: Downloads a large (5GB) test file using HTTP to benchmark sustained throughput and test WAN optimization appliances.

### 🤖 AI & Ad Filtering

- **`ai_https_random`**: Targets common AI SaaS endpoints (e.g., OpenAI, Anthropic, HuggingFace) over HTTPS. Tests access and TLS inspection behavior.
- **`ads_random`**: Sends HTTP requests to domains known for ad tracking (e.g., `doubleclick.net`, `googlesyndication.com`) to validate ad filtering or DNS blackholing.

### 🎥 Streaming & Speed

- **`speedtest_fast`**: Invokes Netflix's `fastcli` to measure downstream speed from Netflix servers. Useful for testing streaming service prioritization or throttling.

---
