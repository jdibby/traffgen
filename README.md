
# 🧪 Traffgen: Network Traffic Generator

Traffgen is a comprehensive network traffic generator designed to test connectivity, performance, security filtering, and reliability across a broad range of network protocols. It supports DNS, HTTP(S), FTP, SSH, ICMP, NTP, and more.

---

## 📁 Test Categories

### 🔧 Connectivity Tests

| ✅ Test        | 🧩 Function         | 🔍 Description                                                    |
|---------------|---------------------|-------------------------------------------------------------------|
| DNS Lookup     | `dig_random`        | Resolves random domains using multiple DNS servers                |
| ICMP Ping      | `ping_random`       | Verifies basic reachability using ICMP ping                       |
| Traceroute     | `traceroute_random` | Traces network paths to target destinations                       |
| SSH Access     | `ssh_random`        | Attempts SSH connections to assess availability and authentication |
| NTP Sync       | `ntp_random`        | Tests time synchronization with public NTP servers via `chronyd`  |

---

### 🌐 Web Protocol Tests

| ✅ Test               | 🧩 Function            | 🔍 Description                                         |
|----------------------|------------------------|--------------------------------------------------------|
| HTTP Requests         | `http_random`          | Sends HTTP requests with randomized User-Agent headers |
| HTTPS Requests        | `https_random`         | Sends HTTPS requests using randomized User-Agent headers |
| ZIP File Download     | `http_download_zip`    | Downloads sample ZIP files of various sizes            |
| TAR.GZ Download       | `http_download_targz`  | Downloads the latest WordPress `.tar.gz` archive       |
| URL Response Timing   | `urlresponse_random`   | Measures HTTP/HTTPS response times                     |
| HTTPS Crawler         | `https_crawl`          | Recursively follows links on HTTPS web pages           |
| HTTP Crawler          | `webcrawl`             | Crawls external HTTP websites from a defined starting point |

---

### 🔒 Security & Filtering Tests

| ✅ Test               | 🧩 Function         | 🔍 Description                                                               |
|----------------------|---------------------|------------------------------------------------------------------------------|
| EICAR Test (HTTP)     | `virus_sim_http`    | Simulates antivirus/malware detection using EICAR over HTTP                  |
| EICAR Test (HTTPS)    | `virus_sim_https`   | Simulates antivirus/malware detection using EICAR over HTTPS                 |
| IPS Detection         | `ips`               | Sends known malicious User-Agents to trigger Intrusion Prevention Systems    |
| DLP Simulation        | `dlp`               | Downloads sample PII/PCI data to evaluate Data Loss Prevention mechanisms    |
| Malware User-Agents   | `malware-agents`    | Sends suspicious User-Agents to provoke security filtering responses         |
| Malware Downloads     | `malware-download`  | Attempts to download malware-related files for sandbox inspection            |
| NMAP Port Scan        | `nmap_1024os`       | Performs port scan on ports 1–1024 using Nmap                                |
| NMAP CVE Scan         | `nmap_cve`          | Conducts vulnerability scanning using Nmap scripts (CVE-based)               |

---

### 📦 File Transfer Tests

| ✅ Test             | 🧩 Function     | 🔍 Description                                         |
|--------------------|----------------|--------------------------------------------------------|
| FTP Downloads       | `ftp_random`   | Retrieves sample files via FTP                         |
| Large File Download | `bigfile`      | Downloads a 5GB file to assess bandwidth and throughput |

---

### 🤖 AI & Ad Filtering

| ✅ Test         | 🧩 Function        | 🔍 Description                                      |
|----------------|-------------------|-----------------------------------------------------|
| AI Endpoints    | `ai_https_random` | Sends HTTPS traffic to common AI service endpoints  |
| Ad Blocking     | `ads_random`      | Verifies access to known ad networks and trackers   |

---

### 🎥 Streaming & Speed Tests

| ✅ Test            | 🧩 Function       | 🔍 Description                                                       |
|-------------------|------------------|----------------------------------------------------------------------|
| Netflix Speedtest | `speedtest_fast` | Uses `fastcli` to emulate Netflix throughput testing and detection   |

---

## ⚙️ Command-Line Flags

| Flag              | Description                                                               |
|-------------------|---------------------------------------------------------------------------|
| `--suite`         | Selects test suite: `all`, `http`, `dns`, `nmap`, etc.                    |
| `--size`          | Defines test scale: `S`, `M`, `L`, `XL`                                   |
| `--loop`          | Enables continuous execution in an infinite loop                         |
| `--max-wait-secs` | Sets max randomized wait time (in seconds) between loop iterations        |
| `--nowait`        | Disables random delays between tests                                      |
| `--crawl-start`   | Specifies the starting URL for HTTP/HTTPS crawlers                        |

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
| `jdibby/traffgen`      | For ARMv7 (e.g., Raspberry Pi 4)           |
| `jdibby/traffgen`      | For ARM64 (e.g., Raspberry Pi 5)           |
| `jdibby/traffgen`      | For x86_64 and other 64-bit platforms      |

---

## 🐳 Docker Image

A pre-built containerized version is available on Docker Hub:

🔗 [Docker Hub: jdibby/traffgen](https://hub.docker.com/r/jdibby/traffgen)

### View Help Menu

```bash
docker run -it jdibby/traffgen:<version> --help
```

### Run Full Suite in Loop Mode with Minimal Delay

```bash
docker run -it jdibby/traffgen:<version> --suite=all --size=L --loop --max-wait-secs=10
```

---

## 📫 Feedback & Contributions

We welcome contributions and suggestions. Please open issues or submit PRs on the [GitHub repo](https://github.com/jdibby/traffgen).
