# 🧪 Traffgen - Network Traffic Generator

[![Docker Pulls](https://img.shields.io/docker/pulls/jdibby/traffgen)](https://hub.docker.com/r/jdibby/traffgen)
[![Image Size](https://img.shields.io/docker/image-size/jdibby/traffgen/latest)](https://hub.docker.com/r/jdibby/traffgen)
[![License](https://img.shields.io/github/license/jdibby/traffgen)](LICENSE)

> A modular traffic generator designed for network observability, anomaly detection validation, IPS/IDS testing, and firewall policy verification.

---

## 📚 Table of Contents

- [Traffic Generation Summary](#-traffic-generation-summary)
- [Test Categories](#-test-categories)
  - [Connectivity Tests](#-connectivity-tests)
  - [Web Protocol Tests](#-web-protocol-tests)
  - [Security & Filtering Tests](#-security--filtering-tests)
  - [File Transfer Tests](#-file-transfer-tests)
  - [AI & Ad Filtering](#-ai--ad-filtering)
  - [Streaming & Speed](#-streaming--speed)
- [Command-Line Flags](#-command-line-flags)
- [Full Test Suite](#-full-test-suite---suite-all)
- [Additional Features](#-additional-features)
- [Stager Script](#-stager-script-stagersh)
- [Docker Image](#-docker-image)
- [Usage Examples](#-usage-examples)

---

## 🧪 Traffic Generation Summary

Traffgen is a lightweight, test-driven framework for validating network connectivity, protocol-specific behavior, content inspection, throughput limits, and deep packet inspection (DPI) behavior. It's optimized for headless operation in testbeds, CI/CD pipelines, and edge devices.

---

## 📌 Test Categories

### 🔧 Connectivity Tests

| ✅ Test            | 🧩 Function         | 🔍 Description                                                |
|-------------------|---------------------|----------------------------------------------------------------|
| **DNS Lookup**    | `dig_random`        | Resolves pseudo-random domains against multiple public resolvers to validate DNS reachability and caching behavior |
| **ICMP Ping**     | `ping_random`       | Sends ICMP echo requests to test L3 reachability and latency  |
| **Traceroute**    | `traceroute_random` | Maps layer 3 hops to destination domains using TTL-expired UDP probes |
| **SSH Access**    | `ssh_random`        | Initiates TCP handshakes to SSH ports and attempts login using keyless/noauth methods |
| **NTP Sync**      | `ntp_random`        | Queries NTP servers via `chronyd` to assess time sync performance and port 123 UDP behavior |

---

### 🌐 Web Protocol Tests

| ✅ Test                  | 🧩 Function            | 🔍 Description                                                  |
|--------------------------|------------------------|------------------------------------------------------------------|
| **HTTP**                 | `http_random`         | Sends GET requests with randomized headers and User-Agent strings |
| **HTTPS**                | `https_random`        | Executes TLS handshakes and GETs to HTTPS endpoints; logs handshake timing |
| **ZIP File Download**    | `http_download_zip`   | Downloads binary ZIP files (10KB–5MB) to evaluate HTTP transfer performance |
| **TAR.GZ Download**      | `http_download_targz` | Downloads the latest WordPress release (tar.gz) to test large file pulls |
| **URL Response Times**   | `urlresponse_random`  | Performs GETs and logs DNS, connect, TLS, and TTFB timings individually |
| **HTTPS Crawling**       | `https_crawl`         | Recursively crawls hyperlinks on HTTPS domains to simulate bot or scraper behavior |
| **HTTP Crawling**        | `webcrawl`            | Performs depth-limited crawling over HTTP (plaintext) targets using random seed URLs |

---

### 🔒 Security & Filtering Tests

| ✅ Test                 | 🧩 Function         | 🔍 Description                                                  |
|------------------------|---------------------|------------------------------------------------------------------|
| **EICAR via HTTP**     | `virus_sim_http`    | Downloads the EICAR string over HTTP to trigger antivirus/DPI or web proxy scanning |
| **EICAR via HTTPS**    | `virus_sim_https`   | Same as above but using TLS; tests SSL interception and AV inspection |
| **IPS Triggering**     | `ips`               | Sends malformed or suspicious headers (e.g., SQLi strings, known malicious UAs) to test IPS rule matching |
| **DLP Tests**          | `dlp`               | Fetches fake documents containing PII/PCI patterns (PDF, XLS, CSV, ZIP) to test Data Loss Prevention |
| **Malware Agents**     | `malware-agents`    | Sends requests with User-Agent strings from known malware bots (e.g., Mirai variants, BlackEnergy) |
| **Malware Downloads**  | `malware-download`  | Pulls files commonly used to trigger endpoint sandboxing (e.g., executables hosted on GitHub) |
| **NMAP Port Scan**     | `nmap_1024os`       | Performs TCP SYN scan against well-known ports 1–1024 with OS detection enabled |
| **NMAP CVE Scan**      | `nmap_cve`          | Runs vulnerability and NSE-based scans using `nmap --script vuln` |

---

### 📦 File Transfer Tests

| ✅ Test               | 🧩 Function     | 🔍 Description                                        |
|----------------------|----------------|--------------------------------------------------------|
| **FTP Downloads**    | `ftp_random`   | Connects to FTP endpoints and downloads structured files (e.g., SQL dumps) |
| **Big File Downloads** | `bigfile`    | Downloads a 5GB binary blob to test max throughput and disk write I/O under load |

---

### 🤖 AI & Ad Filtering

| ✅ Test         | 🧩 Function        | 🔍 Description                                                     |
|----------------|-------------------|--------------------------------------------------------------------|
| **AI Endpoints** | `ai_https_random` | Sends requests to OpenAI, Anthropic, HuggingFace, etc., to test AI app accessibility |
| **Ad Blocking**  | `ads_random`      | Hits known ad server URLs (e.g., `doubleclick.net`) to test DNS/content blocking policies |

---

### 🎥 Streaming & Speed

| ✅ Test               | 🧩 Function       | 🔍 Description                                                  |
|----------------------|------------------|------------------------------------------------------------------|
| **Netflix Speedtest** | `speedtest_fast` | Runs Netflix’s `fast.com` CLI to test CDN speed and identify if video streaming is deprioritized |

---

## 🛠️ Command-Line Flags

| Flag                  | Description                                                                |
|-----------------------|----------------------------------------------------------------------------|
| `--suite`             | Select specific suite (`all`, `http`, `dns`, `nmap`, etc.)                 |
| `--size`              | Scale of the run: `S` (light), `M`, `L`, `XL` (exhaustive)                 |
| `--loop`              | Repeats the test suite indefinitely until interrupted                     |
| `--max-wait-secs`     | Max randomized delay (in seconds) between test executions                  |
| `--nowait`            | Disables randomized delay                                                  |
| `--crawl-start`       | Custom seed URL for `webcrawl` or `https_crawl`                            |

---

## 🧠 Full Test Suite (`--suite all`)

<details>
<summary>🧠 Click to expand full function list</summary>

```bash
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

## 🧰 Additional Features

- ✅ Random test execution order
- ⏱️ Optional randomized delay between tests
- 🔁 Infinite loop mode for stress or long-term testing
- 🌐 Endpoint list fetched via remote `endpoints.py` file
- 🧹 Output colorized using `colorama`
- 📊 Download progress via `tqdm`

---

## 🛠️ Stager Script (stager.sh)

To stage a linux system to turn it into a traffic generator, use this... beware, this will need to be run as root

- ✅ Autodetects Hardware/OS
- ✅ Supports Ubuntu and Rocky Linux
- ✅ Supports Raspberry Pi4 and Raspberry Pi5

| Docker Image Used         | Description                                                             |
|-----------------------|-----------------------------------------------------------------------------|
| jdibby/traffgen:latest | Raspberry Pi4 and other armv7 processors                                    |
| jdibby/traffgen:latest | Raspberry Pi5 64bit processors                                |
| jdibby/traffgen:latest | Other 64bit processors (default option)                                     |

```bash
sudo bash < <(curl -s https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh)
```
---

## 🐳 Docker Image

This test suite is also available as a prebuilt Docker container:

> **Docker Hub**: [jdibby/traffgen](https://hub.docker.com/r/jdibby/traffgen)

---

## 💡 Show the help file

To run the container to show the help file:

```bash
docker run -it jdibby/traffgen:<version> --help
```

## 💡 Full test suite with inject user simulated delay

To run the full test suite continuously with minimal delay:

```bash
docker run -it jdibby/traffgen:<version> --suite=all --size=L --loop --max-wait-secs=10
```



---
