
# 🧪 Network Traffic Script Summary

This traffic generator script runs a suite of tests across multiple network protocols and services, including DNS, HTTP, HTTPS, FTP, SSH, ICMP, NTP, and more. The tests help evaluate connectivity, performance, latency, security filtering, and reliability.

---

## 📌 Test Categories

### 🔧 Connectivity Tests

| ✅ Test            | 🧩 Function         | 🔍 Description                                        |
|-------------------|---------------------|------------------------------------------------------|
| **DNS Lookup**    | `dig_random`        | Resolve random domains using various DNS servers    |
| **ICMP Ping**     | `ping_random`       | Basic reachability test using `ping`                |
| **Traceroute**    | `traceroute_random` | Trace network path to destination hosts             |
| **SSH Access**    | `ssh_random`        | Attempt SSH connections to test reachability/auth    |
| **NTP Sync**      | `ntp_random`        | Time sync test using `chronyd` with public time servers  |

---

### 🌐 Web Protocol Tests

| ✅ Test                  | 🧩 Function                      | 🔍 Description                                              |
|--------------------------|----------------------------------|--------------------------------------------------------------|
| **HTTP**                 | `http_random`                   | Send HTTP requests with random user agents                    |
| **HTTPS**                | `https_random`                  | Perform HTTPS requests with random user agents                |
| **ZIP File Download**    | `http_download_zip`             | Download test ZIP files of various sizes                     |
| **TAR.GZ Download**      | `http_download_targz`           | Download the latest WordPress tarball                        |
| **URL Response Times**   | `urlresponse_random`            | Measures HTTP/HTTPS response times in seconds                   |
| **HTTPS Crawling**       | `https_crawl`                   | Follow links recursively on HTTPS sites                      |
| **Web Crawling**         | `webcrawl`                      | Crawl external sites from starting point                      |

---

### 🔒 Security & Filtering Tests

| ✅ Test                     | 🧩 Function                  | 🔍 Description                                              |
|----------------------------|------------------------------|-------------------------------------------------------------|
| **EICAR via HTTP**         | `virus_sim_http`            | Simulate virus downloads to test HTTP AV/Malware filtering           |
| **EICAR via HTTPS**        | `virus_sim_https`           | Simulate virus downloads to test HTTPS AV/Malware filtering          |
| **IPS Triggering**         | `ips`                       | Send malicious-looking User-Agent to trigger IPS            |
| **Malware Agents**         | `malware`                   | Send malicious-looking random User-Agents to trigger IPS           |
| **NMAP Port Scan**         | `nmap_1024os`               | Scan ports 1-1024 using NMAP                                 |
| **NMAP CVE Scan**          | `nmap_cve`                  | Full CVE/script scan with NMAP                              |

---

### 📦 File Transfer Tests

| ✅ Test            | 🧩 Function     | 🔍 Description                                         |
|-------------------|----------------|--------------------------------------------------------|
| **FTP Downloads**  | `ftp_random`   | Download sample DB files via FTP                      |
| **Big File Downloads** | `bigfile`      | Download a 5GB file to test throughput                |

---

### 🤖 AI & Ad Filtering

| ✅ Test           | 🧩 Function        | 🔍 Description                                  |
|------------------|-------------------|-------------------------------------------------|
| **AI Endpoints** | `ai_https_random` | HTTPS tests to common AI-related services       |
| **Ad Blocking**  | `ads_random`      | Tests if ad sites are blocked or filtered       |

---

### 🎥 Streaming & Speed

| ✅ Test              | 🧩 Function       | 🔍 Description                         |
|---------------------|------------------|----------------------------------------|
| **Netflix Throughput**   | `speedtest_fast` | Uses `fastcli` to test Netflix detection and throughput |

---

## 🛠️ Command-Line Flags

| Flag                  | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| `--suite`             | Choose test suite (`all`, `http`, `dns`, `nmap`, etc.)                      |
| `--size`              | Size/scale of tests: `S`, `M`, `L`, `XL`                                     |
| `--loop`              | Run the tests in an infinite loop                                           |
| `--max-wait-secs`     | Maximum wait time (in seconds) between looped test runs                    |
| `--nowait`            | Skip random wait between test runs                                          |
| `--crawl-start`       | Starting URL for the crawler (`webcrawl`/`https_crawl`)                     |

---

## 🧠 Full Test Suite (`--suite all`)

When run with `--suite all`, the following functions are executed:

```
dig_random
ftp_random
http_download_targz
http_download_zip
http_random
https_random
https_crawl
ai_https_random
ips
ads_random
ai_https_random
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

## 🐳 Docker Image

This test suite is also available as a prebuilt Docker container:

> **Docker Hub**: [jdibby/traffgen](https://hub.docker.com/r/jdibby/traffgen)

---

## 💡 Tip 1

To run the full test suite continuously with minimal delay:

```bash
docker run -it jdibby/traffgen:<version> --suite all --size S --loop --max-wait-secs 10 --nowait
```

## 💡 Tip 2

To stage a linux system to turn it into a traffic generator, use this... beware, this will need to be run as root

```bash
sudo bash < <(curl -s https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh)
```

---