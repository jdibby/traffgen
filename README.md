
# 🧪 Network Test Script Summary

This diagnostic script runs a suite of tests across multiple network protocols and services, including DNS, HTTP(S), FTP, SSH, ICMP, NTP, and more. The tests help evaluate connectivity, performance, latency, security filtering, and reliability.

---

## 📌 Test Categories

### 🔧 Connectivity Tests

| ✅ Test            | 🧩 Function         | 🔍 Description                                        |
|-------------------|---------------------|------------------------------------------------------|
| **DNS Lookup**    | `dig_random`        | Resolve random domains using various DNS servers    |
| **ICMP Ping**     | `ping_random`       | Basic reachability test using `ping`                |
| **Traceroute**    | `traceroute_random` | Trace network path to destination hosts             |
| **SSH Access**    | `ssh_random`        | Attempt SSH connection to test reachability/auth    |
| **NTP Sync**      | `ntp_random`        | Time sync test using `chronyd` with public servers  |

---

### 🌐 Web Protocol Tests

| ✅ Test                  | 🧩 Function                      | 🔍 Description                                              |
|--------------------------|----------------------------------|--------------------------------------------------------------|
| **HTTP HEAD**            | `http_random`                   | Send HTTP HEAD requests with random user agents              |
| **HTTPS HEAD**           | `https_random`                  | Perform HTTPS HEAD requests                                  |
| **ZIP File Download**    | `http_download_zip`             | Download test ZIP files of various sizes                     |
| **TAR.GZ Download**      | `http_download_targz`           | Download the latest WordPress tarball                        |
| **Response Time**        | `urlresponse_random`            | Measure response time in seconds                             |
| **HTTPS Crawl**          | `https_crawl`                   | Follow links recursively on HTTPS sites                      |
| **Web Crawl**            | `webcrawl`                      | Crawl external site from starting point                      |

---

### 🔒 Security & Filtering Tests

| ✅ Test                     | 🧩 Function                  | 🔍 Description                                              |
|----------------------------|------------------------------|-------------------------------------------------------------|
| **EICAR via HTTP**         | `virus_sim_http`            | Simulate virus download to test HTTP AV filtering           |
| **EICAR via HTTPS**        | `virus_sim_https`           | Simulate virus download to test HTTPS AV filtering          |
| **IPS Trigger**            | `ips`                       | Send malicious-looking User-Agent to trigger IPS            |
| **Nmap Port Scan**         | `nmap_1024os`               | Scan ports 1-1024 using Nmap                                 |
| **Nmap CVE Scan**          | `nmap_cve`                  | Full CVE/script scan with Nmap                              |

---

### 📦 File Transfer Tests

| ✅ Test            | 🧩 Function     | 🔍 Description                                         |
|-------------------|----------------|--------------------------------------------------------|
| **FTP Download**  | `ftp_random`   | Download sample DB files via FTP                      |
| **Big File Test** | `bigfile`      | Download a 5GB file to test throughput                |

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
| **Netflix Speed**   | `speedtest_fast` | Uses `fastcli` to test fast.com speeds |

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

## 💡 Tip

To run the full test suite continuously with minimal delay:

```bash
python3 testscript.py --suite all --size XL --loop --max-wait-secs 10 --nowait
```

---
