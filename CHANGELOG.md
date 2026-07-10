# Changelog

All notable changes to Traffgen are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [3.11.0] — 2026-07-10

### Added
- **`--impersonate` flag — browser-accurate TLS/HTTP2 fingerprinting**: adds [curl-impersonate](https://github.com/lwthiker/curl-impersonate) (8 profiles: `chrome116`, `chrome116-linux`, `chrome99-android`, `ff117`, `ff117-linux`, `edge101`, `edge101-linux`, `safari15-5`) to the Docker image and wires it into every HTTP(S)-probing suite (`_curl_head`/`_run_head_batch`, `_curl_download`, and `_probe_domain_list` — effectively all of them). Confirmed live against a production Cato Networks deployment: system curl/Python `requests` are always classified `Client Class: restclient cpp`/`unclassified tls` by JA3-aware SASE/NGFW traffic classifiers regardless of declared `User-Agent`, while curl-impersonate profiles are correctly classified as real browser engines (`chromium`, `webkit`). The `-linux` profile variants correct the stock (Windows/macOS-declaring) profiles' UA/`Sec-CH-UA-Platform` to Linux, since that's traffgen's actual runtime OS.
- **`tools/fingerprint-matrix.sh`** — cycles through every `--impersonate` profile against every suite that honors it, printing UTC timestamps for correlating results against a SASE/NGFW dashboard's event log.

### Fixed
- **`docker-entrypoint.sh` — curl-impersonate's Firefox profiles were silently broken**: `curl-impersonate-ff` links against NSS and needs the `nss-plugin-pem` package to load the system CA bundle; without it every `curl_ff*` request failed with no response. Fixed for the stock Firefox profile as well as the new Linux variant.

---

## [3.10.2] — 2026-07-10

### Fixed
- **`docker-entrypoint.sh` — TLS-interception auto-probe blind spot**: the automatic proxy-CA detection (`auto_trust_proxy_ca()`, Option 3) only probed 15 cloud/developer-infra hosts (Google, Microsoft, Apple, GitHub, package registries, CA/OCSP endpoints). Most SASE/TLS-inspection vendors (Cato Networks, Zscaler, Palo Alto Prisma, Netskope, etc.) ship default bypass rules exempting exactly these categories — and in practice often major consumer brands and AI/LLM services too — from inspection, so the probe could report "no interception detected" and skip installing the proxy's CA even while the proxy was actively inspecting — and breaking cert validation on — traffgen's actual test traffic. Added 10 ordinary consumer-web hosts (news, commerce, reference, entertainment) and 8 AI/LLM hosts (ChatGPT, Claude, Gemini, Copilot, Perplexity, Character.AI, Hugging Face) to the probe set (32 hosts total, all rarely on a vendor's default bypass list), and added an explicit warning when the probe comes back fully clean, pointing at Option 1 (bind-mount) / Option 2 (`EXTRA_CA_CERT`) as the reliable fallback.
- **`docs/deployment.md`** — documented the bypass-list blind spot and updated the auto-probe host count/example output.

### Added
- **TLS-inspection vendor detection** (`tls-inspection` suite, `_PROXY_VENDOR_MAP`) — added issuer CN/Org matching for 22 more SASE/firewall vendors: SonicWall, Hillstone Networks, Stormshield, Array Networks, Sangfor, Huawei, Zyxel, Netgate/pfSense, OPNsense/Deciso, HPE Aruba Networking, VMware/Broadcom VeloCloud, Citrix/NetScaler, Todyl, NordLayer, Absolute Secure Access, Axis Security (HPE), Ericom Security, GFI KerioControl, and Untangle/Arista ETM/Smoothwall.

---

## [3.10.1] — 2026-06-11

### Fixed
- **Block page accuracy** — HTTP 200 responses whose bodies contain vendor-agnostic block-page phrases (`Access Denied`, `Request Blocked`, `Policy Violation`, `threat prevention`, vendor names like `zscaler`, `fortigate`, `palo alto networks`, etc.) are now reclassified as `blocked` instead of `allowed`. Applies to all `requests`-based suite functions. Blocked-via-200 probes appear as `200bp` in the HTTP code breakdown. Curl-based probes (which discard the body with `-o /dev/null`) are unchanged.
- **`c2_beacon_targets` — broken HTTPS entry** — removed `https://www.testmyids.com` (TLS certificate error: tlsv1 alert internal error). The HTTP entry `http://www.testmyids.com` is retained.
- **CI — Node.js 24 migration** — added `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true` to all three GitHub Actions workflows (`docker-publish.yml`, `msf-base-publish.yml`, `docs-check.yml`) ahead of GitHub's forced migration on 2026-06-16.

---

## [3.10.0] — 2026-06-11

### Added
- **`crypto-mining` suite** — stratum protocol handshakes on authorised test hosts (testmyids.com / scanme.nmap.org) across all common stratum ports (3333, 4444, 9200, 10128, 13333, 14444, 45700), plus DNS lookups for 15 well-known mining-pool domains. Validates NGFW stratum DPI, ET COINMINER Snort/Suricata signatures, and crypto-mining DNS threat-intel feeds on any NGFW, IDS/IPS, or SASE platform.
- **`ransomware` suite** — three-vector ransomware pre-encryption pattern simulation: (1) DNS lookups for sinkholed/seized ransomware C2 domains (WannaCry kill-switch, REvil DOJ seizure, Conti, DarkSide, Maze, DoppelPaymer, Cl0p, Dharma/Phobos); (2) geo-IP check-in requests to public IP-geolocation APIs using ransomware-family user-agents (the country-exclusion check present in LockBit, ALPHV, REvil, Conti); (3) C2 HTTP beacons to httpbin.org and testmyids.com using ransomware URI patterns (/gate.php, /is_alive, /token) and observed implant UAs (Go-http-client, python-requests, WinHTTP, PowerShell). Validates DNS reputation, URI-pattern, UA-based, and behavioural anomaly rules.
- Total suite count is now **57**.

### Fixed
- **`nmap` suite — `nmap_cve` parallelism**: replaced `--script=ALL` (600+ NSE scripts, 10–20 min per host) with the targeted set `default,vuln,exploit,malware,auth` (~80 scripts covering all security-relevant triggers). Hosts now run in parallel (up to 3 workers via `ThreadPoolExecutor`) so wall-clock time stays under 2.5 minutes regardless of host count. Suite watchdog timeout reduced from 210 s to 150 s.

---

## [3.9.3] — 2026-06-11

### Fixed
- **Loop resilience** — wrapped every test iteration in `try/except` so a crash in one test never stops the loop. `WATCHDOG.kick()` moved to the start of `_run_guarded()` so the full 600 s watchdog budget is available for each test. Watchdog is also kicked inside the web-pause wait loop so a dashboard pause cannot trigger a container restart.
- **`ips-ua` crash** — `_size_to_limits()` called with 6 positional arguments instead of 5 (the function signature uses a keyword-only `xs=` parameter). Fixed by removing the spurious extra argument.
- **`cve-probe` crash** — same `_size_to_limits()` 6-argument bug; fixed identically.
- **Thread health monitoring** — `run_test()` now logs a warning when the active thread count exceeds 30, indicating resource pressure from accumulated timed-out daemon threads.
- **Stager — Raspberry Pi 4 (32-bit Raspbian)** — the `download.docker.com/linux/raspbian` repository was removed in 2023. `stager.sh` now uses the Debian repo for all Raspbian devices (Pi 4 and Pi 5), matching Docker's official installation instructions.
- **Stager — macOS Docker Desktop startup timeout** — increased from 60 s (30 × 2 s) to 120 s (60 × 2 s) to accommodate slower first-launch on M1/M2/M3 hardware.

---

## [3.9.2] — 2026-05-xx

### Fixed
- `iperf3` silent failures: added per-server connect timeout (5 s) and per-run output validation. Servers that fail to respond within the window are skipped and counted as `dropped`.

---

## [3.9.1] — 2026-05-xx

### Added
- `iperf3` suite restored: TCP bidirectional bandwidth test (`--bidir`) against 10 public iperf3 servers on port 5201. Size controls server count (XS=1 … XL=all 10).

### Changed
- Diagnostics rework: cleaner output, wider login card.

---

## [3.9.0] — 2026-04-xx

### Added
- `ips-ua` suite: ~260 malicious/suspicious HTTP User-Agent strings against `testmyids.com` and `scanme.nmap.org`. Covers C2 frameworks (Cobalt Strike, Metasploit, Empire, Sliver), infostealers, scanners, and credential-attack tools.
- `cve-probe` suite: 31 CVE-matched HTTP exploit probes against `testmyids.com` and `scanme.nmap.org`. Covers Log4Shell, Shellshock, Struts2, Spring4Shell, EternalBlue, ProxyLogon, Zerologon, and more.

---

> **Older versions** — see [GitHub releases](https://github.com/jdibby/traffgen/releases) and `git log` for full history.
