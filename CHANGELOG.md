# Changelog

All notable changes to Traffgen are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
