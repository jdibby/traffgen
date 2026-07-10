# Configuration

## CLI Flags

| Flag | Values | Default | Description |
|---|---|---|---|
| `--suite` | Any suite name (see `--list`) | `all` | Test suite to run |
| `--size` | `XS` `S` `M` `L` `XL` | `S` | Traffic volume / intensity |
| `--loop` | — | off | Loop forever in a randomised round-robin deck — every test runs once per round before any test repeats |
| `--max-wait-secs` | integer | `20` | Max random pause between iterations when looping |
| `--nowait` | — | off | Disable all inter-test pauses (loop and single-run mode) |
| `--crawl-start` | URL | `https://data.commoncrawl.org` | Seed URL for the `web-crawl` suite |
| `--lateral-networks` | CIDRs | *(auto-detect)* | Comma-separated CIDRs to target in the `lateral-movement` suite (e.g. `192.168.1.0/24,10.0.0.0/24`). Omit to scan all auto-detected networks. |
| `--impersonate` | `off` `chrome116` `chrome116-linux` `chrome99-android` `ff117` `ff117-linux` `edge101` `edge101-linux` `safari15-5` | `off` | Issue HTTP(S) probes through a [curl-impersonate](https://github.com/lwthiker/curl-impersonate) binary instead of system curl / Python `requests`, replicating a real browser's TLS ClientHello, HTTP/2 fingerprint, and Client Hint headers. Applies to every HTTP(S)-probing suite. See [Browser Fingerprint Impersonation](#browser-fingerprint-impersonation---impersonate) below. |
| `--list` | — | — | Print all suites with descriptions and exit |
| `--version` | — | — | Print version and exit |

```bash
# List all available suites with descriptions
docker run --pull=always -it jdibby/traffgen:latest --list

# Run a specific suite at high volume
docker run --pull=always -it jdibby/traffgen:latest --suite=lateral-movement --size=L

# Loop indefinitely with 30-second max wait between tests
docker run --pull=always -it jdibby/traffgen:latest --suite=all --size=S --loop --max-wait-secs=30

# Run with no pauses between tests (stress mode)
docker run --pull=always -it jdibby/traffgen:latest --suite=https --size=XL --nowait
```

---

## Traffic Volume (`--size`)

The `--size` flag scales test intensity across all suites — more requests, larger files, more targets:

| Size | Intended Use |
|:---:|---|
| ⚪ `XS` | Ultra-light — single tiny requests, very slow pacing; ideal for smoke tests |
| 🟢 `S` | Long-running background daemons — low bandwidth impact |
| 🟡 `M` | General-purpose testing |
| 🟠 `L` | Heavier load for firewall and IDS stress tests |
| 🔴 `XL` | Maximum volume — capacity and saturation testing |

---

## Traffic Pacing

Traffgen is designed to look like **normal human traffic** — not a scanner or DDoS tool. Every layer has deliberate pacing built in:

| Layer | Behavior |
|---|---|
| **Between tests** | 2–5 s random pause after every test function (single-run mode). Loop mode uses `--max-wait-secs` (default 20 s). `--nowait` removes all pauses. |
| **Concurrent requests** | `_run_head_batch` (used by `https`, `ad-tracker`, `ai-browse`, `c2-useragents`, etc.) uses **3 concurrent workers** with 0.2–0.6 s random jitter between each request submission. |
| **DNS over HTTPS** | 0.3–0.8 s between each DoH query. |
| **DNS over TLS** | 0.5–1.2 s between TLS handshakes. |
| **NTP** | 0.4–1.0 s between UDP probes. |
| **Nmap** | 1–3 s between host scans (on top of nmap's own per-host timeout). |
| **C2 beacon** | Bimodal jitter: 80 % short (1–5 s), 20 % slow-and-low (10–30 s) — matches real C2 beacon distributions. |
| **DNS exfil** | 0.3–2.0 s between queries with mixed query types (TXT/A/MX). |
| **VoIP / video** | 0.2–1.5 s between every STUN probe, UCaaS HTTPS request, and SIP OPTIONS. |

The result: traffic patterns that appear in firewall and SIEM logs as **individual sessions from a single workstation**, not a flood.

---

## Custom Endpoints

All network targets are defined as plain Python lists in `endpoints.py` — DNS resolvers, domain names, HTTPS URLs, user-agent strings, SNMP community strings, BGP neighbors, and more. Test logic lives in `generator.py` and references these lists by name, so you can customise targets without touching generator code.

### Bind-mounting a custom endpoints file

```bash
docker run --pull=always -it \
  -v /path/to/my-endpoints.py:/traffgen/endpoints.py \
  jdibby/traffgen:latest --suite=all --loop
```

### Hot-swap at runtime

`generator.py` also exposes a `replace_all_endpoints(url)` function that can hot-swap `endpoints.py` from a remote URL at runtime without restarting the container. The file is syntax-checked with `ast.parse()` before being written.

### Variable Reference

| Variable | Used by | Contents |
|---|---|---|
| `dns_endpoints` | `dns`, `dns-exfil` | Public DNS resolver IPs |
| `dns_urls` | `dns`, `http`, `doh` | Domain names to resolve / request |
| `doh_providers` | `doh` | DNS-over-HTTPS provider URLs |
| `dot_servers` | `dot` | `(ip, servername)` tuples for DNS-over-TLS |
| `dns_exfil_domains` | `dns-exfil` | Domains used for DNS-tunnel simulation |
| `icmp_endpoints` | `icmp`, `traceroute` | IPs for ping and traceroute |
| `bgp_neighbors` | `bgp` | BGP peer IPs for GoBGP session attempts |
| `ntp_endpoints` | `ntp` | NTP server hostnames |
| `ssh_endpoints` | `ssh` | SSH probe targets |
| `nmap_endpoints` | `nmap` | Nmap port-scan targets |
| `snmp_endpoints` | `snmp` | SNMP walk targets |
| `snmp_v1_strings` | `snmp` | SNMPv1 community strings |
| `snmp_v2c_strings` | `snmp` | SNMPv2c community strings |
| `snmp_v3_creds` | `snmp` | SNMPv3 credential tuples (user, level, auth-proto, auth-pass, priv-proto, priv-pass) |
| `http_endpoints` | `http` | Plain HTTP hostnames |
| `https_endpoints` | `https`, `web-crawl`, `http3`, `speedtest`, `web-scanner` | General HTTPS URLs |
| *(Hagezi pro blocklist)* | `ad-tracker` | 300k+ domains fetched at runtime; falls back to `ad_endpoints` in `endpoints.py` if unreachable |
| `ai_endpoints` | `ai-browse` | AI-service HTTPS endpoints |
| `webscan_endpoints` | `web-scanner` | Intentionally-vulnerable web app targets |
| `kyber_endpoints` | `post-quantum` | Post-quantum TLS server URLs |
| `malware_endpoints` | `c2-useragents` | Malware-category test URLs (WICAR, AMTSO, Google Safe Browsing test domains) |
| `c2_user_agents` | `c2-useragents`, `c2-beacon` | C2 framework and malware family UAs (Cobalt Strike, Meterpreter, Empire, DarkComet, QuasarRAT, etc.) |
| `malware_files` | `malware-samples` | RAT archive URLs for download testing |
| `c2_beacon_targets` | `c2-beacon` | Public echo services for C2 check-in simulation |
| `virus_endpoints` | `av-test` | EICAR / AV-test file URLs |
| `pornography_endpoints` | `pornography` | Adult-content URLs |
| `dlp_https_endpoints` | `dlp` | DLP test-data file URLs |
| `shadow_it_endpoints` | `shadow-it` | 27 unsanctioned cloud apps across CASB categories |
| `tor_anonymizer_endpoints` | `tor-anonymizer` | Tor/VPN/proxy sites for URL-filter anonymizer category |
| `waf_attack_targets` | `waf-attack` | Pen-test-authorised web apps for WAF probe targets |
| `data_exfil_targets` | `data-exfil-http` | Paste/file-drop services for DLP POST simulation |
| `stun_servers` | `voip` | `(host, port)` tuples for STUN Binding Requests (UDP/3478 + 19302) |
| `sip_servers` | `voip` | `(host, port)` tuples for SIP OPTIONS probes (UDP/5060) |
| `ucaas_endpoints` | `ucaas` | UCaaS platform signaling URLs (Zoom, Teams, WebEx, Meet, Slack, etc.) |
| `user_agents` | all HTTP suites | 500 realistic browser user-agent strings |
| `llm_api_endpoints` | `llm-dlp` | LLM provider REST API paths |
| `llm_web_endpoints` | `llm-dlp`, `ai-browse` | Browser-facing AI app URLs |

### User Agent Coverage

The `user_agents` list ships **500 entries** covering current 2024–2025 devices:

- **Windows** — Chrome 120–136, Firefox 120–137, Edge 120–136
- **macOS Sonoma/Sequoia** — Safari 17/18, Chrome, Firefox, Edge
- **iPhone iOS 17/18** — Safari, Chrome (CriOS), Firefox (FxiOS)
- **iPad iPadOS 17/18** — Safari, Chrome
- **Android 13–15** — Samsung Galaxy S23/S24/S25, A-series, Z-Fold, Pixel 6–9, OnePlus, Xiaomi, OPPO, vivo, Motorola, POCO, Redmi
- **Samsung Internet** 23–26, Huawei Browser, Opera, Vivaldi, Brave
- **Linux** Chrome/Firefox, ChromeOS, WebView UAs
- **Smart TVs** — Samsung Tizen, LG webOS, Sony Android TV
- **Gaming** — PS5, Xbox Series X/S
- **Other** — Meta Quest 2/3, Apple TV

---

## Browser Fingerprint Impersonation (`--impersonate`)

By default, HTTP(S)-probing suites send a realistic browser `User-Agent` and matching headers, but the underlying TLS connection is made by system `curl` (OpenSSL) or Python's `requests` library — both of which have a distinct TLS ClientHello fingerprint (JA3/JA4) that JA3-aware NGFW/SASE traffic classifiers can distinguish from a real browser, regardless of what `User-Agent` string is attached. This was confirmed live against a production Cato Networks deployment: every plain-curl/requests-based probe was classified `Client Class: restclient cpp` / `unclassified tls`, no matter which browser UA was randomly picked that round.

`--impersonate` routes the request through a [curl-impersonate](https://github.com/lwthiker/curl-impersonate) binary instead — a curl build that replicates a specific browser's actual TLS cipher order/extensions, ALPS, HTTP/2 settings frame, and Client Hint headers (`Sec-CH-UA-Platform`, etc.), not just its `User-Agent` string. In the same live testing, this correctly flipped `Client Class` to real browser-engine identifiers (`chromium`, `webkit`) instead of the generic automation bucket.

```bash
# Run the tor-anonymizer suite impersonating desktop Chrome on Linux
docker run --pull=always -it jdibby/traffgen:latest \
  --suite=tor-anonymizer --impersonate=chrome116-linux

# Run everything, impersonating Firefox
docker run --pull=always -it jdibby/traffgen:latest \
  --suite=all --impersonate=ff117
```

| Profile | Browser | Platform declared |
|---|---|---|
| `chrome116` | Chrome 116 | Windows |
| `chrome116-linux` | Chrome 116 | Linux (UA + `Sec-CH-UA-Platform` corrected — this container's actual OS) |
| `chrome99-android` | Chrome 99 Mobile | Android |
| `ff117` | Firefox 117 | Windows |
| `ff117-linux` | Firefox 117 | Linux |
| `edge101` | Edge 101 | Windows |
| `edge101-linux` | Edge 101 | Linux |
| `safari15-5` | Safari 15.5 | macOS |

The `-linux` variants exist because traffgen's own runtime genuinely is Linux — declaring Windows/macOS is not more "realistic," it's just inaccurate. curl-impersonate's stock profiles all default to Windows or macOS since those are the common desktop-browser cases; the Linux variants only rewrite the platform-declaring tokens (User-Agent + `Sec-CH-UA-Platform` where present), leaving the actual TLS/HTTP2 fingerprint untouched.

`tools/fingerprint-matrix.sh` (in the repo) cycles through every profile against every suite that honors `--impersonate`, printing UTC timestamps so results can be correlated against your NGFW/SASE dashboard event log.

**Scope:** applies to all HTTP(S)-probing suites (built on `_curl_head`, `_curl_download`, or `_probe_domain_list`) — effectively every suite except protocol-specific ones with no HTTP layer (DNS, ICMP, SNMP, BGP, SSH, etc).

**Separately:** `Device OS Type`/`OS Type` fields in some SASE dashboards (as opposed to `Client Class`) were observed to be a *persistent, per-device cached classification* rather than a live per-request signal — they did not change with `--impersonate` across live testing, regardless of profile. This appears to be inherent to how these platforms do passive device fingerprinting (TCP/IP stack-level), not something any HTTP/TLS-layer client change can influence.
