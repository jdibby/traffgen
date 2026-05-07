# 🚦 Traffgen

**Multi-protocol network traffic generator for security validation.**

[![Docker Hub](https://img.shields.io/docker/pulls/jdibby/traffgen?logo=docker&label=Docker%20Hub)](https://hub.docker.com/r/jdibby/traffgen)
[![Multi-arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64%20%7C%20arm%2Fv7-blue?logo=linux)](https://hub.docker.com/r/jdibby/traffgen)

Traffgen simulates realistic network traffic across **48 test suites** — DNS, HTTP/S, FTP, SSH, BGP, ICMP, NTP, SNMP, DoH, DoT, C2 beacons, DNS exfiltration, AI/LLM DLP, Metasploit checks, malware downloads, phishing probes, web scanning, and more.

Purpose-built to stress-test **firewalls**, **IDS/IPS**, **URL filters**, **DLP engines**, **CASB platforms**, and **SIEM pipelines**.

Runs as a Docker container with a built-in watchdog, per-test timeout guard, and healthcheck to keep it generating traffic indefinitely — no babysitting required.

---

## ⚠ Disclaimer

This tool is intended for **authorized security testing and research in controlled lab environments only**.

- You are solely responsible for obtaining explicit written permission before testing any systems or networks.
- The author(s) accept **no liability** for misuse, unauthorized access, damage, data loss, or legal consequences arising from use of this tool.
- Use of this software constitutes acceptance of these terms.

---

## ⚡ Quick Start

```bash
# Print help and available suites
docker run --pull=always -it jdibby/traffgen:latest --help

# Run all suites in a continuous loop (background daemon)
docker run --pull=always --detach --restart unless-stopped \
  --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop

# Run all suites interactively
docker run --pull=always --restart unless-stopped -it \
  jdibby/traffgen:latest --suite=all --size=S --max-wait-secs=20 --loop

# Run a single suite once
docker run --pull=always -it jdibby/traffgen:latest --suite=nmap --size=L
```

> **Docker Hub:** `jdibby/traffgen:latest` — multi-arch: `linux/amd64` · `linux/arm64` · `linux/arm/v7`

---

## 🤖 Automated Deployment

`stager.sh` installs Docker and starts the container on a fresh host. Supports Ubuntu, Debian, Rocky Linux, and Raspberry Pi 4/5.

```bash
curl -sk https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh | sudo bash
```

---

## 🖥️ Web Dashboard

Add `-p 7777:7777` to expose a live HTTPS monitoring dashboard at `https://<host>:7777`.

```bash
docker run --pull=always --detach --restart unless-stopped \
  -p 7777:7777 --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop
```

The dashboard includes:

- **Overview** — stat cards, live Network I/O sparkline in Mbps (1 s default refresh with selectable interval), requests-over-time chart, per-test breakdown table, and live events feed
- **Security** — dedicated security posture page modeled on NGFW/SASE dashboards: KPI cards (Total Probes / Blocked / Silently Dropped / Allowed), outcome-distribution donut, block & drop trend sparkline, per-suite security breakdown table sorted by blocked count, and a block-signal breakdown showing exactly how controls are signalling blocks (HTTP 403 block page, TCP RST, proxy refused, TLS intercept, DNS sinkhole, timeout). Refresh interval is configurable (default 1 m, 30 s–5 m).
- **Tests** — card grid for every suite; click any card to launch it immediately with custom settings
- **Output** — CLI-style live log with level coloring (✔ OK, ✗ Error, ⚠ Warn), section banners, and rule separators mirroring the terminal output; filterable by level
- **Health** — CPU/memory gauges, load average, disk I/O bars, network sparkline in Mbps, top-processes table
- **Dark / light mode** — toggle with the ☾ button in the topbar; preference saved across sessions
- **Controls** — pause, resume, stop, and settings drawer to change suite/size/wait without restarting the container
- **Status pill** — live state badge in the topbar: `Running` (with pulse dot), `Between Tests (Ns)` with a live countdown during inter-test pauses, `Paused`, and `Stopped`
- **Multi-user:** first browser tab gets full control; additional tabs are read-only with a visible banner

> **Full documentation:** [docs/web-dashboard.md](docs/web-dashboard.md)

---

## 🎛️ CLI Reference

| Flag | Values | Default | Description |
|---|---|---|---|
| `--suite` | See suite names below | `all` | Test suite to run |
| `--size` | `XS` `S` `M` `L` `XL` | `S` | Traffic volume / intensity |
| `--loop` | — | off | Loop forever in a randomised round-robin deck — every test runs once per round before any test repeats |
| `--max-wait-secs` | integer | `20` | Max random pause between iterations when looping |
| `--nowait` | — | off | Disable all inter-test pauses (loop and single-run mode) |
| `--crawl-start` | URL | `https://data.commoncrawl.org` | Seed URL for the `crawl` suite |
| `--list` | — | — | Print all suites with descriptions and exit |
| `--version` | — | — | Print version and exit |

---

## 🧪 Test Suites

### 🌐 Connectivity & Network Layer

| Suite | Description |
|---|---|
| 🔍 `dns` | `dig` queries to multiple public DNS resolvers (Google, Cloudflare, Quad9, OpenDNS, and others) across a rotating set of domains. Exercises DNS inspection, logging, and resolver-policy enforcement. |
| 📡 `icmp` | `ping` and `traceroute` to a set of well-known public hosts. Validates ICMP allow/deny policies and verifies that path-tracing generates the expected firewall events. |
| 🔀 `bgp` | Starts a GoBGP daemon (AS 65555) and attempts peering sessions with configured BGP neighbors from `endpoints.py`. Tests BGP route-filter policies and monitors for rogue peering attempts. |
| 🕐 `ntp` | NTP UDP/123 probes to a list of public time servers. Validates NTP allow policies and confirms that outbound time-sync traffic generates expected SIEM log entries. |
| 🔑 `ssh` | Non-interactive SSH connection attempts to a list of hosts on TCP/22. Connections terminate immediately after key exchange — no credentials submitted. Validates SSH reachability and confirms session logs appear in security tooling. |

---

### 🌍 Web & HTTP

| Suite | Description |
|---|---|
| 📄 `http` | HTTP HEAD requests to a broad set of plain-HTTP endpoints, followed by ZIP and tar.gz file downloads. Tests HTTP inspection, file-type enforcement, and download logging. |
| 🔒 `https` | HTTPS HEAD requests to a wide endpoint pool followed by an iterative TLS crawl. Tests TLS inspection policy, certificate validation enforcement, and HTTPS download logging. |
| 🕷️ `crawl` | Iterative web crawl from a configurable seed URL (`--crawl-start`). Follows links up to a depth that scales with `--size`. Mimics a browser session for URL categorisation and user-activity analytics testing. |
| ⏱️ `url-response` | Measures HTTPS response times across a diverse URL set using the Python `requests` library. Populates URL-filter logs and response-time dashboards. |
| 🪣 `s3` | Simulates S3 bucket upload and download traffic. GET requests target a mix of public AWS datasets and private-style bucket paths (200 or 403 — both generate CASB-visible S3 traffic). PUT requests upload small synthetic payloads containing PII, credentials, and confidential strings to S3 paths — requests return 403 (no credentials) but are fully visible to DLP and CASB engines as cloud-upload/exfiltration attempts. Also targets Wasabi and Backblaze B2 S3-compatible endpoints. |
| 💾 `bigfile` | Streams an HTTP download to `/dev/null` — file size scales with `--size` (XS=10 MB, S=100 MB, M=1 GB, L=2 GB, XL=5 GB). Tests large-file and bandwidth-cap policies across the full volume range without always hitting the ceiling. |
| 📂 `ftp` | FTP file download via `curl` with rate limiting against a public test server. Validates FTP inspection, logging, and file-transfer policy enforcement. |

---

### 🔐 Encrypted & Modern Protocols

| Suite | Description |
|---|---|
| 🔮 `kyber` | HTTPS HEAD requests using the post-quantum **X25519MLKEM768** (Kyber) key exchange. Tests whether TLS inspection infrastructure handles hybrid post-quantum cipher suites without breaking connectivity. |
| 🌐 `doh` | DNS over HTTPS (RFC 8484 JSON API) via `curl` to a rotating list of DoH providers. Tests DoH detection and DNS-over-HTTPS bypass policy enforcement. |
| 🔏 `dot` | DNS over TLS on TCP/853 via `openssl s_client`. Tests whether DoT connections are logged, blocked, or decrypted by TLS inspection. |
| ⚡ `http3` | HTTP/3 QUIC HEAD requests via a native `aioquic` implementation (`QuicConnectionProtocol` + `H3Connection`). QUIC runs over UDP/443 and is invisible to many legacy inspection stacks. Tests QUIC visibility and QUIC-block policy enforcement without relying on a curl build that supports HTTP/3. |

---

### 🛡️ Security & Threat Intelligence

| Suite | Description |
|---|---|
| 🚨 `ids-trigger` | Sends a HEAD request to `testmyids.com` with the `BlackSun` user-agent string — a classic Snort/Suricata IDS/IPS signature. Confirms that IDS alert rules are active and generating SIEM events. |
| 🦠 `malware-agents` | HEAD requests to benign endpoints using known malware user-agent strings (Emotet, Cobalt Strike, AsyncRAT, and others). Tests whether user-agent-based IDS/IPS signatures fire for malware-associated UA patterns. |
| ⬇️ `malware-download` | Downloads known-malware file samples from public repositories to `/dev/null`. Tests whether anti-malware scanning or URL reputation filtering blocks downloads before they reach the endpoint. |
| 🧬 `virus` | Downloads EICAR anti-virus test files and virus sample markers to `/dev/null`. Confirms that inline AV scanning is active and reporting correctly. |
| 🚫 `domain-check` | Probes a random sample of domains from the **Hagezi DNS blocklist**. Tests whether DNS-based threat intelligence blocks known bad domains and generates expected SIEM events. |
| 🎣 `phishing-domains` | Probes a random sample of domains from an active phishing domain feed. Tests anti-phishing DNS/URL filtering, confirms phishing-category blocks appear in firewall logs, and validates events reach the SIEM. |
| 🔤 `squatting` | Runs `dnstwist` typosquatting generation against popular brand domains. Generates hundreds of lookalike domain variants (homoglyphs, additions, transpositions) and resolves them. Tests whether DNS analytics detect typosquatting lookups. |
| 🗺️ `nmap` | Nmap port scan covering ports 1–1024 against a target list, followed by an NSE CVE-script scan. Tests whether IDS/IPS detects and alerts on port-scan patterns and CVE-detection signatures. |
| 🔬 `web-scanner` | Nikto web vulnerability scanner against `testmyids.com`. Generates a broad mix of vulnerability-probe HTTP requests (path traversal, header injection, known CVE probes). Scan duration scales with `--size`. |
| 💥 `metasploit-check` | Runs Metasploit `.rc` scripts in **check-only mode** — no exploitation performed. Scripts issue the same probe traffic Metasploit uses to fingerprint a target before exploit delivery, without sending any payload. Covers 46 check scripts across web apps, network appliances, databases, and protocol-level scanners. Tests IDS/IPS, CASB, and SIEM detection of Metasploit fingerprint traffic. |

---

### 🕵️ Evasion & Advanced Techniques

#### 📻 `c2-beacon`
Simulates a C2 beacon: periodic HTTP POST requests using randomised malware user-agent strings with random jitter delay between beacons. The request body contains a base64-encoded pseudo-random session ID, mimicking the check-in pattern of common RAT families. Tests C2 beacon detection rules in SIEM and NDR platforms.

#### 🧅 `dns-exfil`
Simulates DNS data exfiltration using base32-encoded subdomains in DNS TXT queries, mimicking traffic produced by `iodine` and `dnscat2`. Tests whether DNS analytics detect high-entropy subdomain patterns characteristic of DNS tunnelling.

#### 🤖 `llm-dlp`
Simulates the real-world scenario of an employee pasting sensitive data into a public AI assistant. Runs two phases:

**Phase 1 — API POST simulation:** Generates unique blocks of format-valid but obviously fake PII (SSN, credit card, phone, passport, MRN, credentials) and POSTs them inside realistic chat-completion requests to randomly chosen LLM API endpoints. 25% of requests embed a **prompt injection / jailbreak pattern** to exercise AI-specific DLP rules.

Supports the correct request format per provider:

| Provider | Auth | Body format |
|---|---|---|
| OpenAI (GPT-4o, o3-mini, …) | `Authorization: Bearer sk-…` | `messages` array |
| Anthropic (Claude Opus/Sonnet/Haiku) | `x-api-key` + `anthropic-version` | `messages` array |
| Google (Gemini 2.0 Flash, 1.5 Pro, …) | `x-goog-api-key` | `contents/parts` |
| Cohere (Command-R+, …) | `Authorization: Bearer …` | flat `message` field |
| Azure OpenAI | `api-key` header | `messages` array |
| Perplexity, Mistral, Groq, Together, Fireworks, xAI, DeepSeek, OpenRouter, and more | `Authorization: Bearer …` | `messages` array |

All requests use a fake `sk-DLPTEST-…` token — responses are HTTP 401/403. The value is in the outbound traffic pattern, not the response.

**Phase 2 — Browser UI HEAD requests:** HEAD requests to 60+ browser-facing AI application URLs covering text/chat assistants (ChatGPT, Claude.ai, Gemini, Copilot, Perplexity, Grok), code-generation tools (GitHub Copilot, Cursor, Codeium), image-generation services (Midjourney, Adobe Firefly, DALL-E), and enterprise AI platforms (Microsoft 365 Copilot, Google Workspace Gemini, AWS Bedrock, Azure AI).

**✅ Security controls validated:**
- 🔏 DLP rules for SSN, PCI-DSS card numbers, phone, passport, and credential patterns in outbound HTTPS POST bodies
- 🌐 AI-category URL filtering for API hostnames and browser UIs
- 📊 Behavioural analytics detecting PII uploads to cloud AI services
- 🛑 Prompt injection / jailbreak detection (AI security and CASB platforms)

---

### 🚧 Content Filtering

| Suite | Description |
|---|---|
| 📢 `ads` | HEAD requests to advertising networks, analytics trackers, and telemetry endpoints. Tests ad-blocker and tracker-block URL filter categories. |
| 🤖 `ai-browse` | HEAD requests to AI and LLM service endpoints (API gateways, model-serving hosts). Tests the AI-category URL filter independently from browser-facing chat UIs. Useful for testing API-level AI access policies. |
| 🔞 `pornography` | HTTPS crawl of adult-content endpoints. Tests the adult-content URL filter category and confirms policy enforcement is logging correctly. |
| 🗂️ `dlp` | Downloads DLP test files over HTTPS containing structured PII and PCI data patterns (SSNs, credit card numbers, bank account numbers). Tests inline DLP file-scanning and download-inspection policies. |

---

### 📞 VoIP & Video

| Suite | Description |
|---|---|
| 📞 `voip` | Simulates voice and video call traffic across three phases to trigger application-identification on NGFWs and SASE platforms (Cato Networks, Prisma Access, Palo Alto, etc.):<br><br>**Phase 1 — STUN Binding Requests:** Raw UDP packets with the STUN magic cookie (`0x2112A442`) sent to public STUN servers (Google, Cloudflare, Zoom, Mozilla, and others on UDP/3478). The magic cookie is the primary fingerprint app-ID engines use to classify WebRTC, Zoom, Teams, and generic VoIP sessions.<br><br>**Phase 2 — UCaaS Signaling:** HTTPS requests to meeting/calling APIs for Zoom, Microsoft Teams, Cisco WebEx, Google Meet, Slack, RingCentral, 8x8, GoTo Meeting, Discord, WhatsApp, FaceTime, Vonage, Twilio, and Jitsi. URL-category databases identify these hostnames as "voice/video-conferencing" and trigger the relevant policy hit.<br><br>**Phase 3 — RTP Media Simulation:** UDP packets with valid RTP headers (V=2, PCMU/PCMA audio or H.264/H.265 video payload type) sent to STUN server IPs on standard media ports (5004, 5005, 16384+). Triggers RTP/SRTP app-classification rules without establishing a real media session. Packets are paced with 0.2–0.8 s gaps to mimic real codec timing. |

---

### 📊 Performance

| Suite | Description |
|---|---|
| 🚀 `speedtest` | Runs a `fast.com` speed test via the `fastcli` Python package. Rounds scale with `--size`. Establishes baseline bandwidth and confirms speed-test traffic appears in application-awareness logs. |
| 📡 `snmp` | Three-function suite covering all SNMP versions: **SNMPv1** (18 community strings: `public`, `private`, `cisco`, `ILMI`, `manager`, `guest`, …), **SNMPv2c** (26 community strings: `public`, `private`, `readonly`, `readwrite`, `network`, `core`, …), and **SNMPv3** (20 credential sets across noAuthNoPriv, authNoPriv MD5/SHA, and authPriv DES/AES). Tests SNMP inspection, community-string detection, and SNMPv3 weak-credential signatures. |

---

### 🔄 Meta

#### `all`
Runs every suite above in randomised order. This is the default when no `--suite` flag is provided.

---

## 📈 Traffic Volume

The `--size` flag scales test intensity across all suites:

| Size | Intended Use |
|:---:|---|
| ⚪ `XS` | Ultra-light — single tiny requests, very slow pacing; ideal for smoke tests |
| 🟢 `S` | Long-running background daemons — low bandwidth impact |
| 🟡 `M` | General-purpose testing (default) |
| 🟠 `L` | Heavier load for firewall and IDS stress tests |
| 🔴 `XL` | Maximum volume — capacity and saturation testing |

---

## ⏱️ Traffic Pacing

Traffgen is designed to look like **normal human traffic** — not a scanner or DDoS tool. Every layer of the generator has deliberate pacing built in:

| Layer | Behavior |
|---|---|
| **Between tests** | 2–5 s random pause after every test function (single-run mode). Loop mode uses `--max-wait-secs` (default 20 s). `--nowait` removes all pauses. |
| **Concurrent requests** | `_run_head_batch` (used by `https`, `ads`, `ai-browse`, `malware-agents`, etc.) uses **3 concurrent workers** (down from 6) and adds 0.2–0.6 s random jitter between each request submission — no burst of parallel connections. |
| **DNS over HTTPS** | 0.3–0.8 s between each DoH query. |
| **DNS over TLS** | 0.5–1.2 s between TLS handshakes. |
| **NTP** | 0.4–1.0 s between UDP probes. |
| **Nmap** | 1–3 s between host scans (on top of nmap's own per-host timeout). |
| **C2 beacon** | Bimodal jitter: 80 % short (1–5 s), 20 % slow-and-low (10–30 s) — matches real C2 beacon distributions. |
| **DNS exfil** | 0.3–2.0 s between queries with mixed query types (TXT/A/MX). |
| **VoIP / video** | Explicit 0.2–1.5 s sleeps between every STUN probe, UCaaS HTTPS request, and RTP packet. |

The result: traffic patterns that appear in firewall and SIEM logs as **individual sessions from a single workstation**, not a flood.

---

## 🏗️ Architecture

Three-stage multi-arch build (`linux/amd64`, `linux/arm64`, `linux/arm/v7`):

| Stage | Base Image | Purpose |
|---|---|---|
| `gobgp-build` | `golang:1.23-bookworm` | Compiles GoBGP v3.36.0 with stripped binaries |
| `msf-build` | `debian:bookworm-slim` | Clones Metasploit, vendors gems, strips payloads and docs |
| runtime | `debian:bookworm-slim` | Slim runtime — only compiled binaries and vendored Metasploit |

**🐕 Watchdog:** A 600-second inactivity timer in `generator.py` force-exits the process when no test activity is detected. The container's `restart: unless-stopped` policy relaunches it immediately, providing self-healing for silent hangs.

**⏱️ Per-test guard:** Every test runs in a daemon thread with a per-suite wall-clock limit (`_SUITE_TIMEOUTS`). If a test exceeds its limit the main loop advances to the next test rather than blocking — preventing any single stuck operation from halting traffic generation.

**❤️ Healthcheck:** `healthcheck.sh` uses `pgrep` to verify `generator.py` is running. Evaluated every 10 seconds with a 3-second timeout and 2 retries.

**🚀 Entrypoint:** `docker-entrypoint.sh` auto-detects TLS-inspection proxies, installs any injected CA certificates, then launches `python3 -u /traffgen/generator.py`. Default `CMD` is `--suite=all --size=S --max-wait-secs=20 --loop`.

**📊 Suite Summary:** After every suite completes, a summary panel is printed to the CLI — see [Suite Summary](#-suite-summary) below.

---

## 🔒 TLS Inspection Proxies

When a TLS-inspection proxy (Cato Networks, Prisma Access, Palo Alto, Zscaler, Netskope, etc.) sits between the container and the internet, it re-signs intercepted HTTPS connections with its own CA certificate. Tools that verify certificates — Ruby/Metasploit, `openssl s_client` (DoT tests), and Go — will reject those connections unless the proxy's CA is trusted.

`docker-entrypoint.sh` handles this at startup through three options, applied in order:

### Option 3 — Fully automatic _(zero configuration)_

Just run the container — no flags, no cert files. On startup the entrypoint probes **15 diverse HTTPS hosts** in parallel, spanning CDN providers, cloud platforms, developer tooling, OS vendors, and social platforms. Using a wide target set means the probe catches interception even when the proxy whitelists specific URL categories or ASNs (selective bypass).

For every host that fails TLS verification the entrypoint:

1. Fetches the full certificate chain the proxy is presenting (`openssl s_client -showcerts`)
2. Fingerprints (SHA-256) every `CA:TRUE` cert in the chain that is not yet in the system trust store
3. Votes across all failed hosts — the CA fingerprint seen on the most hosts wins
4. Saves the winning cert to `/usr/local/share/ca-certificates/auto-proxy-ca.crt` and runs `update-ca-certificates`
5. Runs a **verification pass** on a sample of previously-failed hosts to confirm the fix worked

Hosts that pass verification are reported as **bypassed** — useful for understanding the proxy's whitelist policy.

```
[entrypoint] Probing 15 hosts to detect TLS interception...
[entrypoint] Results: 3 clean  11 intercepted  1 unreachable
[entrypoint] Selective bypass detected:
[entrypoint]   Bypassed (clean cert) : www.apple.com ocsp.pki.goog www.digicert.com
[entrypoint]   Intercepted           : www.google.com www.cloudflare.com github.com ...
[entrypoint] Fingerprinting CA certs across 11 intercepted host(s)...
[entrypoint] Proxy CA identified (seen on 11 of 11 intercepted host(s)):
[entrypoint]   Subject    : CN=Cato Networks Root CA, O=Cato Networks, C=IL
[entrypoint]   Expires    : Dec 31 23:59:59 2035 GMT
[entrypoint]   SHA-256 fp : 4A3B...
[entrypoint] Installing proxy CA into trust store...
[entrypoint] Verification pass...
[entrypoint]   www.google.com ✓ now verified
[entrypoint]   github.com ✓ now verified
[entrypoint]   pypi.org ✓ now verified
[entrypoint] Proxy CA trusted — TLS interception will work transparently.
```

Set `DISABLE_AUTO_CA=1` to skip this step if you want to manage certs entirely yourself.

### Option 1 — Bind-mount a certificate file

Export your proxy's CA as a PEM file and mount it into the container:

```bash
docker run --pull=always --detach --restart unless-stopped \
  -v /path/to/proxy-ca.crt:/usr/local/share/ca-certificates/proxy-ca.crt \
  --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop
```

### Option 2 — Inline PEM via environment variable

Useful for Kubernetes secrets, Docker Swarm configs, or CI pipelines:

```bash
docker run --pull=always --detach --restart unless-stopped \
  -e EXTRA_CA_CERT="$(cat /path/to/proxy-ca.crt)" \
  --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop
```

Options 1 and 2 are installed first; the auto-probe (Option 3) runs after, so if a manually-supplied cert already covers the proxy the probe will see a clean chain and skip.  All options can be combined, and multiple `.crt` files can be mounted simultaneously.

> 💡 **Note:** `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE` are pre-configured in the image to point at the system CA bundle, so Python's `requests` library and `ssl` module automatically pick up any injected CA without code changes.

---

## 📊 Suite Summary

After every suite completes, traffgen prints a **Suite Summary** panel directly in the CLI output. This is the quickest way to tell whether your upstream security controls are seeing and acting on the traffic.

```
╭──── Suite Summary ─────────────────────────────────╮
│  suite       https_random                          │
│  elapsed     14.2s                                 │
│  attempted   20                                    │
│  allowed      12                                   │
│  blocked       5                                   │
│  dropped       2                                   │
│  errors        1                                   │
│  http codes  2xx=12  4xx=5                         │
╰────────────────────────────────────────────────────╯
```

### Fields

| Field | What it means |
|---|---|
| **suite** | The internal function name for the suite that just ran |
| **elapsed** | Wall-clock time the suite took to complete |
| **attempted** | Total number of individual probes sent (HTTP requests, DNS queries, pings, etc.) |
| **allowed** | Probes that reached the destination without being intercepted (2xx, 3xx, non-block 4xx/5xx) |
| **blocked** | Probes explicitly intercepted by a security control — HTTP 403/407/451/511 block page, TCP RST (curl exit 7), proxy refused (exit 5), or TLS intercept (exit 35) |
| **dropped** | Probes with no response — firewall silent-drop rule (timeout, exit 28) or DNS sinkhole (exit 6) |
| **errors** | Genuine infrastructure failures — DNS resolution error, unexpected exception |
| **http codes** | Breakdown of HTTP status code families for HTTP-based suites |

### Three-outcome classification

Every probe is classified into one of three security-relevant outcomes:

| Outcome | Signal | What it means |
|:---:|:---:|---|
| ✅ **Allowed** | 2xx, 3xx, non-block 4xx/5xx | Traffic reached its destination — **security control did not intervene** |
| 🟡 **Blocked** | HTTP 403/407/451/511 · TCP RST · Proxy refused | A security control **explicitly intercepted** the traffic — block page served, firewall RST, proxy refusal |
| 🟣 **Dropped** | Timeout · DNS NXDOMAIN | Traffic was **silently dropped** — firewall drop rule (no RST), DNS sinkhole, or no route |

The distinction between **blocked** and **dropped** is critical for validating your policies:
- **Blocked** means your control is active and returning a signal (block page, RST). This is the gold standard — users see an error, logs show the block, SIEM gets an event.
- **Dropped** means the traffic disappears silently. Effective at stopping the threat, but harder to audit — no user-visible error, no SIEM event from the control itself.

### Interpreting results

- **High `allowed` on `malware-download`, `virus`, `dlp`, `pornography`** → those suites are passing through uninspected. Your security controls need attention for those categories.
- **High `blocked` on `llm-dlp`, `c2-beacon`, `malware-agents`** → your proxy/CASB is actively blocking and returning its own response — security controls are working correctly.
- **High `dropped` on any suite** → traffic is being silently terminated. Your firewall has drop (not reject) rules — effective but produces no user-visible feedback and may be harder to audit in SIEM.
- **High `errors` on `dns`, `ntp`, `icmp`** → those protocols may be perimeter-blocked at the infrastructure level — check outbound policies for UDP/53, UDP/123, and ICMP.
- **Mix of `blocked` and `dropped` on the same suite** → your firewall has both block-and-log and drop rules. Common in layered security stacks (NGFW + SASE).

### Security Summary dashboard tab

The web dashboard's **Security** tab aggregates these outcomes across all suites in real time, displaying:
- KPI cards: Total Probes · Blocked · Silently Dropped · Allowed
- Outcome distribution donut (configurable refresh interval, default 1 m)
- Block & drop trend sparkline over time
- Per-suite breakdown table sorted by blocked count
- Block signal breakdown — exactly how each control is signalling (HTTP 403, TCP RST, proxy refused, TLS intercept, DNS sinkhole, timeout)

> 💡 **Non-HTTP suites** (`dns`, `ping`, `traceroute`, `ssh`, `ntp`, `snmp`, `nmap`, `metasploit-check`, etc.) show `allowed` and `errors` only — no HTTP code breakdown. An `allowed` response means the probe ran to completion without an exception; an `error` means the subprocess timed out, the host was unreachable, or the command itself failed.

---

## 🎯 Custom Endpoints

All network targets are defined as plain Python lists in `endpoints.py` — DNS resolvers, domain names, HTTPS URLs, user-agent strings, SNMP community strings, BGP neighbors, and more. Test logic lives in `generator.py` and references these lists by name, so you can customise targets without touching generator code.

### Variable reference

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
| `https_endpoints` | `https`, `crawl`, `http3`, `speedtest`, `web-scanner` | General HTTPS URLs |
| `ad_endpoints` | `ads` | Ad-network and tracker URLs |
| `ai_endpoints` | `ai-browse` | AI-service HTTPS endpoints |
| `webscan_endpoints` | `web-scanner` | Intentionally-vulnerable web app targets |
| `kyber_endpoints` | `kyber` | Post-quantum TLS server URLs |
| `malware_endpoints` | `malware-agents` | Malware / C2-category domains |
| `malware_user_agents` | `malware-agents`, `c2-beacon` | Bot / malware user-agent strings |
| `malware_files` | `malware-download` | RAT archive URLs for download testing |
| `c2_beacon_targets` | `c2-beacon` | Public echo services for C2 check-in simulation |
| `virus_endpoints` | `virus` | EICAR / AV-test file URLs |
| `squatting_endpoints` | `domain-check`, `phishing-domains` | Domains probed for squatting detection |
| `pornography_endpoints` | `pornography` | Adult-content URLs |
| `dlp_https_endpoints` | `dlp` | DLP test-data file URLs |
| `user_agents` | all HTTP suites | 500 realistic browser user-agent strings |
| `stun_servers` | `voip` | `(host, port)` tuples for STUN Binding Requests |
| `ucaas_endpoints` | `voip` | UCaaS platform signaling URLs (Zoom, Teams, WebEx, etc.) |
| `llm_api_endpoints` | `llm-dlp` | LLM provider REST API paths |
| `llm_web_endpoints` | `llm-dlp`, `ai-browse` | Browser-facing AI app URLs |

### User agents

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

### Customising

To use a custom endpoints file, bind-mount it at container start:

```bash
docker run --pull=always -it \
  -v /path/to/my-endpoints.py:/traffgen/endpoints.py \
  jdibby/traffgen:latest --suite=all --loop
```

`generator.py` also exposes a `replace_all_endpoints(url)` function that can hot-swap `endpoints.py` from a remote URL at runtime without restarting the container. The file is syntax-checked with `ast.parse()` before being written.

---

## 🖥️ Web Dashboard

traffgen includes a built-in HTTPS monitoring dashboard on **port 7777**. No configuration is required — it starts automatically with the container.

### Accessing the dashboard

```bash
# Run with port 7777 exposed
docker run --pull=always --detach --restart unless-stopped \
  -p 7777:7777 jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop

# Open in browser (accept the self-signed certificate warning)
https://<host-ip>:7777
```

The dashboard uses a **self-signed TLS certificate** generated at container startup and stored in `/tmp/`. Your browser will show a certificate warning — this is expected and safe to proceed past for an internal monitoring tool.

### Dashboard tabs

| Tab | What it shows |
|---|---|
| **Overview** | Stat cards (total requests, success rate, active test, iteration), Network I/O sparkline (1s default, selectable interval), success/failure donut chart, requests-over-time sparkline, per-test breakdown table, live events feed |
| **Tests** | Card grid of every available suite with description, attempt/ok/fail counters, and a colour-coded success bar. Click any card to launch it immediately with custom settings. |
| **Output** | CLI-style live log mirroring terminal output — ✔/✗/⚠ level icons, section banners, and rule separators. Filterable by level (OK / Warn / Error / Debug). Auto-scroll, clear, and **Pop Out** into a standalone window. |
| **Health** | CPU/memory gauges, load average, disk I/O bars, network sparkline, and top-processes table sampled every 2 seconds. |

### Dark / Light Mode

Click the **☾** button in the topbar to switch between dark (default) and light themes. The preference is saved to `localStorage` and restored automatically.

### Changing settings from the dashboard

Click the **⚙ gear icon** in the sidebar or topbar to open the Settings drawer. From there you can change:

- **Suite** — which test suite to run (dropdown lists all available suites with descriptions)
- **Size** — traffic volume (`XS` → `XL`)
- **Max wait** — seconds between tests (5–300 s slider)
- **Loop mode** — run indefinitely vs. single pass
- **No wait** — disable all inter-test pauses

Click **Apply & Restart** to write the new settings. The generator detects the change at the next test boundary and restarts itself automatically — no container restart needed.

### Security design

The dashboard is **read-only by default** — no authentication is required because it exposes no sensitive data and accepts no dangerous input. The control endpoint (`POST /api/control`) validates all fields strictly against an allowlist before writing anything. All responses include security headers (`CSP`, `X-Frame-Options`, `HSTS`, etc.). The self-signed certificate ensures traffic between your browser and the container is encrypted.

> **Note:** If you do not want the dashboard exposed, simply omit the `-p 7777:7777` flag. The dashboard still runs inside the container (for potential future internal use) but is not reachable from outside.

---

## 🔨 Building & Publishing

The image publishes to Docker Hub as a multi-architecture manifest so `docker pull jdibby/traffgen:latest` automatically delivers the correct image for any supported host architecture.

### Prerequisites

```bash
# Enable BuildKit multi-arch support (once per host)
docker buildx create --name multi --driver docker-container --bootstrap --use
docker buildx inspect --bootstrap
```

### Build and push (all architectures)

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  --tag jdibby/traffgen:latest \
  --push .
```

### Tag a versioned release

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  --tag jdibby/traffgen:latest \
  --tag jdibby/traffgen:2.4.0 \
  --push .
```

### Verify the manifest

```bash
docker buildx imagetools inspect jdibby/traffgen:latest
```

---

## 🤝 Contributing

Issues and pull requests welcome at [github.com/jdibby/traffgen](https://github.com/jdibby/traffgen). When reporting a bug, include the output of `--version` and the `--suite` and `--size` flags used.
