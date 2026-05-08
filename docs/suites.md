# Test Suites

Traffgen ships **52 test suites** covering every major protocol and security control category. Use `--suite=<name>` to run a specific suite, or `--suite=all` to run every suite in shuffled order.

```bash
docker run --pull=always -it jdibby/traffgen:latest --list
```

---

## 🌐 Connectivity & Network Layer

| Suite | Description |
|---|---|
| 🔍 `dns` | `dig` queries to multiple public DNS resolvers (Google, Cloudflare, Quad9, OpenDNS, and others) across a rotating set of domains. Exercises DNS inspection, logging, and resolver-policy enforcement. |
| 📡 `icmp` | `ping` and `traceroute` to a set of well-known public hosts. Validates ICMP allow/deny policies and verifies that path-tracing generates the expected firewall events. |
| 🌐 `bgp` | Starts a GoBGP daemon (AS 65555) and attempts peering sessions with configured BGP neighbors from `endpoints.py`. Tests BGP route-filter policies and monitors for rogue peering attempts. |
| 🕐 `ntp` | NTP UDP/123 probes to a list of public time servers. Validates NTP allow policies and confirms that outbound time-sync traffic generates expected SIEM log entries. |
| 💻 `ssh` | Non-interactive SSH connection attempts to a list of hosts on TCP/22. Connections terminate immediately after key exchange — no credentials submitted. Validates SSH reachability and confirms session logs appear in security tooling. |

---

## 🌍 Web & HTTP

| Suite | Description |
|---|---|
| 🌍 `http` | HTTP HEAD requests to a broad set of plain-HTTP endpoints, followed by ZIP and tar.gz file downloads. Tests HTTP inspection, file-type enforcement, and download logging. |
| 🛡️ `https` | HTTPS HEAD requests to a wide endpoint pool followed by an iterative TLS crawl. Tests TLS inspection policy, certificate validation enforcement, and HTTPS download logging. |
| 🕷️ `crawl` | Iterative web crawl from a configurable seed URL (`--crawl-start`). Follows links up to a depth that scales with `--size`. Mimics a browser session for URL categorisation and user-activity analytics testing. |
| ⏱️ `url-response` | Measures HTTPS response times across a diverse URL set using the Python `requests` library. Populates URL-filter logs and response-time dashboards. |
| 🪣 `s3` | Simulates S3 bucket upload and download traffic. GET requests target a mix of public AWS datasets and private-style bucket paths (200 or 403 — both generate CASB-visible S3 traffic). PUT requests upload small synthetic payloads containing PII, credentials, and confidential strings to S3 paths — requests return 403 (no credentials) but are fully visible to DLP and CASB engines as cloud-upload/exfiltration attempts. Also targets Wasabi and Backblaze B2 S3-compatible endpoints. |
| 💾 `bigfile` | Streams an HTTP download to `/dev/null` — file size scales with `--size` (XS=10 MB, S=100 MB, M=1 GB, L=2 GB, XL=5 GB). Tests large-file and bandwidth-cap policies across the full volume range without always hitting the ceiling. |
| 📁 `ftp` | FTP file download via `curl` with rate limiting against a public test server. Validates FTP inspection, logging, and file-transfer policy enforcement. |

---

## 🔐 Encrypted & Modern Protocols

| Suite | Description |
|---|---|
| 🔮 `kyber` | HTTPS HEAD requests using the post-quantum **X25519MLKEM768** (Kyber) key exchange. Tests whether TLS inspection infrastructure handles hybrid post-quantum cipher suites without breaking connectivity. |
| 🔐 `doh` | DNS over HTTPS (RFC 8484 JSON API) via `curl` to a rotating list of DoH providers. Tests DoH detection and DNS-over-HTTPS bypass policy enforcement. |
| 🔑 `dot` | DNS over TLS on TCP/853 via `openssl s_client`. Tests whether DoT connections are logged, blocked, or decrypted by TLS inspection. |
| ⚡ `http3` | HTTP/3 QUIC HEAD requests via a native `aioquic` implementation (`QuicConnectionProtocol` + `H3Connection`). QUIC runs over UDP/443 and is invisible to many legacy inspection stacks. Tests QUIC visibility and QUIC-block policy enforcement without relying on a curl build that supports HTTP/3. |

---

## 🛡️ Security & Threat Simulation

| Suite | Description |
|---|---|
| 🚨 `ids-trigger` | Fires a battery of **16 HTTP requests** targeting `testmyids.com` — the Emerging Threats IDS validation service — each matching a distinct Snort/Suricata signature category: **10 scanner user-agents** (BlackSun, ZmEu, Havij, sqlmap, Nikto, Acunetix, w3af, masscan, DirBuster, libwww-perl) and **6 web-attack URL probes** (LFI `../../etc/passwd`, SQLi `UNION SELECT`, XSS `<script>`, `.env` disclosure, wp-admin, cmd-injection). Tests inline IDS/IPS (Snort, Suricata, Cisco FTD, Palo Alto NGFW with IPS rules) signature coverage across multiple rule categories. |
| 👾 `malware-agents` | HEAD requests to malware-category test URLs using **known C2 framework user-agents**. Destinations include WICAR, AMTSO, and Google Safe Browsing test URLs. UAs cover Cobalt Strike, Metasploit Meterpreter, PowerShell Empire, Sliver, DarkComet RAT, QuasarRAT, Emotet/TrickBot, AgentTesla, njRAT, python-requests, Go-http-client, Java RATs, curl, and PowerShell Invoke-WebRequest. Exercises both URL-category blocking and C2 UA behavioral detection independently. |
| 🦠 `malware-download` | Downloads known-malware file samples from public repositories to `/dev/null`. Tests whether anti-malware scanning or URL reputation filtering blocks downloads before they reach the endpoint. |
| ☣️ `virus` | Downloads EICAR anti-virus test files and virus sample markers to `/dev/null`. Confirms that inline AV scanning is active and reporting correctly. |
| 🚫 `domain-check` | Probes a random sample of domains from the **Hagezi DNS blocklist**. Tests whether DNS-based threat intelligence blocks known bad domains and generates expected SIEM events. |
| 🎣 `phishing-domains` | Probes a random sample of domains from an active phishing domain feed. Tests anti-phishing DNS/URL filtering, confirms phishing-category blocks appear in firewall logs, and validates events reach the SIEM. |
| 🔤 `squatting` | Runs `dnstwist` typosquatting generation against popular brand domains. Generates hundreds of lookalike domain variants (homoglyphs, additions, transpositions) and resolves them. Tests whether DNS analytics detect typosquatting lookups. |
| 🗺️ `nmap` | Nmap port scan covering ports 1–1024 against a target list, followed by an NSE CVE-script scan (`--script=ALL`). Targets are restricted to explicitly authorized public hosts: `scanme.nmap.org`, `testmyids.com`, and `juice-shop.herokuapp.com`. Tests whether IDS/IPS detects and alerts on port-scan patterns and CVE-detection signatures. |
| 🔬 `web-scanner` | Nikto web vulnerability scanner against `testmyids.com`. Generates a broad mix of vulnerability-probe HTTP requests (path traversal, header injection, known CVE probes). Scan duration scales with `--size`. |
| 📡 `msf-appliance` | Metasploit **check-mode probes for network security appliances**: Cisco IOS XE WebUI privilege escalation (CVE-2023-20198/20273, CISA KEV), Palo Alto PAN-OS GlobalProtect RCE (CVE-2024-3400, CVSS 10.0), Juniper SRX/EX J-Web RCE chain (CVE-2023-36844), Fortinet FortiOS SSL VPN heap overflow (CVE-2023-27997), Ivanti Connect Secure command injection, and F5 BIG-IP TMUI RCE (CVE-2020-5902). All run in `check` mode only — no exploitation. Generates the appliance-targeted probe patterns that NGFW/NDR and IDS vendors specifically signature-match. |
| 🔭 `msf-aux-scan` | Metasploit **auxiliary vulnerability scanners** against live LAN hosts only. Two-phase: ping sweep to discover live hosts, then runs MSF auxiliary modules (EternalBlue/MS17-010, BlueKeep/CVE-2019-0708, Heartbleed, Shellshock, Log4Shell scanner, SMB share enumeration, RDP detection) against confirmed-live hosts only. No blind subnet scanning — every target was first confirmed alive. Respects `--lateral-networks` filter. Tests IDS/IPS detection of MSF scanner traffic and validates whether your NGFW/NDR fires on these high-signal CVE probe patterns. |
| 🚨 `msf-cisa-kev` | Metasploit **check-mode probes for CISA Known Exploited Vulnerabilities**: Log4Shell HTTP header injection (CVE-2021-44228, CVSS 10.0), Fortra GoAnywhere MFT pre-auth RCE (CVE-2024-0204), MOVEit Transfer SQL injection (CVE-2023-34362), Barracuda ESG pre-auth RCE (CVE-2023-2868, linked to UNC4841), SolarWinds Web Help Desk deserialization (CVE-2024-28986), and Check Point SSL VPN arbitrary file read (CVE-2024-24919). All confirmed actively exploited in the wild — highest-priority IDS/IPS validation target. |
| 🔑 `msf-cred-spray` | Metasploit **credential-testing auxiliary modules** (SSH, FTP, SMB, HTTP Basic-Auth, Telnet) with fake credentials against `scanme.nmap.org` and `testmyids.com` only — never LAN hosts, to avoid account lockout on production systems. Generates protocol-level brute-force traffic that UEBA, SIEM, and identity-security platforms signature-match. Complements the `credential-spray` suite's HTTP API-only traffic with lower-level protocol auth attempts. |
| 🏢 `msf-enterprise` | Metasploit **check-mode probes for enterprise software**: Microsoft Exchange ProxyShell (CVE-2021-34473/34523/31207) and ProxyLogon (CVE-2021-26855), Atlassian Confluence Namespace OGNL injection (CVE-2023-22527), Atlassian Crowd Java deserialization (CVE-2019-11580), ManageEngine ADSelfService Plus unauthenticated SAML RCE (CVE-2022-47966), SAP WebDynpro deserialization (CVE-2020-6287, CVSS 10.0), and SaltStack Salt API command execution (CVE-2021-25281). |
| ⚙️ `msf-middleware` | Metasploit **check-mode probes for application servers and middleware**: Apache Struts2 REST XStream deserialization (CVE-2017-9805 S2-052) and Content-Type OGNL injection (CVE-2017-5638 S2-045), Oracle WebLogic T3 deserialization (CVE-2019-2725), JBoss unauthenticated deployment, Apache OFBiz deserialization (CVE-2021-26295), Spring Cloud Function SpEL injection (CVE-2022-22963), Jenkins Script Console RCE, and Apache Solr Velocity template RCE (CVE-2019-17558). |
| 📦 `msf-payload-delivery` | Uses **msfvenom** to generate encoded shellcode payloads with multiple encoders (`x86/shikata_ga_nai`, `x64/xor_dynamic`, `cmd/powershell_base64`, `x86/countdown`) and delivers them over HTTP POST to `scanme.nmap.org` and `testmyids.com`. The payloads are never executed — there is no listener. The encoded bytes cross the wire and test whether NGFW/SASE **deep-packet inspection** and IDS/IPS detect obfuscated malware payload patterns in transit. |
| 🔭 `msf-recon` | Metasploit **auxiliary recon scanners** that generate tier-1 IDS/IPS fingerprinting traffic: EternalBlue (MS17-010) probe, SMB share enumeration, RDP service detection, MySQL version banner, Redis unauthenticated access probe, HTTP server version banner grab, robots.txt fetch, and SSH version scanner. Output parsed per-module — connection outcomes classified as allowed (reached), drop (refused/timeout), or fail (module error). |
| 🌐 `msf-webapp` | Metasploit **check-mode probes for web application CVEs**: Drupal Drupalgeddon2 (CVE-2018-7600) and Drupalgeddon3 (CVE-2018-7602), Joomla HTTP header RCE (CVE-2015-8562), WordPress RevSlider arbitrary file upload, GitLab arbitrary file read via ExifTool injection (CVE-2021-22205), PHP CGI argument injection (CVE-2024-4577/CVE-2012-1823), Magento Shoplift SQL injection (CVE-2015-1397), and Webmin Package Update RCE (CVE-2019-12840). |
| 💥 `log4shell` | Injects **Log4Shell (CVE-2021-44228) JNDI payloads** into six HTTP request headers using LDAP, RMI, DNS, and obfuscated `${lower:}` / `${::-}` bypass variants. Targets testmyids.com and OWASP Juice Shop. Triggers Suricata SID 2034907/2034908 (ET EXPLOIT Log4j) and WAF header-injection rules. |
| 🛑 `waf-attack` | Sends **18 WAF-targeting attack payloads** in URL query parameters and POST bodies: SQLi (union/error/blind/sleep), XSS (script/img/svg), LFI (path traversal), SSRF (AWS metadata + localhost), OS command injection (semicolon/pipe/backtick), XXE (external entity), and SSTI (Jinja2/Twig). |
| 🧅 `tor-anonymizer` | HEAD requests to 16 **Tor Project, commercial VPN landing pages, and web-proxy sites** (check.torproject.org, ProtonVPN, NordVPN, Mullvad, ExpressVPN, kproxy.com, hide.me, croxyproxy.com, etc.). Tests the "anonymizers / proxy avoidance" URL-filter category on NGFW and SASE platforms. |
| 👥 `shadow-it` | HEAD requests to **27 unsanctioned cloud applications** across five CASB app-control categories: personal file sharing (Dropbox, Box, MEGA, WeTransfer, iCloud), personal messaging (Discord, Telegram, WhatsApp Web), privacy mail (ProtonMail, Tutanota), paste/file hosting (Pastebin, Filebin, GoFile), and crypto/blockchain (Coinbase, Etherscan, Binance). |
| 📞 `voip` | Two-phase **VoIP/WebRTC signaling simulation**. Phase 1: STUN Binding Requests (UDP/3478 + UDP/19302) to 15 public STUN servers used by Zoom, Google Meet, Teams, and open-source SIP stacks. Phase 2: SIP OPTIONS probes (UDP/5060) to 12 public SIP registrars — the standard SIP "ping" that triggers "SIP-signaling" app-ID signatures. No real calls placed. |
| 🎥 `ucaas` | HEAD requests to **30+ UCaaS signaling URLs** across 10 platforms: Zoom, Microsoft Teams, Cisco WebEx, Google Meet, Slack, RingCentral, 8x8, GoTo Meeting, Discord (voice channels), WhatsApp, Apple FaceTime, Vonage, Twilio, and Jitsi. Validates UCaaS/video-conferencing app-ID categories on Palo Alto, Cato, Zscaler, and Prisma Access. |
| 📬 `data-exfil-http` | POSTs **synthetic PII and credential payloads** to public paste and file-drop services. Payload types: SSN lists, Luhn-valid card numbers, RSA private key blocks, password hashes, and CSV PII. Tests DLP outbound content-inspection and CASB upload policies — destinations return 4xx but the outbound POST bodies are visible to inline inspection. |
| 🔏 `tls-check` | Connects to **20 diverse HTTPS endpoints** and reports the presented TLS certificate for each. Classifies each host as **CLEAN**, **INTERCEPTED** (issuer matches a known SASE/SSE/proxy vendor CA), **UNVERIFIED** (proxy re-signing without a trusted CA installed), or **UNREACHABLE**. Also detects selective bypass: if finance/government hosts are CLEAN while social/developer hosts are INTERCEPTED, the proxy has category or ASN bypass rules active. |
| 🕵️ `lateral-movement` | Two-phase east-west reconnaissance against **all physical networks** the Docker host is connected to. Designed to validate **micro-segmentation implementations** — confirms that east-west firewall policy, network ACLs, and host-based controls block lateral movement between segments as intended. When the host has multiple NICs or is multi-homed, all subnets are scanned simultaneously. Phase 1: nmap `-sn` ping sweep of each subnet to enumerate live hosts. Phase 2: port scan every discovered host on 12 lateral-movement ports: SSH (22), Kerberos (88), WMI/RPC (135), NetBIOS (137-139), LDAP (389), SMB (445), LDAPS (636), RDP (3389), WinRM HTTP/HTTPS (5985/5986). See [Deployment Guide](deployment.md#lateral-movement-networking) for required network setup. |

---

## 📡 Evasion & Advanced Techniques

#### `c2-beacon`
Simulates a C2 beacon: periodic HTTP POST requests using **known C2 framework user-agent strings** (Cobalt Strike, Meterpreter, Empire, DarkComet, etc.) with random jitter delay between beacons. The request body contains a base64-encoded pseudo-random session ID, mimicking the check-in pattern of common RAT families. Tests C2 beacon detection rules end-to-end on SASE behavioral analysis, NDR platforms, and SIEM.

#### `dns-exfil`
Simulates DNS data exfiltration using base32-encoded subdomains in DNS TXT queries, mimicking traffic produced by `iodine` and `dnscat2`. Tests whether DNS analytics detect high-entropy subdomain patterns characteristic of DNS tunnelling.

#### `llm-dlp`
Simulates an employee pasting sensitive data into a public AI assistant. Two phases:

**Phase 1 — API POST simulation:** Generates unique blocks of format-valid but fake PII (SSN, credit card, phone, passport, MRN, credentials) and POSTs them inside realistic chat-completion requests to randomly chosen LLM API endpoints. 25% of requests embed a **prompt injection / jailbreak pattern** to exercise AI-specific DLP rules.

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

**Phase 2 — Browser UI HEAD requests:** HEAD requests to 60+ browser-facing AI application URLs: text/chat assistants (ChatGPT, Claude.ai, Gemini, Copilot, Perplexity, Grok), code-generation tools (GitHub Copilot, Cursor, Codeium), image-generation services (Midjourney, Adobe Firefly, DALL-E), and enterprise AI platforms (Microsoft 365 Copilot, Google Workspace Gemini, AWS Bedrock, Azure AI).

**Security controls validated:**
- DLP rules for SSN, PCI-DSS card numbers, phone, passport, and credential patterns in outbound HTTPS POST bodies
- AI-category URL filtering for API hostnames and browser UIs
- Behavioural analytics detecting PII uploads to cloud AI services
- Prompt injection / jailbreak detection (AI security and CASB platforms)

---

## 🚧 Content Filtering

| Suite | Description |
|---|---|
| 🎯 `ads` | HEAD requests to a random sample of domains from the [Hagezi pro blocklist](https://github.com/hagezi/dns-blocklists) (300k+ ad, tracker, telemetry, and malware domains). The list is fetched at first run and cached for the process lifetime. Tests ad-blocker and tracker-block URL filter categories at scale. |
| 🤖 `ai-browse` | HEAD requests to AI and LLM service endpoints (API gateways, model-serving hosts). Tests the AI-category URL filter independently from browser-facing chat UIs. |
| 🔞 `pornography` | HTTPS crawl of adult-content endpoints. Tests the adult-content URL filter category and confirms policy enforcement is logging correctly. |
| 🔒 `dlp` | Downloads DLP test files over HTTPS containing structured PII and PCI data patterns (SSNs, credit card numbers, bank account numbers). Tests inline DLP file-scanning and download-inspection policies. |

---

## 📊 Performance

| Suite | Description |
|---|---|
| 🚀 `speedtest` | Runs a `fast.com` speed test via the `fastcli` Python package. Rounds scale with `--size`. Establishes baseline bandwidth and confirms speed-test traffic appears in application-awareness logs. |
| 📊 `snmp` | Three-function suite covering all SNMP versions: **SNMPv1** (18 community strings), **SNMPv2c** (26 community strings), and **SNMPv3** (20 credential sets across noAuthNoPriv, authNoPriv MD5/SHA, and authPriv DES/AES). Tests SNMP inspection, community-string detection, and SNMPv3 weak-credential signatures. |

---

## ✨ `all`

Runs every suite above in randomised order. This is the default when no `--suite` flag is provided. Each iteration shuffles a full deck of suites — every test runs once per round before any test repeats.

---

## 📊 Suite Summary

After every suite completes, traffgen prints a **Suite Summary** panel to the CLI:

```
╭──── Suite Summary ─────────────────────────────────╮
│  suite       https-random                          │
│  elapsed     14.2s                                 │
│  attempted   20                                    │
│  allowed      12                                   │
│  blocked       5                                   │
│  dropped       2                                   │
│  errors        1                                   │
│  http codes  2xx=12  4xx=5                         │
╰────────────────────────────────────────────────────╯
```

### Field Reference

| Field | What it means |
|---|---|
| **suite** | Suite name that just ran |
| **elapsed** | Wall-clock time to complete |
| **attempted** | Total individual probes sent (requests, queries, pings, etc.) |
| **allowed** | Probes that reached the destination without interception |
| **blocked** | Probes explicitly intercepted — HTTP 403/407/451/511 block page, TCP RST (curl exit 7), proxy refused (exit 5), or TLS intercept (exit 35) |
| **dropped** | Probes with no response — silent-drop firewall rule (timeout, exit 28) or DNS sinkhole (exit 6) |
| **errors** | Genuine infrastructure failures — DNS resolution error, unexpected exception |
| **http codes** | HTTP status code family breakdown for HTTP-based suites |

### Outcome Classification

Every probe maps to one of three security-relevant outcomes:

| Outcome | Signal | What it means |
|:---:|:---:|---|
| ✅ **Allowed** | 2xx, 3xx, non-block 4xx/5xx | Traffic reached its destination — security control did not intervene |
| 🟡 **Blocked** | HTTP 403/407/451/511 · TCP RST · Proxy refused | A security control explicitly intercepted the traffic |
| 🟣 **Dropped** | Timeout · DNS NXDOMAIN | Traffic was silently dropped — firewall drop rule, DNS sinkhole, or no route |

**Blocked vs. Dropped:** Blocked means your control is active and returning a signal (block page, RST) — users see an error, logs show the block, SIEM gets an event. Dropped means the traffic disappears silently — effective at stopping the threat but harder to audit.

### Interpreting Results

| Pattern | What to check |
|---|---|
| High `allowed` on `malware-download`, `virus`, `dlp`, `pornography` | Those categories are passing through uninspected |
| High `blocked` on `llm-dlp`, `c2-beacon`, `malware-agents` | Proxy/CASB is actively blocking — controls are working |
| High `dropped` on any suite | Firewall has drop (not reject) rules — effective but produces no user-visible feedback |
| High `errors` on `dns`, `ntp`, `icmp` | Those protocols may be perimeter-blocked (UDP/53, UDP/123, ICMP) |
| Mix of `blocked` and `dropped` on same suite | Layered security stack (NGFW + SASE) with both block-and-log and drop rules |

> **Non-HTTP suites** (`dns`, `ping`, `traceroute`, `ssh`, `ntp`, `snmp`, `nmap`, `msf-recon`, etc.) show `allowed`, `dropped`, and `errors` — no HTTP code breakdown. `allowed` means the probe ran to completion; `dropped` means connection refused/timeout (firewall block); `error` means the subprocess timed out or the host was unreachable.
