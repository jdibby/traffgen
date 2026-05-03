# Traffgen — Containerised multi-protocol network traffic generator

Traffgen generates realistic network traffic across 34 test suites to stress-test firewalls, IDS/IPS systems, URL filters, DLP engines, and security analytics pipelines. It runs as a Docker container with a built-in watchdog, healthcheck, and configurable traffic volume.

---

## Quick Start

Pull and print the help menu:

```bash
docker run --pull=always -it jdibby/traffgen:latest --help
```

Run all suites in a foreground loop with a 20-second random pause between iterations:

```bash
docker run --pull=always --restart unless-stopped -it \
  jdibby/traffgen:latest --suite=all --size=M --max-wait-secs=20 --loop
```

Run as a background daemon:

```bash
docker run --pull=always --detach --restart unless-stopped \
  --name traffgen jdibby/traffgen:latest --suite=all --size=S --max-wait-secs=20 --loop
```

Run a single suite once (no loop):

```bash
docker run --pull=always -it jdibby/traffgen:latest --suite=nmap --size=L
```

**Docker Hub:** `jdibby/traffgen:latest` (multi-arch: x86_64, ARM64, ARMv7)

---

## Automated Deployment

`stager.sh` installs Docker and starts the container on a fresh host. Supports Ubuntu, Rocky Linux, Debian, and Raspberry Pi 4/5.

```bash
sudo bash < <(curl -s https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh)
```

---

## CLI Reference

| Flag | Values | Default | Description |
|---|---|---|---|
| `--suite` | See suite names below | `all` | Test suite to run. |
| `--size` | `S` `M` `L` `XL` | `M` | Traffic volume / intensity. |
| `--loop` | — | off | Loop forever, picking tests at random each iteration. |
| `--max-wait-secs` | integer | `20` | Maximum random pause between iterations when looping. |
| `--nowait` | — | off | Disable inter-test pauses when looping. |
| `--crawl-start` | URL | `https://data.commoncrawl.org` | Seed URL for the `crawl` suite. |
| `--version` | — | — | Print version and exit. |
| `--list` | — | — | Print all suites with descriptions and exit. |

---

## Test Suite Reference

### Connectivity / Network Layer

#### `dns`
`dig` queries to multiple public DNS resolvers (Google, Cloudflare, Quad9, OpenDNS, and others) across a rotating set of domains. The query count scales with `--size`. Exercises DNS inspection, DNS logging, and resolver-policy enforcement.

#### `icmp`
`ping` and `traceroute` to a set of well-known public hosts. Measures RTT and packet loss. Validates ICMP allow/deny policies and verifies that path-tracing generates the expected firewall events.

#### `bgp`
Starts a GoBGP daemon (AS 65555) and attempts a peering session with configured BGP neighbors defined in `endpoints.py`. Useful for testing BGP route-filter policies and monitoring for rogue peering attempts.

#### `ntp`
NTP UDP/123 probes to a list of public time servers. Validates NTP allow policies and confirms that outbound time-sync traffic generates the expected log entries in SIEM or flow collectors.

#### `ssh`
Non-interactive SSH connection attempts to a list of hosts on TCP/22. Connections are terminated immediately after the TCP handshake and key exchange — no credentials are submitted. Validates SSH reachability and confirms that SSH session logs appear in security tooling.

---

### Web / HTTP

#### `http`
HTTP HEAD requests to a broad set of plain-HTTP endpoints, followed by ZIP and tar.gz file downloads. Tests HTTP (non-TLS) inspection, file-type enforcement, and download logging.

#### `https`
HTTPS HEAD requests to a wide set of HTTPS endpoints, followed by an iterative TLS crawl that follows links across pages. Tests TLS inspection policy, certificate validation enforcement, and HTTPS download logging.

#### `crawl`
Iterative web crawl starting from a configurable seed URL (`--crawl-start`). Follows links up to a depth and page count that scales with `--size`. Mimics a browser browsing session for testing URL categorisation, web filtering, and user-activity analytics.

#### `url-response`
Measures HTTPS response times across a diverse set of URLs using the Python `requests` library. Generates HTTPS traffic to domains spanning multiple URL categories to populate URL-filter logs and response-time dashboards.

#### `bigfile`
Streams a 5 GB HTTP download to `/dev/null` for bandwidth saturation and QoS testing. Useful for validating that large-file or bandwidth-cap policies trigger correctly and that flow records capture high-volume sessions accurately.

#### `ftp`
FTP file download via `curl` with rate limiting. Targets a public FTP test server. Validates FTP inspection, FTP logging, and file-transfer policy enforcement.

---

### Encrypted / Modern Protocols

#### `kyber`
HTTPS HEAD requests using the post-quantum **X25519MLKEM768** key exchange (also known as PQ-TLS or Kyber). Tests whether TLS inspection infrastructure can handle hybrid post-quantum cipher suites without breaking connectivity, and whether next-generation algorithm alerts fire correctly.

#### `doh`
DNS over HTTPS (RFC 8484 JSON API) queries via `curl` to a rotating list of DoH providers (Google, Cloudflare, NextDNS, and others). Tests whether DoH traffic is detected and whether DNS-over-HTTPS bypass policies are in effect.

#### `dot`
DNS over TLS on TCP/853 via `openssl s_client`. Establishes TLS connections to DoT resolvers and sends raw DNS wire-format queries. Tests whether DoT connections are logged, blocked, or decrypted by TLS inspection.

#### `http3`
HTTP/3 QUIC HEAD requests via `curl --http3`. QUIC runs over UDP/443 and is invisible to many legacy inspection stacks. Tests whether QUIC traffic is visible to the security platform, whether it falls back to HTTP/2, and whether QUIC-block policies are enforced.

---

### Security / Threat Intelligence

#### `ids-trigger`
Sends a HEAD request to `testmyids.com` using the `BlackSun` user-agent string, which matches a classic Snort/Suricata IDS/IPS signature. Confirms that IDS/IPS alert rules are active and generating events in the SIEM.

#### `malware-agents`
HEAD requests to a list of benign endpoints using known malware user-agent strings (Emotet, Cobalt Strike, AsyncRAT, and others). Tests whether user-agent-based IDS/IPS signatures fire for malware-associated UA patterns.

#### `malware-download`
Downloads known-malware file samples from public repositories to `/dev/null`. Files are identified by hash in threat intelligence feeds. Tests whether anti-malware scanning or URL reputation filtering blocks the downloads before they reach the endpoint.

#### `virus`
Downloads EICAR anti-virus test files and other virus sample markers to `/dev/null`. The EICAR string is the universal AV test pattern — every compliant AV engine must detect and block it. Confirms that inline AV scanning is active and reporting correctly.

#### `domain-check`
Probes a random sample of domains from the **Hagezi DNS blocklist**, one of the most comprehensive community-maintained DNS block lists. Tests whether DNS-based threat intelligence is blocking known bad domains and generating the expected SIEM events.

#### `phishing-domains`
Probes a random sample of domains from an active phishing domain feed. Tests whether anti-phishing DNS/URL filtering is in place, confirms that phishing-category blocks appear in firewall logs, and validates that phishing domain events reach the SIEM.

#### `squatting`
Runs `dnstwist` typosquatting generation against a list of popular brand domains. `dnstwist` generates hundreds of plausible lookalike domains (homoglyphs, additions, deletions, transpositions) and resolves them. Tests whether DNS analytics detect typosquatting lookups and whether security tooling flags lookalike-domain activity.

#### `nmap`
Nmap port scan covering ports 1–1024 against a list of targets, followed by an NSE CVE-script scan. The scan intensity scales with `--size`. Tests whether the IDS/IPS detects and alerts on port-scan patterns, and validates that CVE-detection signatures are firing.

#### `web-scanner`
Nikto web vulnerability scanner against `testmyids.com`. Nikto generates a broad mix of vulnerability-probe HTTP requests (path traversal, header injection, known CVE probes). Tests whether web-application IDS signatures fire for scanner activity. Scan duration scales with `--size`.

#### `metasploit-check`
Runs Metasploit `.rc` scripts in **check-only mode** — no exploitation is performed. The scripts issue the same probe traffic that Metasploit uses to fingerprint a target before deciding whether to launch an exploit, without delivering any payload. Tests whether IDS/IPS and SIEM detect Metasploit check-phase traffic. Scan duration scales with `--size`.

---

### Evasion and Advanced Techniques

#### `c2-beacon`
Simulates a C2 (command-and-control) beacon: periodic HTTP POST requests to a list of external hosts using randomised malware user-agent strings and a random jitter delay between beacons. The request body contains a base64-encoded pseudo-random session identifier, mimicking the check-in pattern used by many RAT families. Tests whether C2 beacon detection rules in the SIEM or NDR platform fire for this pattern.

#### `dns-exfil`
Simulates DNS data exfiltration using base32-encoded subdomains in DNS TXT queries, mimicking the traffic pattern produced by tools such as `iodine` and `dnscat2`. A random "payload" string is base32-encoded and split into 63-character DNS labels, then queried against a rotating list of exfiltration simulation domains. Tests whether DNS analytics detect high-entropy subdomain patterns or unusually long DNS queries that are characteristic of DNS tunnelling.

#### `llm-dlp`
Simulates the real-world scenario of an employee copy-pasting sensitive data into a public AI assistant. Each iteration runs two phases:

**Phase 1 — API POST simulation:** Generates a unique block of **format-valid but obviously fake PII** and POSTs it inside a realistic chat-completion request to a randomly chosen LLM API endpoint. PII types included:

- SSNs in the `9xx` range (permanently unassigned by the SSA)
- `555` phone numbers (reserved for fiction under the North American Numbering Plan)
- Well-known public Luhn-valid test card numbers (Visa `4111 1111 1111 1111`, Mastercard `5500 0000 0000 0004`, etc.)
- Test-prefix passport numbers (`TEST-P-…`) and driver's licence numbers (`TEST-DL-…`)
- Weak-pattern passwords and ABA routing number `999999999` (unassigned)

Requests include a 25% probability of embedding a **prompt injection / jailbreak pattern** (DAN, SYSTEM OVERRIDE, and similar) to test AI-specific DLP and jailbreak-detection rules. Supported API providers and their authentication formats:

| Provider | Auth scheme | Body format |
|---|---|---|
| OpenAI (GPT-4o, GPT-4-turbo, …) | `Authorization: Bearer sk-…` | `messages` array |
| Anthropic (Claude Opus/Sonnet/Haiku) | `x-api-key` + `anthropic-version` | `messages` array |
| Google (Gemini 2.0 Flash, 1.5 Pro, …) | `x-goog-api-key` | `contents/parts` |
| Cohere (Command-R+, Command-R) | `Authorization: Bearer …` | flat `message` field |
| Azure OpenAI | `api-key` header | `messages` array |
| Perplexity, Mistral, Groq, Together, Fireworks, xAI, DeepSeek, Meta, Cohere v2, OpenRouter, Bedrock, HuggingFace, and more | `Authorization: Bearer …` | `messages` array |

All requests use a fake `Bearer sk-DLPTEST-…` token. Responses are HTTP 401/403 — no real credentials are provided or required. The value is in the traffic, not the response.

**Phase 2 — Browser endpoint HEAD requests:** HEAD requests to 60+ browser-facing AI application URLs covering text/chat assistants (ChatGPT, Claude.ai, Gemini, Copilot, Perplexity, Grok, and others), code-generation tools (GitHub Copilot, Cursor, Codeium), image-generation services (Midjourney, Adobe Firefly, DALL-E), and enterprise AI platforms (Microsoft 365 Copilot, Google Workspace Gemini, Salesforce Einstein, AWS Bedrock, Azure AI).

Security controls validated by this suite:

- DLP rules for **SSN, PCI-DSS card numbers, phone, passport, credential patterns** in outbound HTTPS bodies
- **AI-category URL filtering** for known LLM API hostnames and browser UIs
- Behavioural analytics detecting **PII uploads to cloud AI services**
- API key / credential-in-request-body DLP signatures
- **Prompt injection / jailbreak detection** for AI-specific security policies

---

### Content Filtering

#### `ads`
HEAD requests to a broad list of advertising networks, analytics trackers, and telemetry endpoints. Tests ad-blocker and tracker-block URL filter categories, and validates that ad-network traffic appears in firewall category logs.

#### `ai-browse`
HEAD requests to AI and LLM service endpoints (API gateways, model-serving hosts). Tests the AI-category URL filter — distinct from `llm-dlp`, which targets the browser-facing chat UIs. Useful for testing AI access policies that block API-level access independently from browser access.

#### `pornography`
HTTPS crawl of adult-content endpoints. Tests the adult-content URL filter category and confirms that adult-site policy enforcement is logging correctly. All targets are well-known domains already present in every major URL filter database.

#### `dlp`
Downloads DLP test files over HTTPS. The files contain structured patterns mimicking PII and PCI data (SSNs, credit card numbers, bank account numbers) in formats commonly used in DLP product evaluation kits. Tests inline DLP file-scanning and download-inspection policies.

---

### Performance

#### `speedtest`
Runs a `fast.com` speed test via the `fastcli` Python package. The number of test rounds scales with `--size`. Each round has a 5-second timeout so a slow or blocked connection does not stall the suite. Useful for establishing baseline bandwidth and for confirming that speed-test traffic appears in application-awareness logs.

#### `snmp`
SNMPv2c `snmpwalk` queries against a list of SNMP-enabled devices using a rotating set of community strings (including `public`, `private`, and common defaults). Tests SNMP inspection, community-string detection, and network-device access logging.

---

### Meta

#### `all`
Runs every suite above in a randomised order. This is the default when no `--suite` flag is provided.

---

## Traffic Volume

The `--size` flag scales test intensity without changing which suites run:

| Size | Intended use |
|---|---|
| `S` | Long-running background daemons; low bandwidth impact. |
| `M` | General-purpose testing (default). |
| `L` | Heavier load for firewall and IDS stress tests. |
| `XL` | Maximum volume; suitable for capacity and saturation tests. |

The Nikto (`web-scanner`) and Metasploit (`metasploit-check`) suites use `--size` to adjust scan duration.

---

## Architecture

The image is built in three stages to minimise runtime image size:

| Stage | Base | Purpose |
|---|---|---|
| `gobgp-build` | `ubuntu:25.10` | Compiles GoBGP v3.36.0 (`gobgp` + `gobgpd`) with stripped binaries. |
| `msf-build` | `ubuntu:25.10` | Clones Metasploit, vendors gems without dev/test dependencies, strips payloads and documentation. |
| runtime | `ubuntu:25.10` | Copies only the compiled binaries and vendored Metasploit into a slim system image. |

**Watchdog:** A 600-second inactivity timer in `generator.py` forces a container restart if no test activity is detected, providing self-healing behaviour in long-running deployments.

**Healthcheck:** `healthcheck.sh` uses `pgrep` to verify `generator.py` is running. Evaluated every 10 seconds with a 3-second timeout (`--retries 2`).

**Entrypoint:** `python3 -u /traffgen/generator.py`; default `CMD` is `--suite=all --size=S --max-wait-secs=40 --loop`.

---

## Custom Endpoints

All network targets — DNS resolvers, URLs, user-agent strings, SNMP community strings, BGP neighbors, and more — are defined as plain Python lists in `endpoints.py`. The file is loaded at startup and is kept separate from test logic so targets can be modified without touching generator code.

To use a custom endpoints file, bind-mount a replacement at container start:

```bash
docker run --pull=always -it \
  -v /path/to/my-endpoints.py:/traffgen/endpoints.py \
  jdibby/traffgen:latest --suite=all --loop
```

`generator.py` also exposes a `replace_all_endpoints()` function that can hot-swap `endpoints.py` from a remote URL at runtime without restarting the container.

---

## Building and Publishing the Image

The image is published to Docker Hub as a multi-architecture manifest covering **linux/amd64**, **linux/arm64**, and **linux/arm/v7** so it runs natively on x86_64 servers, ARM64 (Raspberry Pi 5, Apple Silicon workers), and ARMv7 (Raspberry Pi 4).

### Prerequisites

```bash
# Enable BuildKit multi-arch support once per host
docker buildx create --name multi --driver docker-container --bootstrap --use
docker buildx inspect --bootstrap
```

### Build and push (all three architectures in one command)

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  --tag jdibby/traffgen:latest \
  --push \
  .
```

This pushes a combined manifest to Docker Hub. Clients that `docker pull jdibby/traffgen:latest` automatically receive the image that matches their host architecture.

### Tag a versioned release alongside `latest`

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  --tag jdibby/traffgen:latest \
  --tag jdibby/traffgen:2.4.0 \
  --push \
  .
```

### Verify the manifest

```bash
docker buildx imagetools inspect jdibby/traffgen:latest
```

---

## Contributing

Issues and pull requests are welcome at [github.com/jdibby/traffgen](https://github.com/jdibby/traffgen). When reporting a bug, include the output of `--version` and the suite and size flags used.
