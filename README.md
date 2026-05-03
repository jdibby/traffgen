# Traffgen

**Multi-protocol network traffic generator for security validation.**

Traffgen simulates realistic network traffic across 46 test suites — DNS, HTTP/S, FTP, SSH, BGP, ICMP, NTP, SNMP, DoH, DoT, C2 beacons, DNS exfiltration, AI/LLM DLP, Metasploit checks, malware downloads, phishing probes, web scanning, and more. Purpose-built to stress-test firewalls, IDS/IPS systems, URL filters, DLP engines, CASB platforms, and SIEM pipelines.

Runs as a Docker container with a built-in watchdog, per-test timeout guard, and healthcheck to keep it generating traffic indefinitely without human intervention.

---

## Quick Start

```bash
# Print help and available suites
docker run --pull=always -it jdibby/traffgen:latest --help

# Run all suites in a continuous loop (background daemon)
docker run --pull=always --detach --restart unless-stopped \
  --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop

# Run all suites interactively
docker run --pull=always --restart unless-stopped -it \
  jdibby/traffgen:latest --suite=all --size=M --max-wait-secs=20 --loop

# Run a single suite once
docker run --pull=always -it jdibby/traffgen:latest --suite=nmap --size=L
```

**Docker Hub:** `jdibby/traffgen:latest` — multi-arch: `linux/amd64`, `linux/arm64`, `linux/arm/v7`

---

## Automated Deployment

`stager.sh` installs Docker and starts the container on a fresh host. Supports Ubuntu, Debian, Rocky Linux, and Raspberry Pi 4/5.

```bash
sudo bash < <(curl -s https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh)
```

---

## CLI Reference

| Flag | Values | Default | Description |
|---|---|---|---|
| `--suite` | See suite names below | `all` | Test suite to run |
| `--size` | `S` `M` `L` `XL` | `M` | Traffic volume / intensity |
| `--loop` | — | off | Loop forever, picking tests at random each iteration |
| `--max-wait-secs` | integer | `20` | Max random pause between iterations when looping |
| `--nowait` | — | off | Disable inter-test pauses when looping |
| `--crawl-start` | URL | `https://data.commoncrawl.org` | Seed URL for the `crawl` suite |
| `--list` | — | — | Print all suites with descriptions and exit |
| `--version` | — | — | Print version and exit |

---

## Test Suites

### Connectivity & Network Layer

#### `dns`
`dig` queries to multiple public DNS resolvers (Google, Cloudflare, Quad9, OpenDNS, and others) across a rotating set of domains. Exercises DNS inspection, DNS logging, and resolver-policy enforcement.

#### `icmp`
`ping` and `traceroute` to a set of well-known public hosts. Validates ICMP allow/deny policies and verifies that path-tracing generates the expected firewall events.

#### `bgp`
Starts a GoBGP daemon (AS 65555) and attempts peering sessions with configured BGP neighbors from `endpoints.py`. Tests BGP route-filter policies and monitors for rogue peering attempts.

#### `ntp`
NTP UDP/123 probes to a list of public time servers. Validates NTP allow policies and confirms that outbound time-sync traffic generates expected SIEM log entries.

#### `ssh`
Non-interactive SSH connection attempts to a list of hosts on TCP/22. Connections terminate immediately after the TCP handshake and key exchange — no credentials submitted. Validates SSH reachability and confirms SSH session logs appear in security tooling.

---

### Web & HTTP

#### `http`
HTTP HEAD requests to a broad set of plain-HTTP endpoints, followed by ZIP and tar.gz file downloads. Tests HTTP inspection, file-type enforcement, and download logging.

#### `https`
HTTPS HEAD requests to a wide endpoint pool followed by an iterative TLS crawl. Tests TLS inspection policy, certificate validation enforcement, and HTTPS download logging.

#### `crawl`
Iterative web crawl from a configurable seed URL (`--crawl-start`). Follows links up to a depth that scales with `--size`. Mimics a browser session for URL categorisation and user-activity analytics testing.

#### `url-response`
Measures HTTPS response times across a diverse URL set using the Python `requests` library. Populates URL-filter logs and response-time dashboards.

#### `bigfile`
Streams a 5 GB HTTP download to `/dev/null` for bandwidth saturation and QoS testing. Validates that large-file or bandwidth-cap policies trigger correctly and that flow records capture high-volume sessions.

#### `ftp`
FTP file download via `curl` with rate limiting against a public test server. Validates FTP inspection, logging, and file-transfer policy enforcement.

---

### Encrypted & Modern Protocols

#### `kyber`
HTTPS HEAD requests using the post-quantum **X25519MLKEM768** (Kyber) key exchange. Tests whether TLS inspection infrastructure handles hybrid post-quantum cipher suites without breaking connectivity.

#### `doh`
DNS over HTTPS (RFC 8484 JSON API) via `curl` to a rotating list of DoH providers. Tests DoH detection and DNS-over-HTTPS bypass policy enforcement.

#### `dot`
DNS over TLS on TCP/853 via `openssl s_client`. Tests whether DoT connections are logged, blocked, or decrypted by TLS inspection.

#### `http3`
HTTP/3 QUIC HEAD requests via `curl --http3`. QUIC runs over UDP/443 and is invisible to many legacy inspection stacks. Tests QUIC visibility, fallback behaviour, and QUIC-block policy enforcement.

---

### Security & Threat Intelligence

#### `ids-trigger`
Sends a HEAD request to `testmyids.com` with the `BlackSun` user-agent string — a classic Snort/Suricata IDS/IPS signature. Confirms that IDS alert rules are active and generating SIEM events.

#### `malware-agents`
HEAD requests to benign endpoints using known malware user-agent strings (Emotet, Cobalt Strike, AsyncRAT, and others). Tests whether user-agent-based IDS/IPS signatures fire for malware-associated UA patterns.

#### `malware-download`
Downloads known-malware file samples from public repositories to `/dev/null`. Tests whether anti-malware scanning or URL reputation filtering blocks downloads before they reach the endpoint.

#### `virus`
Downloads EICAR anti-virus test files and virus sample markers to `/dev/null`. Confirms that inline AV scanning is active and reporting correctly.

#### `domain-check`
Probes a random sample of domains from the **Hagezi DNS blocklist**. Tests whether DNS-based threat intelligence blocks known bad domains and generates expected SIEM events.

#### `phishing-domains`
Probes a random sample of domains from an active phishing domain feed. Tests anti-phishing DNS/URL filtering, confirms phishing-category blocks appear in firewall logs, and validates events reach the SIEM.

#### `squatting`
Runs `dnstwist` typosquatting generation against popular brand domains. Generates hundreds of lookalike domain variants (homoglyphs, additions, transpositions) and resolves them. Tests whether DNS analytics detect typosquatting lookups.

#### `nmap`
Nmap port scan covering ports 1–1024 against a target list, followed by an NSE CVE-script scan. Tests whether IDS/IPS detects and alerts on port-scan patterns and CVE-detection signatures.

#### `web-scanner`
Nikto web vulnerability scanner against `testmyids.com`. Generates a broad mix of vulnerability-probe HTTP requests (path traversal, header injection, known CVE probes). Scan duration scales with `--size`.

#### `metasploit-check`
Runs Metasploit `.rc` scripts in **check-only mode** — no exploitation is performed. Scripts issue the same probe traffic that Metasploit uses to fingerprint a target before exploit delivery, without sending any payload. Covers 46 check scripts across web apps, network appliances, databases, and protocol-level scanners. Tests IDS/IPS, CASB, and SIEM detection of Metasploit fingerprint traffic.

---

### Evasion & Advanced Techniques

#### `c2-beacon`
Simulates a C2 beacon: periodic HTTP POST requests using randomised malware user-agent strings with random jitter delay between beacons. The request body contains a base64-encoded pseudo-random session ID, mimicking the check-in pattern of common RAT families. Tests C2 beacon detection rules in SIEM and NDR platforms.

#### `dns-exfil`
Simulates DNS data exfiltration using base32-encoded subdomains in DNS TXT queries, mimicking traffic produced by `iodine` and `dnscat2`. Tests whether DNS analytics detect high-entropy subdomain patterns characteristic of DNS tunnelling.

#### `llm-dlp`
Simulates the real-world scenario of an employee pasting sensitive data into a public AI assistant. Runs two phases:

**Phase 1 — API POST simulation:** Generates unique blocks of format-valid but obviously fake PII (SSN, credit card, phone, passport, MRN, credentials) and POSTs them inside realistic chat-completion requests to randomly chosen LLM API endpoints. 25% of requests embed a **prompt injection / jailbreak pattern** to exercise AI-specific DLP rules. Supports the correct request format per provider:

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

**Security controls validated:**
- DLP rules for SSN, PCI-DSS card numbers, phone, passport, and credential patterns in outbound HTTPS POST bodies
- AI-category URL filtering for API hostnames and browser UIs
- Behavioural analytics detecting PII uploads to cloud AI services
- Prompt injection / jailbreak detection (Cato AI Security and equivalents)

---

### Content Filtering

#### `ads`
HEAD requests to advertising networks, analytics trackers, and telemetry endpoints. Tests ad-blocker and tracker-block URL filter categories.

#### `ai-browse`
HEAD requests to AI and LLM service endpoints (API gateways, model-serving hosts). Tests the AI-category URL filter independently from browser-facing chat UIs. Useful for testing API-level AI access policies.

#### `pornography`
HTTPS crawl of adult-content endpoints. Tests the adult-content URL filter category and confirms policy enforcement is logging correctly.

#### `dlp`
Downloads DLP test files over HTTPS containing structured PII and PCI data patterns (SSNs, credit card numbers, bank account numbers). Tests inline DLP file-scanning and download-inspection policies.

---

### Performance

#### `speedtest`
Runs a `fast.com` speed test via the `fastcli` Python package. Rounds scale with `--size`. Establishes baseline bandwidth and confirms speed-test traffic appears in application-awareness logs.

#### `snmp`
SNMPv2c `snmpwalk` queries against SNMP-enabled hosts using rotating community strings (`public`, `private`, and common defaults). Tests SNMP inspection and community-string detection.

---

### Meta

#### `all`
Runs every suite above in randomised order. This is the default when no `--suite` flag is provided.

---

## Traffic Volume

The `--size` flag scales test intensity across all suites:

| Size | Intended use |
|---|---|
| `S` | Long-running background daemons — low bandwidth impact |
| `M` | General-purpose testing (default) |
| `L` | Heavier load for firewall and IDS stress tests |
| `XL` | Maximum volume — capacity and saturation testing |

---

## Architecture

Three-stage multi-arch build (`linux/amd64`, `linux/arm64`, `linux/arm/v7`):

| Stage | Base image | Purpose |
|---|---|---|
| `gobgp-build` | `golang:1.23-bookworm` | Compiles GoBGP v3.36.0 with stripped binaries |
| `msf-build` | `debian:bookworm-slim` | Clones Metasploit, vendors gems, strips payloads and docs |
| runtime | `debian:bookworm-slim` | Slim runtime — only compiled binaries and vendored Metasploit |

**Watchdog:** A 300-second inactivity timer in `generator.py` force-exits the process when no test activity is detected. The container's `restart: unless-stopped` policy relaunches it immediately, providing self-healing for silent hangs.

**Per-test guard:** Every test runs in a daemon thread with a per-suite wall-clock limit (`_SUITE_TIMEOUTS`). If a test exceeds its limit the main loop advances to the next test rather than blocking — preventing any single stuck operation from halting traffic generation.

**Healthcheck:** `healthcheck.sh` uses `pgrep` to verify `generator.py` is running. Evaluated every 10 seconds with a 3-second timeout and 2 retries.

**Entrypoint:** `python3 -u /traffgen/generator.py` — default `CMD` is `--suite=all --size=S --max-wait-secs=40 --loop`.

---

## TLS Inspection Proxies

When a TLS-inspection proxy sits between the container and the internet it intercepts HTTPS connections and re-signs them with its own CA certificate. Tools that verify certificates — Ruby/Metasploit, `openssl s_client` (DoT tests), and Go — will reject these connections unless the proxy's CA is trusted.

The container handles this at startup via `docker-entrypoint.sh`, which calls `update-ca-certificates` before the generator runs. Two ways to inject your CA:

### Option 1 — Bind-mount a certificate file (recommended)

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

Both options can be combined, and multiple `.crt` files can be mounted simultaneously. The CA is installed into `/etc/ssl/certs/ca-certificates.crt` at container start — no image rebuild required when the certificate rotates.

> **Note:** `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE` are pre-configured in the image to point at the system CA bundle, so Python's `requests` library and `ssl` module automatically pick up any injected CA without code changes.

---

## Custom Endpoints

All network targets — DNS resolvers, URLs, user-agent strings, SNMP community strings, BGP neighbors, and more — are defined as plain Python lists in `endpoints.py`. The file is loaded at startup and kept separate from test logic so targets can be swapped without touching generator code.

To use a custom endpoints file, bind-mount it at container start:

```bash
docker run --pull=always -it \
  -v /path/to/my-endpoints.py:/traffgen/endpoints.py \
  jdibby/traffgen:latest --suite=all --loop
```

`generator.py` also exposes a `replace_all_endpoints(url)` function that can hot-swap `endpoints.py` from a remote URL at runtime without restarting the container. The file is syntax-checked with `ast.parse()` before being written.

---

## Building & Publishing

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

## Contributing

Issues and pull requests welcome at [github.com/jdibby/traffgen](https://github.com/jdibby/traffgen). When reporting a bug, include the output of `--version` and the `--suite` and `--size` flags used.
