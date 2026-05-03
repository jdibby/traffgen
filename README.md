# 🛡️ Traffgen — Containerised multi-protocol network traffic generator

Traffgen generates realistic network traffic across 34 test suites to stress-test firewalls, IDS/IPS systems, URL filters, and security analytics pipelines. It runs as a Docker container with a built-in watchdog, healthcheck, and configurable traffic volume.

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

| Suite | Description |
|---|---|
| `dns` | `dig` queries to multiple resolvers across a rotating set of domains. |
| `icmp` | `ping` and `traceroute` to a set of hosts; measures RTT and packet loss. |
| `bgp` | GoBGP peering session with configured neighbors (AS 65555). |
| `ntp` | NTP UDP/123 probes to public time servers. |
| `ssh` | Non-interactive SSH connection attempts to verify TCP/22 reachability. |

### Web / HTTP

| Suite | Description |
|---|---|
| `http` | HTTP HEAD requests plus ZIP and tar.gz file downloads. |
| `https` | HTTPS HEAD requests plus an iterative TLS crawl. |
| `crawl` | Iterative web crawl from a configurable seed URL. |
| `url-response` | Measures HTTPS response times across a diverse URL set. |
| `bigfile` | 5 GB HTTP download for bandwidth saturation testing. |
| `ftp` | FTP file download via curl with rate limiting. |

### Encrypted / Modern Protocols

| Suite | Description |
|---|---|
| `kyber` | HTTPS with post-quantum X25519MLKEM768 key exchange (PQ-TLS). |
| `doh` | DNS over HTTPS (RFC 8484 JSON API via curl). |
| `dot` | DNS over TLS (TCP/853) via `openssl s_client`. |
| `http3` | HTTP/3 QUIC HEAD requests via `curl --http3`. |

### Security / Threat Intelligence

| Suite | Description |
|---|---|
| `ips` | BlackSun user-agent IPS trigger to `testmyids.com`. |
| `malware-agents` | HEAD requests using known malware user-agent strings. |
| `malware-download` | Downloads known-malware file samples to `/dev/null`. |
| `virus` | Downloads EICAR and virus sample files to `/dev/null`. |
| `domain-check` | Probes random samples from the Hagezi DNS blocklist. |
| `phishing-domains` | Probes random samples from an active phishing domain list. |
| `squatting` | `dnstwist` typosquatting generation for popular domains. |
| `nmap` | Nmap port scan (ports 1–1024) plus NSE CVE script scan. |
| `web-scanner` | Nikto web vulnerability scan against `testmyids.com`. |
| `metasploit-check` | Runs Metasploit `.rc` check scripts in check-only mode (no exploitation). |

### Evasion and Advanced Techniques

| Suite | Description |
|---|---|
| `c2-beacon` | C2 beacon simulation: periodic HTTP POSTs with randomised jitter. |
| `dns-exfil` | DNS TXT exfiltration simulation: base32-encoded subdomains. |

### Content Filtering

| Suite | Description |
|---|---|
| `ads` | HEAD requests to ad-network and analytics endpoints. |
| `ai` | HEAD requests to AI/LLM service endpoints. |
| `pornography` | HTTPS crawl of adult-content endpoints for URL filter validation. |
| `dlp` | DLP test file downloads over HTTPS (simulated PII/PCI data patterns). |

### Performance

| Suite | Description |
|---|---|
| `netflix` | `fast.com` speed test via `fastcli`. |
| `snmp` | SNMPv2c walks with rotating community strings. |

### Meta

| Suite | Description |
|---|---|
| `all` | Runs every suite above in random order. This is the default. |

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

## Contributing

Issues and pull requests are welcome at [github.com/jdibby/traffgen](https://github.com/jdibby/traffgen). When reporting a bug, include the output of `--version` and the suite and size flags used.
