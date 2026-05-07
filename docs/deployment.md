# Deployment Guide

## Quick Start

```bash
# Print help and list all available suites
docker run --pull=always -it jdibby/traffgen:latest --help

# Run all suites in a continuous loop (background daemon)
docker run --pull=always --detach --restart unless-stopped \
  --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop

# Run all suites interactively
docker run --pull=always -it \
  jdibby/traffgen:latest --suite=all --size=S --max-wait-secs=20 --loop

# Run a single suite once
docker run --pull=always -it jdibby/traffgen:latest --suite=nmap --size=L
```

> **Docker Hub:** `jdibby/traffgen:latest` — multi-arch: `linux/amd64` · `linux/arm64` · `linux/arm/v7`

---

## Running Without the Web Dashboard (Headless)

Use headless mode when you want minimal overhead, clean log output, or are running on a host where port 7777 is unavailable. There is no port mapping and no HTTPS server — traffgen runs and logs results to stdout/stderr only.

```bash
# Continuous loop — all suites, medium intensity, headless
docker run --pull=always --detach --restart unless-stopped \
  --name traffgen jdibby/traffgen:latest \
  --suite=all --size=M --max-wait-secs=20 --loop

# Run a single suite once, interactive (output in terminal)
docker run --pull=always -it jdibby/traffgen:latest --suite=dns --size=L

# Tail logs from a running headless container
docker logs -f traffgen
```

---

## Running With the Web Dashboard

The web dashboard runs on HTTPS port 7777. It provides live test status, security trend charts, network I/O, health stats, and controls to pause/stop/reconfigure tests without restarting the container.

### Standard — expose port 7777

Works on Linux, macOS, and Windows Docker Desktop. The `lateral-movement` suite is limited to the Docker bridge network.

```bash
docker run --pull=always --detach --restart unless-stopped \
  -p 7777:7777 --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop
```

Open `https://<host-ip>:7777` — accept the self-signed certificate warning on first visit.

### Host networking — full LAN access (Linux only)

`--network=host` shares the host's network namespace, giving the `lateral-movement` suite access to your physical LAN for realistic host discovery scans. The dashboard is available at port 7777 without an explicit mapping.

```bash
docker run --pull=always --detach --restart unless-stopped \
  --network=host --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop
```

> **Note:** `--network=host` does not work on Docker Desktop for Mac or Windows.

---

## Automated Deployment

`stager.sh` installs Docker (if needed), asks you a set of configuration questions, then starts the container on a fresh host.

**Configuration prompts** — stager.sh asks:

| Prompt | Options | Default |
|---|---|---|
| Suite to run | any suite name or `all` | `all` |
| Traffic intensity | `XS` `S` `M` `L` `XL` | `S` |
| Run in a loop | yes / no | yes |
| Max wait between tests | seconds | `20` |
| Enable web dashboard | yes / no | yes |
| Use host networking *(Linux only)* | yes / no | no |

Based on your answers, stager.sh builds and runs the appropriate `docker run` command.

**Supported platforms:**
- macOS 12 Monterey and later (requires [Homebrew](https://brew.sh))
- Ubuntu, Debian, Linux Mint, Pop!_OS
- Raspberry Pi 4/5 (Raspbian)
- Rocky Linux, AlmaLinux, CentOS Stream, RHEL, Fedora
- Amazon Linux 2 and 2023

**Linux** (requires sudo):
```bash
curl -sk https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh | sudo bash
```

**macOS** (do NOT use sudo — Homebrew cannot run as root):
```bash
curl -sk https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh | bash
```

On macOS, `stager.sh` installs Docker Desktop via `brew install --cask docker`, launches it, and waits for the daemon to be ready. Note that `--network=host` is not supported on macOS Docker Desktop, so the `lateral-movement` suite will be limited to the Docker bridge network.

`stager.sh` captures the host's LAN IP and subnet prefix before the container starts, injecting them as `HOST_LAN_CIDR` so the Network Info widget and `lateral-movement` suite use the real host IP instead of the Docker bridge address.

---

## Web Dashboard

Run with `--network=host` to expose the live HTTPS dashboard at `https://<host>:7777` and give the container full access to the host's physical network (required for `lateral-movement` scanning).

```bash
docker run --pull=always --detach --restart unless-stopped \
  --network=host --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop
```

Or expose just the port without `--network=host`:

```bash
docker run --pull=always --detach --restart unless-stopped \
  -p 7777:7777 --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop
```

> **Note:** `--network=host` is Linux-only. It does not work on Docker Desktop for Mac or Windows — use `-p 7777:7777` on those platforms, but `lateral-movement` will be limited to the Docker bridge network.

---

## Lateral Movement Networking

The `lateral-movement` suite scans the **host's physical LAN**, not the Docker bridge (`172.17.x.x`). A standard Docker container runs in its own network namespace and cannot see the host's physical interfaces. One of the two methods below is required.

### Method 1 — stager.sh (recommended)

`stager.sh` captures the host's LAN IP **and subnet prefix** with `hostname -I` and `ip addr` **before** the container starts and passes them as `-e HOST_LAN_CIDR=<ip>/<prefix>`. The suite reads this and scans the correct network:

| Host prefix | Scan target | Notes |
|---|---|---|
| `/24` | `x.x.x.0/24` | Normal LAN |
| `/25` – `/31` | Actual subnet | Smaller segment |
| `/32` | `x.x.x.0/24` | Microsegmentation detected — suite logs a warning and scans the containing /24 |
| `/8` – `/23` | `x.x.x.0/24` | Large subnet capped at /24 to keep scan time reasonable |

No extra flags needed — just use stager.sh.

### Method 2 — `--network=host`

Run the container with `--network=host` to share the host's network namespace. The container can then see and scan the host's physical interfaces directly.

```bash
docker run --pull=always --detach --restart unless-stopped \
  --network=host --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop
```

> **Note:** `--network=host` is Linux-only. It does not work on Docker Desktop for Mac or Windows.

If neither method is used, the suite logs a warning and falls back to scanning the container's own subnet (useful only for inter-container east-west testing).

---

## TLS Inspection Proxies

When a TLS-inspection proxy (Cato Networks, Prisma Access, Palo Alto, Zscaler, Netskope, etc.) sits between the container and the internet, it re-signs intercepted HTTPS connections with its own CA certificate. Tools that verify certificates — Ruby/Metasploit, `openssl s_client` (DoT tests), and Go — will reject those connections unless the proxy's CA is trusted.

`docker-entrypoint.sh` handles this at startup through three options applied in order.

### Option 3 — Fully automatic _(zero configuration)_

Just run the container — no flags, no cert files. On startup the entrypoint probes **15 diverse HTTPS hosts** in parallel spanning CDN providers, cloud platforms, developer tooling, OS vendors, and social platforms. For every host that fails TLS verification the entrypoint:

1. Fetches the full certificate chain the proxy is presenting (`openssl s_client -showcerts`)
2. Fingerprints (SHA-256) every `CA:TRUE` cert in the chain not yet in the system trust store
3. Votes across all failed hosts — the CA fingerprint seen on the most hosts wins
4. Saves the winning cert and runs `update-ca-certificates`
5. Runs a **verification pass** on a sample of previously-failed hosts to confirm the fix worked

```
[entrypoint] Probing 15 hosts to detect TLS interception...
[entrypoint] Results: 3 clean  11 intercepted  1 unreachable
[entrypoint] Selective bypass detected:
[entrypoint]   Bypassed (clean cert) : www.apple.com ocsp.pki.goog www.digicert.com
[entrypoint]   Intercepted           : www.google.com www.cloudflare.com github.com ...
[entrypoint] Proxy CA identified (seen on 11 of 11 intercepted host(s)):
[entrypoint]   Subject    : CN=Cato Networks Root CA, O=Cato Networks, C=IL
[entrypoint]   Expires    : Dec 31 23:59:59 2035 GMT
[entrypoint]   SHA-256 fp : 4A3B...
[entrypoint] Installing proxy CA into trust store...
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

Options 1 and 2 are installed first; the auto-probe (Option 3) runs after, so if a manually-supplied cert already covers the proxy the probe will see a clean chain and skip. All options can be combined, and multiple `.crt` files can be mounted simultaneously.

> `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE` are pre-configured in the image to point at the system CA bundle, so Python's `requests` library and `ssl` module automatically pick up any injected CA without code changes.

---

## Architecture

Three-stage multi-arch build (`linux/amd64`, `linux/arm64`, `linux/arm/v7`):

| Stage | Base Image | Purpose |
|---|---|---|
| `gobgp-build` | `golang:1.26-bookworm` | Compiles GoBGP with stripped binaries |
| `msf-build` | `jdibby/msf-base:latest` | Pre-built Metasploit base with vendored gems |
| runtime | `debian:bookworm-slim` | Slim runtime — only compiled binaries and vendored Metasploit |

**Watchdog:** A 600-second inactivity timer in `generator.py` force-exits the process when no test activity is detected. The container's `restart: unless-stopped` policy relaunches it immediately.

**Per-test guard:** Every test runs in a daemon thread with a per-suite wall-clock limit (`_SUITE_TIMEOUTS`). If a test exceeds its limit the main loop advances to the next test rather than blocking.

**Healthcheck:** `healthcheck.sh` uses `pgrep` to verify `generator.py` is running. Evaluated every 10 seconds with a 3-second timeout and 2 retries.

**Entrypoint:** `docker-entrypoint.sh` auto-detects TLS-inspection proxies, installs any injected CA certificates, then launches `python3 -u /traffgen/generator.py`. Default `CMD` is `--suite=all --size=S --max-wait-secs=20 --loop`.

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
  --tag jdibby/traffgen:3.0.0 \
  --push .
```

### Verify the manifest

```bash
docker buildx imagetools inspect jdibby/traffgen:latest
```
