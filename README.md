# 🚦 Traffgen

**Multi-protocol network traffic generator for security validation.**

[![Docker Hub](https://img.shields.io/docker/pulls/jdibby/traffgen?logo=docker&label=Docker%20Hub)](https://hub.docker.com/r/jdibby/traffgen)
[![Multi-arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64%20%7C%20arm%2Fv7-blue?logo=linux)](https://hub.docker.com/r/jdibby/traffgen)
[![Version](https://img.shields.io/badge/version-3.9.1-green)](https://github.com/jdibby/traffgen/blob/main/generator.py)

Trafgen simulates realistic network traffic across **53 test suites** — DNS, HTTP/S, FTP, SSH, BGP, ICMP, NTP, SNMP, DoH, DoT, VoIP/UCaaS, C2 beacons, DNS exfiltration, AI/LLM DLP, lateral movement, TLS inspection checks, WAF attacks, iperf3 bandwidth, and more.

Purpose-built to validate **firewalls**, **IDS/IPS**, **URL filters**, **DLP engines**, **CASB platforms**, and **SIEM pipelines**.

Runs as a Docker container with a built-in watchdog, per-test timeout guard, and healthcheck. Includes a live HTTPS monitoring dashboard on port 7777.

---

## ⚠ Disclaimer

This tool is intended for **authorized security testing and research in controlled lab environments only**. You are solely responsible for obtaining explicit written permission before testing any systems or networks. The author(s) accept **no liability** for misuse, unauthorized access, damage, or legal consequences arising from use of this tool.

---

## ⚡ Quick Start

```bash
# Run all suites in a continuous loop
docker run --pull=always --detach --restart unless-stopped \
  -p 7777:7777 --name traffgen jdibby/traffgen:latest \
  --suite=all --size=S --max-wait-secs=20 --loop

# Then open the dashboard
https://<host-ip>:7777
```

```bash
# Run a single suite once
docker run --pull=always -it jdibby/traffgen:latest --suite=nmap --size=L

# Print all available suites
docker run --pull=always -it jdibby/traffgen:latest --list
```

> **Docker Hub:** `jdibby/traffgen:latest` — multi-arch: `linux/amd64` · `linux/arm64` · `linux/arm/v7`

---

## 🤖 Automated Deployment

`stager.sh` installs Docker and starts the container on a fresh host. Supports Ubuntu, Debian, Rocky Linux, and Raspberry Pi 4/5.

```bash
curl -sk https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh | sudo bash
```

---

## 📚 Documentation

| Doc | What's in it |
|---|---|
| [Test Suites](docs/suites.md) | All 53 suites — what each tests, how to interpret results, outcome classification |
| [Deployment Guide](docs/deployment.md) | Docker commands, stager.sh, network modes, TLS proxy setup, architecture, building |
| [Configuration](docs/configuration.md) | CLI flags, `--size`, traffic pacing, custom endpoints |
| [Web Dashboard](docs/web-dashboard.md) | Dashboard tabs, controls, draggable widgets, chart hover, multi-user mode |

---

## 🤝 Contributing

Issues and pull requests welcome at [github.com/jdibby/traffgen](https://github.com/jdibby/traffgen). When reporting a bug, include the output of `--version` and the `--suite` and `--size` flags used.
