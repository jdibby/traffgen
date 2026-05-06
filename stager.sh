#!/bin/bash
# stager.sh — Installs Docker and starts the traffgen container on a fresh host.
# Supports: Ubuntu, Debian, Raspbian (Raspberry Pi 4/5), and Rocky Linux.
# Usage: sudo bash < <(curl -s https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh)

set -euo pipefail

# ── Privilege check ───────────────────────────────────────────────────────────
if [ "$(whoami)" != "root" ]; then
    echo "ERROR: This script must be run as root (or via sudo)."
    exit 1
fi

# ── Environment setup ─────────────────────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive   # suppress interactive apt prompts
export NEEDRESTART_MODE=a               # auto-restart services without asking

BOLD=$(tput bold 2>/dev/null || true)
NORMAL=$(tput sgr0 2>/dev/null || true)

# ── OS detection ──────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}### DETECTING OPERATING SYSTEM ###${NORMAL}"
echo ""

RPIVER=""
if [ -f /proc/device-tree/model ]; then
    # Extract the Raspberry Pi generation number (4 or 5) from the device tree
    RPIVER=$(grep -a "Raspberry" /proc/device-tree/model 2>/dev/null | awk '{print $3}' || true)
fi

UBUNTU=0; ROCKY=0; RASPBIAN=0; DEBIAN=0

if [ -f /etc/os-release ]; then
    UBUNTU=$(grep -c  'NAME="Ubuntu"'      /etc/os-release || true)
    ROCKY=$(grep  -ci 'NAME="Rocky Linux"' /etc/os-release || true)
    RASPBIAN=$(grep -c 'ID=raspbian'       /etc/os-release || true)
    DEBIAN=$(grep  -c '^ID=debian$'        /etc/os-release || true)
    # Raspbian ships with both ID=raspbian and ID_LIKE=debian; treat it as
    # Raspbian only so it gets the correct Docker repo below.
    [ "$RASPBIAN" -gt 0 ] && DEBIAN=0
fi

if   [ "$RASPBIAN" -gt 0 ]; then OS_LABEL="Raspbian"
elif [ "$DEBIAN"   -gt 0 ]; then OS_LABEL="Debian"
elif [ "$UBUNTU"   -gt 0 ]; then OS_LABEL="Ubuntu"
elif [ "$ROCKY"    -gt 0 ]; then OS_LABEL="Rocky Linux"
else
    echo "ERROR: Unsupported operating system. Exiting."
    exit 1
fi

echo "Detected: ${BOLD}${OS_LABEL}${NORMAL}"

# ── System update ─────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}### UPDATING SYSTEM PACKAGES ###${NORMAL}"
if [ "$ROCKY" -gt 0 ]; then
    dnf update -y && dnf upgrade -y
else
    apt-get update -y && apt-get upgrade -y && apt-get autoremove -y && apt-get clean -y
fi

# ── Remove any existing Docker installation ───────────────────────────────────
echo ""
echo "${BOLD}### REMOVING EXISTING DOCKER INSTALLATIONS AND CONTAINERS ###${NORMAL}"

if [ "$ROCKY" -gt 0 ]; then
    dnf remove -y docker-ce docker-ce-cli containerd.io 2>/dev/null || true
    rm -rf /var/lib/docker /var/lib/containerd
else
    # Stop and remove all running containers before removing packages
    docker stop  "$(docker ps -aq)" 2>/dev/null || true
    docker rm    "$(docker ps -aq)" 2>/dev/null || true
    docker images -q | xargs -r docker rmi -f    2>/dev/null || true

    for pkg in docker.io docker-doc docker-compose docker-compose-v2 \
               podman-docker containerd runc; do
        apt-get remove -y "$pkg" 2>/dev/null || true
    done
fi

# ── Install Docker ────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}### INSTALLING DOCKER ###${NORMAL}"

if [ "$ROCKY" -gt 0 ]; then
    # Rocky Linux uses the CentOS Docker repo
    dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
    dnf update -y
    dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
else
    # Debian-family: deduplicate APT sources, then install via the official Docker repo

    # Remove duplicate/blank/comment-only lines from all APT source files.
    # Processes /etc/apt/sources.list and every *.list in sources.list.d/.
    # Uses only awk — no third-party tools required.
    _cleanup_apt_sources() {
        local f
        local _dedup='
            /^[[:space:]]*$/  { next }
            /^[[:space:]]*#/  { next }
            !seen[$0]++
        '
        if [ -f /etc/apt/sources.list ]; then
            awk "$_dedup" /etc/apt/sources.list > /tmp/_apt_src_clean \
                && mv /tmp/_apt_src_clean /etc/apt/sources.list
        fi
        for f in /etc/apt/sources.list.d/*.list; do
            [ -f "$f" ] || continue
            awk "$_dedup" "$f" > /tmp/_apt_src_clean \
                && mv /tmp/_apt_src_clean "$f"
            [ -s "$f" ] || rm -f "$f"
        done
    }
    _cleanup_apt_sources

    # Install prerequisites for adding the Docker GPG key
    apt-get install -y ca-certificates curl gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings

    ARCH=$(dpkg --print-architecture)
    CODENAME=$(grep VERSION_CODENAME /etc/os-release | cut -d= -f2)

    # Select the correct Docker GPG key and repo URL for each distro variant
    if [ "$RASPBIAN" -gt 0 ] && [ "${RPIVER:-0}" -eq 5 ]; then
        # Raspberry Pi 5 runs a 64-bit Debian kernel — use the Debian repo
        DOCKER_GPG="https://download.docker.com/linux/debian/gpg"
        DOCKER_REPO="https://download.docker.com/linux/debian"
    elif [ "$RASPBIAN" -gt 0 ]; then
        # Raspberry Pi 4 (ARMv7) uses the dedicated Raspbian repo
        DOCKER_GPG="https://download.docker.com/linux/raspbian/gpg"
        DOCKER_REPO="https://download.docker.com/linux/raspbian"
    elif [ "$UBUNTU" -gt 0 ]; then
        DOCKER_GPG="https://download.docker.com/linux/ubuntu/gpg"
        DOCKER_REPO="https://download.docker.com/linux/ubuntu"
    else
        # Pure Debian
        DOCKER_GPG="https://download.docker.com/linux/debian/gpg"
        DOCKER_REPO="https://download.docker.com/linux/debian"
    fi

    curl -fsSL "$DOCKER_GPG" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] ${DOCKER_REPO} ${CODENAME} stable" \
        > /etc/apt/sources.list.d/docker.list

    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io \
                       docker-buildx-plugin docker-compose-plugin

    # Restart Docker and prune any leftover images/volumes from prior installs
    systemctl restart docker
    docker system prune -f
fi

echo ""
echo "${BOLD}### DOCKER INSTALLATION COMPLETE ###${NORMAL}"

# ── Start traffgen container ──────────────────────────────────────────────────
echo ""
echo "${BOLD}### STARTING TRAFFGEN CONTAINER ###${NORMAL}"
docker run \
    --pull=always \
    --detach \
    --restart unless-stopped \
    jdibby/traffgen:latest \
    --suite=all --size=XS --max-wait-secs=20 --loop

echo ""
echo "${BOLD}### INSTALL COMPLETE ###${NORMAL}"
echo ""
docker ps -a --format "table {{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}"
echo ""
