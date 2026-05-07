#!/bin/bash
# stager.sh — Installs Docker and starts the traffgen container.
#
# Idempotent: skips Docker install if already running, skips container
# start if already running under the name "traffgen".
#
# Supported distros:
#   Debian family : Ubuntu, Debian, Linux Mint, Pop!_OS
#   Raspberry Pi  : Raspbian (Pi 4 ARMv7 / Pi 5 arm64)
#   RHEL family   : Rocky Linux, AlmaLinux, CentOS Stream, RHEL, Fedora
#   Amazon Linux  : Amazon Linux 2 and Amazon Linux 2023
#
# Usage:
#   curl -sk https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh | sudo bash

set -euo pipefail

# ── Warning banner ────────────────────────────────────────────────────────────
cat <<'BANNER'

================================================================================
            TRAFFGEN STAGER -- SYSTEM CHANGES WARNING
================================================================================

  This script will make the following changes to your system:

    1. apt update        - refresh package index
    2. apt upgrade       - upgrade ALL installed packages
    3. Install deps      - ca-certificates, curl, gnupg, lsb-release
    4. Install Docker CE - docker-ce, docker-ce-cli, containerd.io,
                           docker-buildx-plugin, docker-compose-plugin
    5. Enable Docker     - systemctl enable --now docker
    6. Remove containers - stop and remove ALL existing Docker containers
    7. Prune images      - delete ALL Docker images, volumes, build cache
    8. Pull image        - jdibby/traffgen:latest from Docker Hub
    9. Start container   - port 7777, restart unless-stopped

  NOTE: Steps 6 & 7 will permanently DELETE all existing containers and
  images on this host. Run on a dedicated machine, or review the script
  at https://github.com/jdibby/traffgen/blob/main/stager.sh before use.

--------------------------------------------------------------------------------

  DISCLAIMER: For AUTHORIZED SECURITY TESTING AND RESEARCH only.
  You are solely responsible for obtaining explicit written permission
  before testing any systems or networks. The author(s) accept NO
  liability for misuse, unauthorized access, damage, or data loss.

================================================================================
BANNER

# Read acceptance — works both interactively and when piped via curl | bash
printf '\nDo you accept these terms and wish to continue? [y/N] '
if [ -t 0 ]; then
    read -r _ACCEPT
else
    _ACCEPT=""
    read -r _ACCEPT < /dev/tty 2>/dev/null || {
        echo ""
        echo "ERROR: No terminal available for interactive input." >&2
        echo "       Save the script and run it directly: sudo bash stager.sh" >&2
        exit 1
    }
fi
case "${_ACCEPT}" in
    y|Y|yes|YES) echo "" ;;
    *)
        echo ""
        echo "Aborted."
        exit 0
        ;;
esac

# ── Privilege check ───────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run as root or via sudo." >&2
    exit 1
fi

# ── Terminal helpers ──────────────────────────────────────────────────────────
if [ -t 1 ]; then
    BOLD=$(tput bold 2>/dev/null || printf '')
    GREEN=$(tput setaf 2 2>/dev/null || printf '')
    CYAN=$(tput setaf 6 2>/dev/null || printf '')
    RESET=$(tput sgr0 2>/dev/null || printf '')
else
    BOLD=''; GREEN=''; CYAN=''; RESET=''
fi

step() { echo ""; echo "${BOLD}${CYAN}▶ $*${RESET}"; }
ok()   { echo "${GREEN}✔ $*${RESET}"; }

# ── OS detection ──────────────────────────────────────────────────────────────
step "Detecting operating system"

ID=""
ID_LIKE=""
VERSION_CODENAME=""
PRETTY_NAME=""
VERSION_ID=""

[ -f /etc/os-release ] && . /etc/os-release

# Raspberry Pi model check
RPIVER=0
if [ -f /proc/device-tree/model ]; then
    MODEL=$(cat /proc/device-tree/model 2>/dev/null || true)
    case "$MODEL" in
        *"Raspberry Pi 5"*) RPIVER=5 ;;
        *"Raspberry Pi 4"*) RPIVER=4 ;;
        *"Raspberry Pi"*)   RPIVER=3 ;;
    esac
fi

# Normalise ID_LIKE to space-separated lowercase
ID_LIKE_LOWER=$(echo "${ID_LIKE:-}" | tr '[:upper:]' '[:lower:]')

is_like() {
    # Returns 0 if $ID or $ID_LIKE contains the given string
    local needle="$1"
    [ "${ID:-}" = "$needle" ] && return 0
    echo "$ID_LIKE_LOWER" | grep -qw "$needle" && return 0
    return 1
}

PKG_FAMILY=""  # "deb", "rpm-rhel", or "rpm-amzn"

case "${ID:-}" in
    raspbian)
        PKG_FAMILY="deb"
        OS_LABEL="Raspbian (Pi ${RPIVER})"
        ;;
    ubuntu|linuxmint|pop)
        PKG_FAMILY="deb"
        OS_LABEL="${PRETTY_NAME:-Ubuntu-family}"
        ;;
    debian)
        PKG_FAMILY="deb"
        OS_LABEL="${PRETTY_NAME:-Debian}"
        ;;
    amzn)
        PKG_FAMILY="rpm-amzn"
        OS_LABEL="Amazon Linux ${VERSION_ID:-}"
        ;;
    fedora|rhel|rocky|almalinux|centos)
        PKG_FAMILY="rpm-rhel"
        OS_LABEL="${PRETTY_NAME:-RHEL-family}"
        ;;
    *)
        # Fallback: try ID_LIKE
        if is_like "debian" || is_like "ubuntu"; then
            PKG_FAMILY="deb"
            OS_LABEL="${PRETTY_NAME:-Debian-like}"
        elif is_like "rhel" || is_like "fedora"; then
            PKG_FAMILY="rpm-rhel"
            OS_LABEL="${PRETTY_NAME:-RHEL-like}"
        else
            echo "ERROR: Unsupported OS (ID=${ID:-unknown}). Open an issue at https://github.com/jdibby/traffgen" >&2
            exit 1
        fi
        ;;
esac

ok "Detected: ${OS_LABEL}"

# ── System package update & upgrade ──────────────────────────────────────────
step "Updating and upgrading system packages"

case "$PKG_FAMILY" in
    deb)
        export DEBIAN_FRONTEND=noninteractive
        export NEEDRESTART_MODE=a
        apt-get -qq update
        apt-get -qq -y upgrade
        ;;
    rpm-rhel)
        dnf -y -q upgrade
        ;;
    rpm-amzn)
        if [ "${VERSION_ID:-}" = "2" ]; then
            yum -y -q update
        else
            dnf -y -q upgrade
        fi
        ;;
esac
ok "System packages up to date"

# ── Docker install (idempotent) ───────────────────────────────────────────────
step "Checking Docker"

if docker info &>/dev/null 2>&1; then
    ok "Docker is already running — skipping install"
else
    step "Installing Docker"

    case "$PKG_FAMILY" in

        deb)
            export DEBIAN_FRONTEND=noninteractive
            export NEEDRESTART_MODE=a

            # Minimal APT source deduplication to avoid 'duplicate' warnings
            _dedup_apt() {
                local _awk='/^[[:space:]]*$/{next}/^[[:space:]]*#/{next}!seen[$0]++'
                [ -f /etc/apt/sources.list ] && \
                    awk "$_awk" /etc/apt/sources.list > /tmp/_src && \
                    mv /tmp/_src /etc/apt/sources.list
                for f in /etc/apt/sources.list.d/*.list; do
                    [ -f "$f" ] || continue
                    awk "$_awk" "$f" > /tmp/_src && mv /tmp/_src "$f"
                    [ -s "$f" ] || rm -f "$f"
                done
            }
            _dedup_apt

            apt-get -qq update
            apt-get -qq install -y ca-certificates curl gnupg lsb-release

            install -m 0755 -d /etc/apt/keyrings

            ARCH=$(dpkg --print-architecture)
            # VERSION_CODENAME and UBUNTU_CODENAME are already set from the . /etc/os-release above.
            # UBUNTU_CODENAME is the fallback for Mint/Pop!_OS which set it but not VERSION_CODENAME.
            CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"

            if [ "${ID:-}" = "raspbian" ] && [ "$RPIVER" -ge 5 ]; then
                DOCKER_GPG="https://download.docker.com/linux/debian/gpg"
                DOCKER_REPO="https://download.docker.com/linux/debian"
            elif [ "${ID:-}" = "raspbian" ]; then
                DOCKER_GPG="https://download.docker.com/linux/raspbian/gpg"
                DOCKER_REPO="https://download.docker.com/linux/raspbian"
            elif is_like "ubuntu" || [ "${ID:-}" = "ubuntu" ]; then
                DOCKER_GPG="https://download.docker.com/linux/ubuntu/gpg"
                DOCKER_REPO="https://download.docker.com/linux/ubuntu"
            else
                DOCKER_GPG="https://download.docker.com/linux/debian/gpg"
                DOCKER_REPO="https://download.docker.com/linux/debian"
            fi

            curl -fsSL "$DOCKER_GPG" -o /etc/apt/keyrings/docker.asc
            chmod a+r /etc/apt/keyrings/docker.asc
            echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] ${DOCKER_REPO} ${CODENAME} stable" \
                > /etc/apt/sources.list.d/docker.list

            apt-get -qq update
            apt-get -qq install -y docker-ce docker-ce-cli containerd.io \
                                   docker-buildx-plugin docker-compose-plugin
            systemctl enable --now docker
            ;;

        rpm-rhel)
            # Fedora uses dnf directly; others need the Docker CE repo
            if [ "${ID:-}" = "fedora" ]; then
                dnf -y -q install dnf-plugins-core
                dnf config-manager --add-repo \
                    https://download.docker.com/linux/fedora/docker-ce.repo
            else
                dnf -y -q install dnf-plugins-core
                dnf config-manager --add-repo \
                    https://download.docker.com/linux/centos/docker-ce.repo
            fi
            dnf -y -q install docker-ce docker-ce-cli containerd.io \
                              docker-buildx-plugin docker-compose-plugin
            systemctl enable --now docker
            ;;

        rpm-amzn)
            if [ "${VERSION_ID:-}" = "2" ]; then
                # Amazon Linux 2
                amazon-linux-extras enable docker
                yum -y -q install docker
            else
                # Amazon Linux 2023
                dnf -y -q install docker
            fi
            systemctl enable --now docker
            # Add ec2-user to docker group if present
            id ec2-user &>/dev/null && usermod -aG docker ec2-user || true
            ;;
    esac

    ok "Docker installed"
fi

# ── Full cleanup and fresh start ──────────────────────────────────────────────
step "Stopping and removing all containers"
docker stop $(docker ps -aq) 2>/dev/null || true
docker rm   $(docker ps -aq) 2>/dev/null || true

step "Pruning images, volumes, and build cache"
docker image prune -af   2>/dev/null || true
docker volume prune -f   2>/dev/null || true
docker builder prune -af 2>/dev/null || true

step "Pulling latest traffgen image"
docker pull jdibby/traffgen:latest

step "Starting traffgen container"

# Capture the host's LAN IP before the container starts so the lateral-movement
# suite can scan the real physical network rather than the Docker bridge.
HOST_LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -n "$HOST_LAN_IP" ]; then
    ok "Host LAN IP detected: ${HOST_LAN_IP} (will be passed to container for lateral movement)"
else
    echo "WARNING: could not detect host LAN IP — lateral-movement suite will fall back to container network"
fi

docker run \
    --detach \
    --restart unless-stopped \
    -p 7777:7777 \
    ${HOST_LAN_IP:+-e HOST_LAN_IP="$HOST_LAN_IP"} \
    --name traffgen \
    jdibby/traffgen:latest \
    --suite=all --size=S --max-wait-secs=20 --loop

ok "Container started"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo "${BOLD}  Install complete${RESET}"
echo ""
docker ps --filter "name=^traffgen$" --format "  Container : {{.Names}}  ({{.Status}})"
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
echo ""
echo "  ${BOLD}Web dashboard : ${GREEN}https://${HOST_IP}:7777${RESET}"
echo "  (Accept the self-signed certificate warning in your browser)"
echo "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
