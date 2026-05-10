#!/bin/bash
# stager.sh — Installs Docker and starts the traffgen container.
#
# Idempotent: skips Docker install if already running, skips container
# start if already running under the name "traffgen".
#
# Supported platforms:
#   macOS         : 12 Monterey and later (requires Homebrew)
#   Debian family : Ubuntu, Debian, Linux Mint, Pop!_OS
#   Raspberry Pi  : Raspbian (Pi 4 ARMv7 / Pi 5 arm64)
#   RHEL family   : Rocky Linux, AlmaLinux, CentOS Stream, RHEL, Fedora
#   Amazon Linux  : Amazon Linux 2 and Amazon Linux 2023
#
# Usage (Linux — requires sudo):
#   curl -sk https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh | sudo bash
#
# Usage (macOS — do NOT use sudo; Homebrew cannot run as root):
#   curl -sk https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh | bash

set -euo pipefail

# ── Early platform detection (needed before privilege check and banner) ────────
_UNAME=$(uname -s 2>/dev/null || echo "Linux")

# ── Warning banner ────────────────────────────────────────────────────────────
if [ "$_UNAME" = "Darwin" ]; then
cat <<'BANNER'

================================================================================
            TRAFFGEN STAGER -- SYSTEM CHANGES WARNING
================================================================================

  This script will make the following changes to your system:

    1. brew update       - refresh Homebrew package index
    2. brew upgrade      - upgrade all Homebrew packages
    3. Install Docker    - Docker Desktop via: brew install --cask docker
    4. Launch Docker     - open Docker Desktop and wait for daemon
    5. Remove containers - stop and remove ALL existing Docker containers
    6. Prune images      - delete ALL Docker images, volumes, build cache
    7. Pull image        - jdibby/traffgen:latest from Docker Hub
    8. Start container   - port 7777, restart unless-stopped

  NOTE: Steps 5 & 6 will permanently DELETE all existing containers and
  images on this host. Run on a dedicated machine, or review the script
  at https://github.com/jdibby/traffgen/blob/main/stager.sh before use.

  NOTE: macOS does not support --network=host. The lateral-movement suite
  will be limited to the Docker bridge network, not your physical LAN.

--------------------------------------------------------------------------------

  DISCLAIMER: For AUTHORIZED SECURITY TESTING AND RESEARCH only.
  You are solely responsible for obtaining explicit written permission
  before testing any systems or networks. The author(s) accept NO
  liability for misuse, unauthorized access, damage, or data loss.

================================================================================
BANNER
else
cat <<'BANNER'

================================================================================
            TRAFFGEN STAGER -- SYSTEM CHANGES WARNING
================================================================================

  This script will make the following changes to your system:

    1. apt/dnf update    - refresh package index
    2. apt/dnf upgrade   - upgrade ALL installed packages
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
fi

# ── TTY helper — reads from /dev/tty so it works when piped via curl | bash ───
_ask_tty() {
    # Usage: answer=$(_ask_tty "Prompt: " "default")
    local _prompt="$1" _default="${2:-}"
    printf '%s' "$_prompt" > /dev/tty
    local _r=""
    read -r _r < /dev/tty 2>/dev/null || {
        echo ""
        echo "ERROR: No terminal available for interactive input." >&2
        echo "       Save the script and run it directly: bash stager.sh" >&2
        exit 1
    }
    printf '%s' "${_r:-$_default}"
}

# Read acceptance — works both interactively and when piped via curl | bash
printf '\nDo you accept these terms and wish to continue? [y/N] '
_ACCEPT=$(_ask_tty "" "n")
case "${_ACCEPT}" in
    y|Y|yes|YES) echo "" ;;
    *)
        echo ""
        echo "Aborted."
        exit 0
        ;;
esac

# ── Privilege check ───────────────────────────────────────────────────────────
if [ "$_UNAME" = "Darwin" ]; then
    # Homebrew must NOT be run as root.
    if [ "$(id -u)" -eq 0 ]; then
        echo "ERROR: On macOS, run WITHOUT sudo — Homebrew cannot run as root." >&2
        echo "       Usage: curl -sk <url>/stager.sh | bash" >&2
        exit 1
    fi
    _REAL_USER="$(id -un)"
else
    if [ "$(id -u)" -ne 0 ]; then
        echo "ERROR: Run as root or via sudo." >&2
        exit 1
    fi
fi

# ── Traffic generation configuration ─────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  TRAFFGEN CONFIGURATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Suite
echo "  Available suites: all dns http https ftp ssh bgp icmp ntp snmp doh dot"
echo "                    c2-beacon malware-samples c2-useragents phishing-domains"
echo "                    squatting av-test ad-tracker pornography dlp dns-exfil data-exfil-http"
echo "                    llm-dlp ids-sigs waf-attack log4shell nmap web-scanner"
echo "                    msf-webapp msf-enterprise msf-appliance msf-cisa-kev msf-middleware"
echo "                    msf-recon msf-aux-scan msf-payload-delivery msf-cred-spray"
echo "                    shadow-it tor-anonymizer tls-inspection lateral-movement"
echo "                    ai-browse post-quantum http3 web-crawl bulk-transfer speedtest url-latency s3"
echo "                    blocklist-probe snmp voip ucaas"
echo ""
_CFG_SUITE=$(_ask_tty "  Suite to run [all]: " "all")

# Size
echo ""
echo "  Traffic intensity sizes: XS (minimal) | S (light) | M (moderate) | L (heavy) | XL (max)"
_CFG_SIZE=$(_ask_tty "  Traffic size [S]: " "S")
# Normalise to uppercase
_CFG_SIZE=$(echo "$_CFG_SIZE" | tr '[:lower:]' '[:upper:]')
case "$_CFG_SIZE" in
    XS|S|M|L|XL) ;;
    *) echo "  Unknown size '${_CFG_SIZE}', defaulting to S"; _CFG_SIZE="S" ;;
esac

# Loop
echo ""
_CFG_LOOP_ANS=$(_ask_tty "  Run continuously in a loop? [Y/n]: " "y")
case "$_CFG_LOOP_ANS" in
    n|N|no|NO) _CFG_LOOP="" ;;
    *)          _CFG_LOOP="--loop" ;;
esac

# Max wait
echo ""
_CFG_WAIT=$(_ask_tty "  Max wait between tests in seconds [20]: " "20")
# Basic integer validation
case "$_CFG_WAIT" in
    ''|*[!0-9]*) echo "  Invalid value, defaulting to 20"; _CFG_WAIT="20" ;;
esac

# Web dashboard
echo ""
_CFG_WEBUI_ANS=$(_ask_tty "  Enable web dashboard? [Y/n]: " "y")
case "$_CFG_WEBUI_ANS" in
    n|N|no|NO) _CFG_WEBUI=0 ;;
    *)          _CFG_WEBUI=1 ;;
esac

# Dashboard port (only when web UI is enabled)
_CFG_PORT=7777
if [ "$_CFG_WEBUI" -eq 1 ]; then
    echo ""
    _CFG_PORT_ANS=$(_ask_tty "  Web dashboard port [7777]: " "7777")
    case "$_CFG_PORT_ANS" in
        ''|*[!0-9]*)
            echo "  Invalid port, defaulting to 7777"
            _CFG_PORT=7777
            ;;
        *)
            if [ "$_CFG_PORT_ANS" -lt 1 ] || [ "$_CFG_PORT_ANS" -gt 65535 ]; then
                echo "  Port out of range (1-65535), defaulting to 7777"
                _CFG_PORT=7777
            else
                _CFG_PORT="$_CFG_PORT_ANS"
            fi
            ;;
    esac
fi

# Host networking (Linux only — not supported on macOS Docker Desktop)
_CFG_NET_HOST=0
if [ "$_UNAME" != "Darwin" ] && [ "$_CFG_WEBUI" -eq 1 ]; then
    echo ""
    echo "  Host networking (--network=host) gives the lateral-movement suite access to"
    echo "  your physical LAN and exposes the dashboard without a port mapping."
    echo "  Use -p <port>:7777 if you only need the web dashboard."
    _CFG_NETHOST_ANS=$(_ask_tty "  Use host networking? [y/N]: " "n")
    case "$_CFG_NETHOST_ANS" in
        y|Y|yes|YES) _CFG_NET_HOST=1 ;;
        *)            _CFG_NET_HOST=0 ;;
    esac
fi

# Confirm
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Configuration summary:"
echo "    Suite       : ${_CFG_SUITE}"
echo "    Size        : ${_CFG_SIZE}"
echo "    Loop        : ${_CFG_LOOP:-no}"
echo "    Max wait    : ${_CFG_WAIT}s"
if [ "$_CFG_WEBUI" -eq 1 ]; then
    if [ "$_CFG_NET_HOST" -eq 1 ]; then
        echo "    Networking  : --network=host (dashboard on port 7777 + full LAN scanning)"
    else
        echo "    Networking  : -p ${_CFG_PORT}:7777 (dashboard on https://<host>:${_CFG_PORT})"
    fi
else
    echo "    Networking  : none (headless, no web dashboard)"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
_CFG_CONFIRM=$(_ask_tty "  Proceed with installation? [Y/n]: " "y")
case "$_CFG_CONFIRM" in
    n|N|no|NO)
        echo ""
        echo "Aborted."
        exit 0
        ;;
esac
echo ""

# ── Terminal helpers ──────────────────────────────────────────────────────────
if [ -t 1 ]; then
    BOLD=$(tput bold 2>/dev/null || printf '')
    GREEN=$(tput setaf 2 2>/dev/null || printf '')
    CYAN=$(tput setaf 6 2>/dev/null || printf '')
    RED=$(tput setaf 1 2>/dev/null || printf '')
    RESET=$(tput sgr0 2>/dev/null || printf '')
else
    BOLD=''; GREEN=''; CYAN=''; RED=''; RESET=''
fi

step() { echo ""; echo "${BOLD}${CYAN}▶ $*${RESET}"; }
ok()   { echo "${GREEN}✔ $*${RESET}"; }
note() { echo "${RED}  Note: $*${RESET}"; }
warn() { echo "${RED}WARNING: $*${RESET}"; }

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
    local needle="$1"
    [ "${ID:-}" = "$needle" ] && return 0
    echo "$ID_LIKE_LOWER" | grep -qw "$needle" && return 0
    return 1
}

PKG_FAMILY=""  # "mac", "deb", "rpm-rhel", or "rpm-amzn"

if [ "$_UNAME" = "Darwin" ]; then
    PKG_FAMILY="mac"
    OS_LABEL="macOS $(sw_vers -productVersion 2>/dev/null || echo '')"
else
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
fi

ok "Detected: ${OS_LABEL}"

# ── Remove duplicate package source entries (Linux deb/rpm only) ──────────────
# On re-runs or systems where Docker was previously added via add-apt-repository
# or a third-party script, an auto-named file like
# archive_uri-https_download_docker_com_linux_ubuntu-jammy.list can coexist
# with our canonical docker.list, causing 'configured multiple times' warnings.
if [ "$PKG_FAMILY" = "deb" ]; then
    for _f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [ -f "$_f" ] || continue
        [ "$(basename "$_f")" = "docker.list" ] && continue
        if grep -q "download\.docker\.com" "$_f" 2>/dev/null; then
            rm -f "$_f"
            ok "Removed duplicate Docker source: $(basename "$_f")"
        fi
    done
fi
if [ "$PKG_FAMILY" = "rpm-rhel" ]; then
    # dnf config-manager --add-repo is not idempotent on all versions; remove
    # any existing Docker CE repo file before we add it so there's no duplicate.
    rm -f /etc/yum.repos.d/docker-ce.repo /etc/yum.repos.d/docker-ce-fedora.repo 2>/dev/null || true
fi

# ── System package update & upgrade ──────────────────────────────────────────
step "Updating and upgrading system packages"

case "$PKG_FAMILY" in
    mac)
        if ! command -v brew >/dev/null 2>&1; then
            echo "ERROR: Homebrew is not installed." >&2
            echo "       Install it from https://brew.sh then re-run this script." >&2
            exit 1
        fi
        brew update
        brew upgrade
        ;;
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

        mac)
            brew install --cask docker
            ok "Docker Desktop installed — launching..."
            open -a Docker
            step "Waiting for Docker Desktop to start (this may take up to 60 seconds)"
            _tries=0
            until docker info &>/dev/null 2>&1; do
                _tries=$((_tries + 1))
                if [ "$_tries" -ge 30 ]; then
                    echo "" >&2
                    echo "ERROR: Docker Desktop did not start within 60 seconds." >&2
                    echo "       Open Docker Desktop from Applications and re-run this script." >&2
                    exit 1
                fi
                printf '.'
                sleep 2
            done
            echo ""
            ;;

        deb)
            export DEBIAN_FRONTEND=noninteractive
            export NEEDRESTART_MODE=a

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

# Capture the host's LAN IP and subnet prefix before the container starts.
# This lets the lateral-movement suite and Network Info widget use the real
# host IP instead of the Docker bridge address.
HOST_LAN_IP=""
HOST_LAN_CIDR=""

if [ "$_UNAME" = "Darwin" ]; then
    # macOS: try Wi-Fi (en0) then Ethernet (en1) then any non-loopback inet addr
    HOST_LAN_IP=$(ipconfig getifaddr en0 2>/dev/null || \
                  ipconfig getifaddr en1 2>/dev/null || \
                  ifconfig 2>/dev/null | awk '/inet / && !/127\.0\.0\.1/{print $2; exit}')
    if [ -n "$HOST_LAN_IP" ]; then
        # Convert hex netmask (e.g. 0xffffff00) to CIDR prefix length via python3
        _HEX_MASK=$(ifconfig 2>/dev/null | awk -v ip="$HOST_LAN_IP" '$2==ip{print $4}' | sed 's/0x//')
        _PREFIX=24  # safe default
        if [ -n "$_HEX_MASK" ] && command -v python3 >/dev/null 2>&1; then
            _PREFIX=$(python3 -c "print(bin(int('${_HEX_MASK}',16)).count('1'))" 2>/dev/null || echo 24)
        fi
        HOST_LAN_CIDR="${HOST_LAN_IP}/${_PREFIX}"
        ok "Host LAN detected: ${HOST_LAN_CIDR} (passed to container for Network Info widget)"
        note "--network=host is not supported on macOS — lateral-movement suite will be limited to the Docker bridge network."
    else
        warn "could not detect host LAN IP"
    fi
else
    HOST_LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}') || HOST_LAN_IP=""
    if [ -n "$HOST_LAN_IP" ]; then
        _PREFIX=24  # safe default
        if command -v ip >/dev/null 2>&1; then
            _P=$(ip -o -f inet addr 2>/dev/null \
                 | awk -v h="$HOST_LAN_IP" 'index($4, h"/")>0 {split($4,a,"/"); print a[2]; exit}') || _P=""
            [ -n "$_P" ] && _PREFIX="$_P"
        fi
        HOST_LAN_CIDR="${HOST_LAN_IP}/${_PREFIX}"
        ok "Host LAN detected: ${HOST_LAN_CIDR} (passed to container for lateral movement)"
    else
        warn "could not detect host LAN — lateral-movement suite will fall back to container network"
    fi
fi

# Ensure no stale container with this name blocks the new one
docker rm -f traffgen 2>/dev/null || true

# Build docker run args as an array to avoid word-splitting issues
_DOCKER_ARGS=(
    --detach
    --restart unless-stopped
)
if [ "$_CFG_WEBUI" -eq 1 ]; then
    if [ "$_CFG_NET_HOST" -eq 1 ]; then
        _DOCKER_ARGS+=(--network=host)
    else
        _DOCKER_ARGS+=(-p "${_CFG_PORT}:7777")
    fi
fi
if [ -n "${HOST_LAN_CIDR:-}" ]; then
    _DOCKER_ARGS+=(-e "HOST_LAN_CIDR=${HOST_LAN_CIDR}")
fi
_DOCKER_ARGS+=(--name traffgen jdibby/traffgen:latest)
_DOCKER_ARGS+=(--suite="${_CFG_SUITE}" --size="${_CFG_SIZE}" --max-wait-secs="${_CFG_WAIT}")
[ -n "${_CFG_LOOP:-}" ] && _DOCKER_ARGS+=("${_CFG_LOOP}")

_RUN_LOG=$(mktemp)
if ! docker run "${_DOCKER_ARGS[@]}" 2>"$_RUN_LOG"; then
    echo "" >&2
    echo "ERROR: docker run failed." >&2
    cat "$_RUN_LOG" >&2
    rm -f "$_RUN_LOG"
    # Show any container that may have been partially created
    _STALE=$(docker ps -a --filter "name=^traffgen$" --format "{{.ID}} {{.Status}}" 2>/dev/null || true)
    [ -n "$_STALE" ] && echo "Stale container state: $_STALE" >&2
    exit 1
fi
rm -f "$_RUN_LOG"

# Brief wait and verify the container is actually running
sleep 2
if ! docker ps --filter "name=^traffgen$" --filter "status=running" --format "{{.Names}}" | grep -q traffgen; then
    echo "" >&2
    echo "ERROR: container 'traffgen' started but is not running." >&2
    docker ps -a --filter "name=^traffgen$" --format "  Status: {{.Status}}" >&2
    echo "  Logs:" >&2
    docker logs --tail 20 traffgen 2>&1 | sed 's/^/    /' >&2
    exit 1
fi

ok "Container started"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo "${BOLD}  Install complete${RESET}"
echo ""
docker ps --filter "name=^traffgen$" --format "  Container : {{.Names}}  ({{.Status}})"
echo ""
echo "  Suite       : ${_CFG_SUITE}"
echo "  Size        : ${_CFG_SIZE}  |  Max wait : ${_CFG_WAIT}s  |  Loop : ${_CFG_LOOP:-no}"

if [ "$_CFG_WEBUI" -eq 1 ]; then
    if [ "$_UNAME" = "Darwin" ]; then
        HOST_IP=$(ipconfig getifaddr en0 2>/dev/null || \
                  ipconfig getifaddr en1 2>/dev/null || \
                  ifconfig 2>/dev/null | awk '/inet / && !/127\.0\.0\.1/{print $2; exit}' || \
                  echo "localhost")
    else
        HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
    fi
    echo ""
    echo "  ${BOLD}Web dashboard : ${GREEN}https://${HOST_IP}:${_CFG_PORT}${RESET}"
    echo "  (Accept the self-signed certificate warning in your browser)"
else
    echo ""
    echo "  Running headless — no web dashboard."
    echo "  View logs: docker logs -f traffgen"
fi
echo "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
