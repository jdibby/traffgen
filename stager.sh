#!/bin/bash

# Check for root
WHOAREYOU=$(whoami)
if [ "$WHOAREYOU" != "root" ]; then
    echo "#######################################################################"
    echo "############## YOU MUST BE ROOT OR ELSE SUDO THIS SCRIPT ##############"
    echo "#######################################################################"
    exit 1
fi

BOLD=$(tput bold)
NORMAL=$(tput sgr0)
echo ""
echo "${BOLD}### DETECTING OPERATING SYSTEM ###${NORMAL}"
echo ""

# OS detection
RPIVER=""
if [ -f /proc/device-tree/model ]; then
    RPIVER=$(grep -a "Raspberry" /proc/device-tree/model | awk '{print $3}')
fi

# Reset OS variables
UBUNTU=0
ROCKY=0
RASPBIAN=0
DEBIAN=0

if [ -f /etc/os-release ]; then
    UBUNTU=$(grep 'NAME="Ubuntu"' /etc/os-release | wc -l)
    ROCKY=$(grep -i 'NAME="Rocky Linux"' /etc/os-release | wc -l)
    RASPBIAN=$(grep 'ID=raspbian' /etc/os-release | wc -l)
    DEBIAN=$(grep '^ID=debian$' /etc/os-release | wc -l)
    if [ "$DEBIAN" -gt 0 ] && [ "$RASPBIAN" -gt 0 ]; then
        DEBIAN=0  # Raspbian is not pure Debian
    fi
fi

# OS Message and Initial Update/Upgrade
if [ "$RASPBIAN" -gt 0 ]; then
    echo "${BOLD}System detected: Raspbian${NORMAL}"
elif [ "$DEBIAN" -gt 0 ]; then
    echo "${BOLD}System detected: Pure Debian${NORMAL}"
elif [ "$UBUNTU" -gt 0 ]; then
    echo "${BOLD}System detected: Ubuntu${NORMAL}"
elif [ "$ROCKY" -gt 0 ]; then
    echo "${BOLD}System detected: Rocky Linux${NORMAL}"
else
    echo "Unsupported OS. Exiting."
    exit 1
fi

echo ""
echo "${BOLD}### PERFORMING SYSTEM UPDATE ###${NORMAL}"
if [ "$ROCKY" -gt 0 ]; then
    dnf update -y && dnf upgrade -y
else
    apt update -y && apt upgrade -y && apt autoremove -y && apt clean -y
fi

echo ""
echo "${BOLD}### CLEANING UP OLD CONTAINERS ###${NORMAL}"
docker stop $(docker ps -aq) &>/dev/null
docker rm $(docker ps -aq) &>/dev/null
docker images | awk '{print $3}' | xargs docker rmi -f &>/dev/null

# Docker removal
if [ "$ROCKY" -gt 0 ]; then
    dnf remove -y docker-ce docker-ce-cli containerd.io
    rm -rf /var/lib/docker /var/lib/containerd
else
    for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
        apt remove -y $pkg
    done
fi

# Docker repo & install
echo ""
echo "${BOLD}### CONFIGURING DOCKER REPOSITORY ###${NORMAL}"

if [ "$ROCKY" -gt 0 ]; then
    dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
    dnf update -y
    dnf install docker-ce docker-ce-cli containerd.io docker-compose-plugin -y
    systemctl enable --now docker
else
    apt install -y ca-certificates curl gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings

    ARCH=$(dpkg --print-architecture)
    CODENAME=$(grep VERSION_CODENAME /etc/os-release | cut -d= -f2)

    if [ "$RASPBIAN" -gt 0 ]; then
        if [ "$RPIVER" -eq 5 ]; then
            curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
            echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $CODENAME stable" \
                | tee /etc/apt/sources.list.d/docker.list > /dev/null
        else
            curl -fsSL https://download.docker.com/linux/raspbian/gpg -o /etc/apt/keyrings/docker.asc
            echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/raspbian $CODENAME stable" \
                | tee /etc/apt/sources.list.d/docker.list > /dev/null
        fi
    elif [ "$UBUNTU" -gt 0 ]; then
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
        echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $CODENAME stable" \
            | tee /etc/apt/sources.list.d/docker.list > /dev/null
    elif [ "$DEBIAN" -gt 0 ]; then
        curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
        echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $CODENAME stable" \
            | tee /etc/apt/sources.list.d/docker.list > /dev/null
    fi

    chmod a+r /etc/apt/keyrings/docker.asc
    apt update -y
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl restart docker
fi

echo ""
echo "${BOLD}### DOCKER INSTALLATION COMPLETE ###${NORMAL}"
echo ""

# Start Traffgen
echo "${BOLD}### STARTING TRAFFGEN CONTAINER ###${NORMAL}"
docker run --pull=always --detach --restart unless-stopped jdibby/traffgen:latest --suite=all --size=M --max-wait-secs=10
echo ""
echo "${BOLD}### TRAFFGEN INSTALL COMPLETE ###${NORMAL}"
echo ""
docker ps -a --format "table {{.ID}} -- {{.Image}} -- {{.Names}} -- {{.Status}}"
echo ""
