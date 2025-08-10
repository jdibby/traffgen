#!/bin/bash

### VALIDATE ROOT PRIVILEGES ###
echo "Checking for root privileges..."
WHOAREYOU=$(whoami)
if [ "$WHOAREYOU" != "root" ]; then
    echo "#######################################################################"
    echo "############## YOU MUST BE ROOT OR ELSE SUDO THIS SCRIPT ##############"
    echo "#######################################################################"
    exit 1
fi

### INITIALIZE FORMATTING ###
BOLD=$(tput bold)
NORMAL=$(tput sgr0)
echo ""
echo "${BOLD}### DETECTING OPERATING SYSTEM ###${NORMAL}"
echo ""

### OS DETECTION LOGIC ###
RPIVER=""
if [ -f /proc/device-tree/model ]; then
    RPIVER=$(grep -a "Raspberry" /proc/device-tree/model | awk '{print $3}')
fi

### RESET OS VARIABLES ###
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
        DEBIAN=0
    fi
fi

### DISPLAY OS AND PERFORM GLOBAL UPDATE ###
if [ "$RASPBIAN" -gt 0 ]; then
    echo "#######################################################################"
    echo "##########${BOLD} System detected as Raspbian ${NORMAL}###########################"
    echo "#######################################################################"
elif [ "$DEBIAN" -gt 0 ]; then
    echo "#######################################################################"
    echo "##########${BOLD} System detected as Pure Debian ${NORMAL}######################"
    echo "#######################################################################"
elif [ "$UBUNTU" -gt 0 ]; then
    echo "#######################################################################"
    echo "##########${BOLD} System detected as Ubuntu Linux ${NORMAL}#####################"
    echo "#######################################################################"
elif [ "$ROCKY" -gt 0 ]; then
    echo "#######################################################################"
    echo "##########${BOLD} System detected as Rocky Linux ${NORMAL}#####################"
    echo "#######################################################################"
else
    echo "#######################################################################"
    echo "#################### UNSUPPORTED OPERATING SYSTEM #####################"
    echo "#######################################################################"
    exit 1
fi

echo ""
echo "${BOLD}### UPDATING SYSTEM PACKAGES ###${NORMAL}"
if [ "$ROCKY" -gt 0 ]; then
    dnf update -y && dnf upgrade -y
else
    apt update -y && apt upgrade -y && apt autoremove -y && apt clean -y
fi

### CLEANUP EXISTING CONTAINERS ###
echo ""
echo "${BOLD}### CLEANING UP DOCKER CONTAINERS AND IMAGES ###${NORMAL}"
docker stop $(docker ps -aq) &>/dev/null
docker rm $(docker ps -aq) &>/dev/null
docker images | awk '{print $3}' | xargs docker rmi -f &>/dev/null

### REMOVE OLD DOCKER INSTALLATIONS ###
echo ""
echo "${BOLD}### REMOVING OLD DOCKER INSTALLATIONS ###${NORMAL}"
if [ "$ROCKY" -gt 0 ]; then
    dnf remove -y docker-ce docker-ce-cli containerd.io
    rm -rf /var/lib/docker /var/lib/containerd
else
    for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
        apt remove -y $pkg
    done
fi

### CONFIGURE DOCKER REPOSITORY ###
echo ""
echo "${BOLD}### CONFIGURING DOCKER REPOSITORY ###${NORMAL}"
if [ "$ROCKY" -gt 0 ]; then
    dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
    dnf update -y
    dnf install docker-ce docker-ce-cli containerd.io docker-compose-plugin -y
    systemctl enable --now docker
else
    echo ""
    echo "${BOLD}### CLEANING UP APT SOURCE REPOS ###${NORMAL}"
    echo ""

    ### Cleanup apt repo deduplicates
    ### Install dependencies (if not already present)
    sudo apt install python3-apt python3-regex -y

    ### Download the script
    wget https://github.com/davidfoerster/aptsources-cleanup/releases/download/v0.1.7.5.2/aptsources-cleanup.pyz

    ### Make it executable
    chmod +x aptsources-cleanup.pyz

    ### Run the script
    sudo bash -c "echo all | ./aptsources-cleanup.pyz --yes"

    ### Remove the script after use
    rm aptsources-cleanup.pyz

    echo ""
    echo "${BOLD}### APT SOURCE REPOS ARE NOW CLEAN ###${NORMAL}"
    echo ""

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
    docker system prune -f
    docker image prune -f
    docker volume prune -f
    docker network prune -f
    docker container prune -f
fi  

echo ""
echo "${BOLD}### DOCKER INSTALLATION COMPLETE ###${NORMAL}"
echo ""

echo "${BOLD}### STARTING TRAFFGEN CONTAINER ###${NORMAL}"
docker run --pull=always --detach --restart unless-stopped jdibby/traffgen:latest --suite=all --size=M --max-wait-secs=30 --loop

echo ""
echo "${BOLD}### TRAFFGEN INSTALL COMPLETE ###${NORMAL}"
echo ""
docker ps -a --format "table {{.ID}} -- {{.Image}} -- {{.Names}} -- {{.Status}}"
echo ""
