#!/bin/bash

### Validate this is being run with sudo / root permissions ###
WHOAREYOU=$(whoami)
if [ "$WHOAREYOU" != "root" ]; then
    echo "#######################################################################"
    echo "############## YOU MUST BE ROOT OR ELSE SUDO THIS SCRIPT ##############"
    echo "#######################################################################"
    exit 1
fi

### Adding capabilities of bold fonts ###
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

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

echo ""
echo "${BOLD}### DETECTING OPERATING SYSTEM AND PERFORMING UPDATES ###${NORMAL}"
echo ""

### Check for Raspberry Pi ###
if [ -f /proc/device-tree/model ]; then
    RPIVER=$(grep -a "Raspberry" /proc/device-tree/model | awk '{print $3}')
else
    RPIVER=""
fi

### Check for Ubuntu Linux ###
if [ -f /etc/os-release ]; then
    UBUNTU=$(grep 'NAME="Ubuntu"' /etc/os-release | wc -l)
else
    UBUNTU=0
fi

### Check for Rocky Linux ###
if [ -f /etc/os-release ]; then
    ROCKY=$(grep -i 'NAME="Rocky Linux"' /etc/os-release | wc -l)
else
    ROCKY=0
fi

### Check for Raspbian OS (Raspberry Pi OS) ###
if [ -f /etc/os-release ]; then
    RASPBIAN=$(grep 'ID=raspbian' /etc/os-release | wc -l)
else
    RASPBIAN=0
fi

### Check for Pure Debian OS ###
if [ -f /etc/os-release ]; then
    DEBIAN=$(grep '^ID=debian$' /etc/os-release | wc -l)
    # Ensure it's not Raspbian which also has ID_LIKE=debian
    if [ "$DEBIAN" -gt 0 ] && [ "$RASPBIAN" -gt 0 ]; then
        DEBIAN=0 # If it's Raspbian, don't treat it as pure Debian
    fi
else
    DEBIAN=0
fi

### Proceed with the operating system detection logic and updates

### Raspbian detection
if [ "$RASPBIAN" -gt 0 ]; then
    if [ -n "$RPIVER" ] && [ "$RPIVER" -eq 5 ]; then
        echo "#######################################################################"
        echo "############${BOLD} System detected as Raspberry Pi 5 (Raspbian) ${NORMAL}#############"
        echo "#######################################################################"
    elif [ -n "$RPIVER" ] && [ "$RPIVER" -eq 4 ]; then
        echo "#######################################################################"
        echo "############${BOLD} System detected as Raspberry Pi 4 (Raspbian) ${NORMAL}#############"
        echo "#######################################################################"
    elif [ -n "$RPIVER" ] && [ "$RPIVER" -gt 0 ]; then
        echo "#######################################################################"
        echo "############${BOLD} System detected as Raspberry Pi $RPIVER (Raspbian) ${NORMAL}########"
        echo "#######################################################################"
    else
        echo "#######################################################################"
        echo "############${BOLD} System detected as Raspbian (Non-Pi Hardware) ${NORMAL}#########"
        echo "#######################################################################"
    fi
    echo ""
    apt update -y && apt upgrade -y
### Pure Debian detection
elif [ "$DEBIAN" -gt 0 ]; then
    echo "#######################################################################"
    echo "###################${BOLD} System detected as Pure Debian Linux ${NORMAL}################"
    echo "#######################################################################"
    echo ""
    apt update -y && apt upgrade -y
elif [ "$UBUNTU" -gt 0 ]; then
    echo "#######################################################################"
    echo "##################${BOLD} System detected as Ubuntu Linux ${NORMAL}####################"
    echo "#######################################################################"
    echo ""
    apt update -y && apt upgrade -y
elif [ "$ROCKY" -gt 0 ]; then
    echo "#######################################################################"
    echo "###################${BOLD} System detected as Rocky Linux ${NORMAL}####################"
    echo "#######################################################################"
    echo ""
    dnf update -y && dnf upgrade -y
else
    echo "#######################################################################"
    echo "#######################################################################"
    echo "#################${BOLD} NOT A SUPPORTED OPERATING SYSTEM ${NORMAL}####################"
    echo "#######################################################################"
    echo "#######################################################################"
    echo ""
    exit 1
fi
#################################################################
echo ""
echo "${BOLD}### OPERATING SYSTEM DETECTED AND UPDATES COMPLETED ###${NORMAL}"
echo ""

### Raspbian (Raspberry Pi OS)
if [ "$RASPBIAN" -gt 0 ]; then
    for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do apt-get remove $pkg; done
    apt-get update -y
    apt-get install ca-certificates curl git -y
    install -m 0755 -d /etc/apt/keyrings
    chmod a+r /etc/apt/keyrings/docker.asc

    if [ -n "$RPIVER" ] && [ "$RPIVER" -eq 5 ]; then
        ### RPi 5 Raspbian uses Docker's Debian repository
        curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
        echo \
            "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
            $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
            tee /etc/apt/sources.list.d/docker.list > /dev/null
        echo "${BOLD}### DOCKER INSTALLED AND IS READY TO USE FOR RASPBERRY PI 5 (RASPBIAN) ###${NORMAL}"
    else
        ### RPi < 5 Raspbian and other non-Pi Raspbian installations use Docker's Raspbian repository
        curl -fsSL https://download.docker.com/linux/raspbian/gpg -o /etc/apt/keyrings/docker.asc
        echo \
            "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/raspbian \
            $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
            tee /etc/apt/sources.list.d/docker.list > /dev/null
        if [ -n "$RPIVER" ] && [ "$RPIVER" -eq 4 ]; then
            echo "${BOLD}### DOCKER INSTALLED AND IS READY TO USE FOR RASPBERRY PI 4 (RASPBIAN) ###${NORMAL}"
        else
            echo "${BOLD}### DOCKER INSTALLED AND IS READY TO USE FOR RASPBERRY PI (OLDER RASPBIAN) ###${NORMAL}"
        fi
    fi
    apt-get update -y
    apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
    systemctl restart docker
    echo ""

### Pure Debian
elif [ "$DEBIAN" -gt 0 ]; then
    for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do apt-get remove $pkg; done
    apt-get update -y
    apt-get install ca-certificates curl -y
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -y
    apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
    systemctl restart docker
    echo ""
    echo "${BOLD}### DOCKER INSTALLED AND IS READY TO USE FOR PURE DEBIAN ###${NORMAL}"
    echo ""

### Ubuntu
elif [ "$UBUNTU" -gt 0 ]; then
    for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do apt-get remove $pkg; done
    apt-get update -y
    apt-get install ca-certificates curl -y
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -y
    apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
    systemctl restart docker
    echo ""
    echo "${BOLD}### DOCKER INSTALLED AND IS READY TO USE ###${NORMAL}"
    echo ""

### Rocky Linux
elif [ "$ROCKY" -gt 0 ]; then
    dnf remove -y docker-ce docker-ce-cli containerd.io
    rm -rf /var/lib/docker
    rm -rf /var/lib/containerd
    dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
    dnf update -y
    dnf install docker-ce docker-ce-cli containerd.io docker-compose-plugin -y
    systemctl start docker
    systemctl enable docker
    echo ""
    echo "${BOLD}### INSTALLATION OF DOCKER COMPLETE ###${NORMAL}"
    echo ""
else
    echo ""
    echo "### YOU ARE RUNNING AN UNSUPPORTED OPERATING SYSTEM FOR DOCKER INSTALLATION ###"
    echo ""
    exit 1
fi

echo "${BOLD}### INSTALLATION OF DOCKER COMPLETE ###${NORMAL}"
echo ""

echo "${BOLD}### STARTING TRAFFGEN INSTALL ###${NORMAL}"
echo ""
### Cleanup all other containers
docker stop $(docker ps -a -q) &> /dev/null
docker rm $(docker ps -a -q) &> /dev/null
docker images | awk '{print $3}' | xargs docker rmi -f &> /dev/null

echo ""
echo "${BOLD}### TRAFFGEN CONTAINER BEING STARTED ###${NORMAL}"
### Run the traffgen docker image (this command is universal across architectures and operating systems) 
docker run --detach --restart unless-stopped jdibby/traffgen:latest

echo ""
echo "${BOLD}### TRAFFGEN INSTALL COMPLETE ###${NORMAL}"
echo ""
docker ps -a --format "table {{.ID}} -- {{.Image}} -- {{.Names}} -- {{.Status}}"
echo ""