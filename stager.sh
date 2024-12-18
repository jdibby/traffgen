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

### Set Home Directory ###
HOMEDIR=$(pwd)
###############################################################

echo -e -n "\n" 
echo "${BOLD}### DETECTING OPERATING SYSTEM AND PERFORMING UPDATES ###${NORMAL}"
echo -e -n "\n" 
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

### Proceed with the operating system detection logic ###
if [ -n "$RPIVER" ] && [ "$RPIVER" -gt 0 ]; then
    echo "#######################################################################"
    echo "############${BOLD} System detected as Raspberry Pi $RPIVER ${NORMAL}##################"
    echo "#######################################################################"
    echo -e -n "\n" 
    apt update -y && apt upgrade -y
elif [ "$UBUNTU" -gt 0 ]; then
    echo "#######################################################################"
    echo "##################${BOLD} System detected as Ubuntu Linux ${NORMAL}####################"
    echo "#######################################################################"
    echo -e -n "\n" 
    apt update -y && apt upgrade -y
elif [ "$ROCKY" -gt 0 ]; then
    echo "#######################################################################"
    echo "###################${BOLD} System detected as Rocky Linux ${NORMAL}####################"
    echo "#######################################################################"
    echo -e -n "\n" 
    dnf update -y && dnf upgrade -y
else
    echo "#######################################################################"
    echo "#######################################################################"
    echo "#################${BOLD} NOT A SUPPORTED OPERATING SYSTEM ${NORMAL}####################"
    echo "#######################################################################"
    echo "#######################################################################"
    echo -e -n "\n" 
    exit 1
fi
#################################################################
echo -e -n "\n" 
echo "${BOLD}### OPERATING SYSTEM DETECTED AND UPDATES COMPLETED ###${NORMAL}"
echo -e -n "\n" 
if [ -x "$(command -v docker)" ]; then
    echo -e -n "\n" 
    echo "${BOLD}### DOCKER IS ALREADY INSTALLED AND IS READY TO USE ###${NORMAL}"
    echo -e -n "\n" 
    else
        echo "${BOLD}### STARTING DOCKER INSTALL ###${NORMAL}"
        echo -e -n "\n" 
        ### Different installation options for different OS' ###
        if [ -n "$RPIVER" ] && [ "$RPIVER" -lt 5 ]; then
            for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done
            # Add Docker's official GPG key:
            apt-get install ca-certificates curl git -y
            install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/raspbian/gpg -o /etc/apt/keyrings/docker.asc
            chmod a+r /etc/apt/keyrings/docker.asc
            echo \
                "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/raspbian \
                $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
                sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            apt-get update -y
            apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
            systemctl restart docker
            echo -e -n "\n" 
            echo "${BOLD}### DOCKER INSTALLED AND IS READY TO USE ###${NORMAL}"
            echo -e -n "\n" 
        elif [ -n "$RPIVER" ] && [ "$RPIVER" -eq 5 ]; then
            for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done
            # Add Docker's official GPG key:
            apt-get update -y
            apt-get install ca-certificates curl -y
            install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
            chmod a+r /etc/apt/keyrings/docker.asc
            # Add the repository to Apt sources:
            echo \
            "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
            $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
            tee /etc/apt/sources.list.d/docker.list > /dev/null
            apt-get update -y
            apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
            systemctl restart docker
            echo -e -n "\n" 
            echo "${BOLD}### DOCKER INSTALLED AND IS READY TO USE ###${NORMAL}"
            echo -e -n "\n" 
        elif [ "$UBUNTU" -gt 0 ]; then
            for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done
            # Add Docker's official GPG key:
            apt-get update -y
            apt-get install ca-certificates curl -y
            install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
            chmod a+r /etc/apt/keyrings/docker.asc
            # Add the repository to Apt sources:
            echo \
            "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
            $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
            sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            apt-get update -y
            apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
            systemctl restart docker
            echo -e -n "\n" 
            echo "${BOLD}### DOCKER INSTALLED AND IS READY TO USE ###${NORMAL}"
            echo -e -n "\n" 
        elif [ "$ROCKY" -gt 0 ]; then
            dnf remove -y docker-ce docker-ce-cli containerd.io
            rm -rf /var/lib/docker
            rm -rf /var/lib/containerd
            dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
            dnf update -y
            dnf install docker-ce docker-ce-cli containerd.io docker-compose-plugin -y
            systemctl start docker
            systemctl enable docker
            echo -e -n "\n" 
            echo "${BOLD}### INSTALLATION OF DOCKER COMPLETE ###${NORMAL}"
            echo -e -n "\n" 
        else
            echo -e -n "\n" 
            echo "### YOU ARE RUNNING AN UNSUPPORTED OPERATING SYSTEM ###"
            echo -e -n "\n" 
            exit 1
        fi
fi

echo "${BOLD}### INSTALLATION OF DOCKER COMPLETE ###${NORMAL}"
echo -e -n "\n" 

echo "${BOLD}### STARTING PORTAINER INSTALL ###${NORMAL}"
echo -e -n "\n"
### Cleanup potential existing Portainer installs ###
docker stop portainer
docker rm portainer
docker volume rm portainer_data
docker images | grep portainer | awk '{print $3}' | sudo xargs docker rmi -f
docker volume create portainer_data
docker run -d -p 8000:8000 -p 9443:9443 --name portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:2.21.1
echo -e -n "\n"
echo "${BOLD}### PORTAINER INSTALL COMPLETE WITH DEFAULT USERNAME ADMIN ###${NORMAL}"
echo -e -n "\n" 
echo "${BOLD}### STARTING TRAFFGEN INSTALL ###${NORMAL}"
echo -e -n "\n" 
### Cleanup potential existing traffgen installs ###
docker ps | grep jdibby/traffgen | awk '{print $1}' | sudo xargs docker stop
docker ps -a | grep jdibby/traffgen | awk '{print $1}' | sudo xargs docker rm
docker images | grep jdibby/traffgen | awk '{print $3}' | sudo xargs docker rmi -f
docker images| awk '{print $1}' | grep -v REPOSITORY | sudo xargs docker rmi -f
echo -e -n "\n" 
echo "${BOLD}### TRAFFGEN INSTALL COMPLETE ###${NORMAL}"

echo -e -n "\n" 
### Run specific docker images based on Raspberry Pi or not ###
if [ -n "$RPIVER" ] && [ "$RPIVER" -lt 5 ]; then
   docker run --detach --restart unless-stopped jdibby/traffgen:armv7
elif [ "$RPIVER" -eq 5 ]; then
   docker run --detach --restart unless-stopped jdibby/traffgen:armv8
elif [ "$UBUNTU" -gt 0 ]; then
   docker run --detach --restart unless-stopped jdibby/traffgen:amd64
elif [ "$ROCKY" -gt 0 ]; then
   docker run --detach --restart unless-stopped jdibby/traffgen:amd64
fi
#################################################################
echo -e -n "\n"
echo "${BOLD}### TRAFFGEN INSTALL COMPLETE ###${NORMAL}"
echo -e -n "\n"
