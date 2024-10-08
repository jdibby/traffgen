#!/bin/bash

### Validate this is being run with sudo / root permissions ###
WHOAREYOU=$(whoami)
if [ "$WHOAREYOU" != "root" ]; then
   echo "### YOU MUST BE ROOT OR SUDO THIS SCRIPT ###"
   exit 1
fi

### Adding capabilities to bold font ###
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

### Set Home Directory ###
HOMEDIR=$(pwd)

echo -e -n "\n" 

echo "${BOLD}### DETECTING OPERATING SYSTEM ###${NORMAL}"

# Check if the file for Raspberry Pi detection exists
if [ -f /proc/device-tree/model ]; then
    RPIVER=$(grep -a "Raspberry" /proc/device-tree/model | awk '{print $3}')
else
    RPIVER=""
    echo "Raspberry Pi detection file not found."
fi

# Check if the file for Ubuntu detection exists
if [ -f /etc/os-release ]; then
    UBUNTU=$(grep 'NAME="Ubuntu"' /etc/os-release | wc -l)
else
    UBUNTU=0
    echo "Ubuntu detection file not found."
fi

# Proceed with the operating system detection logic
if [ -n "$RPIVER" ] && [ "$RPIVER" -gt 0 ]; then
    echo "System detected as a Raspberry Pi $RPIVER"
elif [ "$UBUNTU" -gt 0 ]; then
    echo "System detected as Ubuntu"
else
    echo "Not detected as a Raspberry Pi or Ubuntu"
    exit 1
fi

echo "${BOLD}### OPERATING SYSTEM DETECTED ###${NORMAL}"

echo -e -n "\n" 

echo "${BOLD}### UPDATING AND UPGRADING PACKAGES ###${NORMAL}"
### Update and upgrade packages
apt update -y && apt upgrade -y
echo "${BOLD}### UPDATING AND UPGRADING PACKAGES COMPLETE ###${NORMAL}"

echo -e -n "\n" 

echo "${BOLD}### STARTING DOCKER INSTALL ###${NORMAL}"

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
elif [ -n "$RPIVER" ] && [ "$RPIVER" -eq 5 ]; then
   for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done
   # Add Docker's official GPG key:
   apt-get update
   apt-get install ca-certificates curl
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
elif [ "$UBUNTU" -gt 0 ]; then
   for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done
   # Add Docker's official GPG key:
   apt-get update
   apt-get install ca-certificates curl
   install -m 0755 -d /etc/apt/keyrings
   curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
   chmod a+r /etc/apt/keyrings/docker.asc

   # Add the repository to Apt sources:
   echo \
   "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
   $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
   sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
   apt-get update -y

   apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   systemctl restart docker
else
   echo "### YOU ARE RUNNING AN UNSUPPORTED OPERATING SYSTEM ###"
   exit 1
fi

echo "${BOLD}### INSTALLATION OF DOCKER AND GIT COMPLETE ###${NORMAL}"

echo -e -n "\n" 

echo "${BOLD}### STARTING PORTAINER INSTALL ###${NORMAL}"
### Cleanup potential existing Portainer installs ###
docker stop portainer
docker rm portainer
docker volume rm portainer_data
docker images | grep portainer | awk '{print $3}' | sudo xargs docker rmi -f

docker volume create portainer_data
docker run -d -p 8000:8000 -p 9443:9443 --name portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:2.21.1
echo "${BOLD}### PORTAINER INSTALL COMPLETE WITH DEFAULT USERNAME ADMIN ###${NORMAL}"

echo -e -n "\n" 

echo "${BOLD}### STARTING TRAFFGEN INSTALL ###${NORMAL}"
### Cleanup potential existing traffgen installs ###
docker ps | grep jdibby/traffgen | awk '{print $1}' | sudo xargs docker stop
docker ps -a | grep jdibby/traffgen | awk '{print $1}' | sudo xargs docker rm
docker images | grep jdibby/traffgen | awk '{print $3}' | sudo xargs docker rmi -f
docker images| awk '{print $1}' | grep -v REPOSITORY | sudo xargs docker rmi -f
echo "${BOLD}### TRAFFGEN INSTALL COMPLETE ###${NORMAL}"

### Run specific docker images based on Raspberry Pi or not ###
if [ -n "$RPIVER" ] && [ "$RPIVER" -lt 5 ]; then
   docker run --detach --restart unless-stopped jdibby/traffgen:armv7
elif [ "$RPIVER" -eq 5 ]; then
   docker run --detach --restart unless-stopped jdibby/traffgen:armv8
elif [ "$UBUNTU" -gt 0 ]; then
   docker run --detach --restart unless-stopped jdibby/traffgen:amd64
fi

echo -e -n "\n"
