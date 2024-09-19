#!/bin/bash

### SET HOME DIRECTORY ###
HOMEDIR=pwd

echo "### UPDATING AND UPGRADING PACKAGES ###"
apt update -y && apt upgrade -y

echo "### INSTALLING DOCKER AND GIT ###"
# Add Docker's official GPG key:
apt-get install ca-certificates curl git
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/raspbian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/raspbian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

echo "### STARTING PORTAINER INSTALL ###"
docker volume create portainer_data
docker run -d -p 8000:8000 -p 9443:9443 --name portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:2.21.1
echo "### PORTAINER INSTALL COMPLETE WITH DEFAULT USERNAME ADMIN ###"

echo "STARTING TRAFFGEN INSTALL ###"
git clone https://github.com/jdibby/traffgen && cd $HOMEDIR/traffgen
docker build -t jdibby/traffgen .
echo "### TRAFFGEN INSTALL COMPLETE ###"

echo "### STARTING TRAFFGEN ###"
docker run --detach --restart unless-stopped jdibby/traffgen:latest
echo "### TRAFFGEN STARTED ###"