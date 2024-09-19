#!/bin/bash

echo "### UPDATING AND UPGRADING PACKAGES ###"
apt update -y && apt upgrade -y

echo "### INSTALLING DOCKER AND GIT ###"
apt install docker-ce git -y

echo "### STARTING PORTAINER INSTALL ###"
docker volume create portainer_data
docker run -d -p 8000:8000 -p 9443:9443 --name portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:2.21.1
echo "### PORTAINER INSTALL COMPLETE ###"

echo "STARTING TRAFFGEN INSTALL ###"
git clone https://github.com/jdibby/traffgen && cd traffgen
docker build -t jdibby/traffgen .
echo "### TRAFFGEN INSTALL COMPLETE ###"

echo "### STARTING TRAFFGEN ###"
docker run --detach --restart unless-stopped jdibby/traffgen:latest
echo "### TRAFFGEN STARTED ###"
