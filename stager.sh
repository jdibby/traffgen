#!/bin/bash

### PLACE IN HOME DIR OF RPI ###
### Run "sudo su"            ###
### Run "chmod 755 stager.sh ###
### Run "./stager.sh         ###

WHOAREYOU=`whoami`
if [ $WHOAREYOU != root ]; then
   echo "### YOU MUST BE ROOT TO RUN THIS SCRIPT ###"
   exit
fi

### Create Bold and Normal Font Style ###
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

### SET HOME DIRECTORY ###
HOMEDIR=`pwd`

echo -e -n "\n" 

echo "${BOLD}### UPDATING AND UPGRADING PACKAGES ###${NORMAL}"
apt update -y && apt upgrade -y
echo "${BOLD}### UPDATING AND UPGRADING PACKAGES COMPLETE ###${NORMAL}"

echo -e -n "\n" 

echo "${BOLD}### STARTING DOCKER AND GIT INSTALL ###${NORMAL}"
# Add Docker's official GPG key:
apt-get install ca-certificates curl git
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/raspbian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/raspbian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -y

apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
echo "${BOLD}### INSTALLATION OF DOCKER AND GIT COMPLETE ###${NORMAL}"

echo -e -n "\n" 

echo "${BOLD}### STARTING PORTAINER INSTALL ###${NORMAL}"
### Cleanup potential existing Portainer installs ###
docker stop portainer
docker rm portainer
docker volume rm portainer_data
docker images | grep portainer | awk '{print $3}' | xargs docker rmi

docker volume create portainer_data
docker run -d -p 8000:8000 -p 9443:9443 --name portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:2.21.1
echo "${BOLD}### PORTAINER INSTALL COMPLETE WITH DEFAULT USERNAME ADMIN ###${NORMAL}"

echo -e -n "\n" 

#echo "${BOLD}### STARTING TRAFFGEN INSTALL ###${NORMAL}"
echo "${BOLD}### STARTING TRAFFGEN CLEANUP ###${NORMAL}"
### Cleanup potential existing traffgen installs ###
docker ps | grep jdibby/traffgen | awk '{print $1}' | xargs docker stop
rm -rf $HOMEDIR/traffgen/

#git clone https://github.com/jdibby/traffgen
#cd $HOMEDIR/traffgen/
#docker build -t jdibby/traffgen $HOMEDIR/traffgen/.
#echo "${BOLD}### TRAFFGEN INSTALL COMPLETE ###${NORMAL}"
echo "${BOLD}### TRAFFGEN CLEANUP COMPLETE ###${NORMAL}"

echo -e -n "\n" 

echo "${BOLD}### STARTING TRAFFGEN ###${NORMAL}"
docker run --detach --restart unless-stopped jdibby/traffgen:latest
echo "${BOLD}### TRAFFGEN STARTED ###${NORMAL}"

echo -e -n "\n" 

echo "${BOLD}### FINAL CLEANUP STARTED ###${NORMAL}"
rm -rf $HOMEDIR/traffgen
rm -rf $HOMEDIR/stager.sh
echo "${BOLD}### FINAL CLEANUP COMPLETE ###${NORMAL}"

echo -e -n "\n" 
