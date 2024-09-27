#!/bin/bash

### Validate this is being run with sudo / root permissions ###
WHOAREYOU=`whoami`
if [ $WHOAREYOU != root ]; then
   echo "### YOU MUST BE SUDO THIS SCRIPT ###"
   exit
fi

### Adding capabilities to bold font ###
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

### Set Home Directory ###
HOMEDIR=`pwd`

echo -e -n "\n" 

echo "${BOLD}### DETECING OPERATING SYSTEM ###${NORMAL}"
### Detect if it is an Raspberry Pi or Not ###
#!/bin/bash
if grep -q -i raspbian /etc/issue 2>/dev/null
   then
      ISRPI=Y
      echo "System detected as a Raspberry Pi"
    else
      ISRPI=N
      echo "System is NOT a Raspberry Pi"
fi
echo "${BOLD}### OPERATING SYSTEM DETECTED ###${NORMAL}"

echo -e -n "\n" 

echo "${BOLD}### UPDATING AND UPGRADING PACKAGES ###${NORMAL}"
### Update and upgrade packages
apt update -y && apt upgrade -y
echo "${BOLD}### UPDATING AND UPGRADING PACKAGES COMPLETE ###${NORMAL}"

echo -e -n "\n" 

echo "${BOLD}### STARTING DOCKER AND GIT INSTALL ###${NORMAL}"

if [ $ISRPI = "Y" ];
   then
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
      sudo apt-get update -y

      apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
      systemctl restart docker
else
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
     tee /etc/apt/sources.list.d/docker.list > /dev/null
   apt-get update -y

   sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
   systemctl restart docker

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
#!/bin/bash
if [ $ISRPI = "Y" ];
   then
      docker run --detach --restart unless-stopped jdibby/traffgen:rpi
   else
      docker run --detach --restart unless-stopped jdibby/traffgen:amd64
fi

echo -e -n "\n"

echo "${BOLD}### FINAL CLEANUP STARTED ###${NORMAL}"
#rm -rf $HOMEDIR/stager.sh
echo "${BOLD}### FINAL CLEANUP COMPLETE ###${NORMAL}"

echo -e -n "\n"
