FROM alpine:latest

### Set timezone environment variable
ENV TZ=America/Denver

### Set timezone
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

### Update packages and install appropriate packages and do not cache the index to save on storage
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    musl-dev \
    libc-dev \
    python3-dev \
    iputils-ping \
    net-tools \
    gcc \
    curl \
    chrony \
    tzdata \
    bind-tools \
    wget \
    nmap \
    openssh-client \
    busybox-extras \
    ca-certificates \
    git \
    net-snmp

### Install appropriate python packages as root
RUN pip3 install fastcli requests colorama beautifulsoup4 tqdm --break-system-packages

### Pull down all nmap scripts and nse libraries for security scanning
RUN git clone https://github.com/nmap/nmap.git /nmap-src \
 && mkdir -p /usr/share/nmap \
 && cp /nmap-src/nse_main.lua /usr/share/nmap/ \
 && cp -r /nmap-src/scripts /usr/share/nmap/ \
 && cp -r /nmap-src/nselib /usr/share/nmap/

### Set NMAP directory environment
ENV NMAPDIR=/usr/share/nmap

### Pull down latest github data for building the container image
ADD https://raw.githubusercontent.com/jdibby/traffgen/main/generator.py ./
ADD https://raw.githubusercontent.com/jdibby/traffgen/main/endpoints.py ./

### Set the generatory script as the entrypoint of the container
ENTRYPOINT ["python3", "generator.py"]

### Variables to set for the generator
CMD ["--suite=all", "--size=S", "--max-wait-secs=3", "--loop"]