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
    netcat-openbsd \
    tzdata \
    bind-tools \
    wget \
    nmap \
    openssh-client \
    busybox-extras \
    ca-certificates \
    git \
    net-snmp \
    net-snmp-tools \
    go \
    nikto \
    build-base

### Install appropriate python packages as root
RUN pip3 install fastcli requests colorama beautifulsoup4 tqdm dnspython dnstwist --break-system-packages

### Update certs
RUN update-ca-certificates

### Pull down all nmap scripts and NSE libraries for security scanning
RUN git -c http.sslVerify=false clone https://github.com/nmap/nmap.git /nmap-src \
    && mkdir -p /usr/share/nmap \
    && cp /nmap-src/nse_main.lua /usr/share/nmap/ \
    && cp -r /nmap-src/scripts /usr/share/nmap/ \
    && cp -r /nmap-src/nselib /usr/share/nmap/

### Set NMAP directory environment
ENV NMAPDIR=/usr/share/nmap

### Build and install GoBGP v3.37.0 from source
RUN git -c http.sslVerify=false clone https://github.com/osrg/gobgp.git /tmp/gobgp-src \
 && cd /tmp/gobgp-src \
 && git checkout v3.37.0 \
 && go build -o gobgp ./cmd/gobgp \
 && go build -o gobgpd ./cmd/gobgpd \
 && mv gobgp gobgpd /usr/local/bin/ \
 && cd / \
 && rm -rf /tmp/gobgp-src


### Scripts used within the container
ADD generator.py ./
ADD endpoints.py ./

### Set the generator script as the entrypoint of the container
ENTRYPOINT ["python3", "-u", "generator.py"]

### Variables to set for the generator
CMD ["--suite=all", "--size=S", "--max-wait-secs=20", "--loop"]