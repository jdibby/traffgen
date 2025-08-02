FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Denver

# Set timezone and install core dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata \
    curl \
    wget \
    git \
    ca-certificates \
    build-essential \
    python3 \
    python3-pip \
    python3-dev \
    iputils-ping \
    net-tools \
    netcat-openbsd \
    dnsutils \
    openssh-client \
    nmap \
    snmp \
    snmp-mibs-downloader \
    golang \
    perl \
    libssl-dev \
    libffi-dev \
    libpcap-dev \
    libreadline-dev \
    zlib1g-dev \
    libxml2-dev \
    libxslt1-dev \
    libyaml-dev \
    ruby-full \
    sqlite3 \
    make \
    bash \
    nikto && \
    rm -rf /var/lib/apt/lists/*

# Set timezone
RUN ln -fs /usr/share/zoneinfo/$TZ /etc/localtime && dpkg-reconfigure --frontend noninteractive tzdata

# Install Python packages
RUN pip3 install --break-system-packages fastcli requests colorama beautifulsoup4 tqdm dnspython dnstwist

# Pull latest Nmap NSE scripts
RUN git -c http.sslVerify=false clone https://github.com/nmap/nmap.git /nmap-src && \
    mkdir -p /usr/share/nmap && \
    cp /nmap-src/nse_main.lua /usr/share/nmap/ && \
    cp -r /nmap-src/scripts /usr/share/nmap/ && \
    cp -r /nmap-src/nselib /usr/share/nmap/
ENV NMAPDIR=/usr/share/nmap

# Build and install GoBGP
RUN git -c http.sslVerify=false clone https://github.com/osrg/gobgp.git /tmp/gobgp-src && \
    cd /tmp/gobgp-src && \
    git checkout v3.37.0 && \
    go build -o gobgp ./cmd/gobgp && \
    go build -o gobgpd ./cmd/gobgpd && \
    mv gobgp gobgpd /usr/local/bin/ && \
    cd / && rm -rf /tmp/gobgp-src

# Install Metasploit Framework
RUN git -c http.sslVerify=false clone https://github.com/rapid7/metasploit-framework.git /opt/metasploit-framework && \
    cd /opt/metasploit-framework && \
    gem install bundler -v 2.3.26 && \
    bundle config set --local without 'development test' && \
    bundle install

ENV PATH="/opt/metasploit-framework:$PATH"

# Add your scripts
ADD generator.py ./
ADD endpoints.py ./

# Set Python generator as entrypoint
ENTRYPOINT ["python3", "-u", "generator.py"]
CMD ["--suite=all", "--size=M", "--max-wait-secs=15", "--loop"]
