FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Denver
ENV NOKOGIRI_USE_SYSTEM_LIBRARIES=1

# Set timezone and install core dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata curl wget git ca-certificates \
    iproute2 traceroute iputils-ping net-tools netcat-openbsd dnsutils openssh-client \
    nmap snmp snmp-mibs-downloader \
    golang \
    perl \
    build-essential pkg-config \
    python3 python3-pip python3-dev \
    libssl-dev libffi-dev libpcap-dev libreadline-dev zlib1g-dev \
    libxml2-dev libxslt1-dev libyaml-dev libpq-dev \
    sqlite3 libsqlite3-dev \
    ruby-full \
    make bash \
    nikto \
 && ln -fs /usr/share/zoneinfo/$TZ /etc/localtime \
 && dpkg-reconfigure --frontend noninteractive tzdata

# Python packages
RUN pip3 install --break-system-packages \
      fastcli requests colorama beautifulsoup4 tqdm dnspython dnstwist

# Build and install GoBGP
RUN git -c http.sslVerify=false clone https://github.com/osrg/gobgp.git /tmp/gobgp-src && \
    cd /tmp/gobgp-src && \
    git checkout v3.37.0 && \
    go build -o gobgp ./cmd/gobgp && \
    go build -o gobgpd ./cmd/gobgpd && \
    mv gobgp gobgpd /usr/local/bin/ && \
    cd / && rm -rf /tmp/gobgp-src

# Install Metasploit Framework (check mode only)
RUN git -c http.sslVerify=false clone https://github.com/rapid7/metasploit-framework.git /opt/metasploit-framework && \
    cd /opt/metasploit-framework && \
    gem install bundler -v 2.3.26 && \
    bundle config set --local without 'development test' && \
    bundle install && \
    rm -rf ~/.gem ~/.bundle /root/.bundle /opt/metasploit-framework/vendor/bundle/ruby/*/cache

# Clean up build-time dependencies and cache
RUN apt-get purge -y \
      build-essential libssl-dev libffi-dev libpq-dev libreadline-dev zlib1g-dev \
      libxml2-dev libxslt1-dev libyaml-dev libsqlite3-dev pkg-config \
 && apt-get autoremove -y \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set Metasploit in PATH
ENV PATH="/opt/metasploit-framework:$PATH"

# Copy custom Metasploit RC scripts
COPY metasploit /opt/metasploit-framework/ms_checks/
RUN ls -la /opt/metasploit-framework/ms_checks/

# Workdir and files
WORKDIR /traffgen
COPY generator.py endpoints.py healthcheck.sh ./

# Metasploit RC scripts
COPY metasploit /opt/metasploit-framework/ms_checks/
RUN ls -la /opt/metasploit-framework/ms_checks/

# Healthcheck
RUN chmod +x /traffgen/healthcheck.sh
HEALTHCHECK --interval=10s --timeout=3s --retries=2 CMD /traffgen/healthcheck.sh

# Entrypoint
ENTRYPOINT ["python3", "-u", "/traffgen/generator.py"]
CMD ["--suite=all", "--size=M", "--max-wait-secs=15", "--loop"]
