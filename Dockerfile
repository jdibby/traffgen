FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Denver

# Set timezone and install core dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata \
    curl \
    wget \
    git \
    iproute2 \
    traceroute \
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
    libpq-dev \
    libsqlite3-dev \
    pkg-config \
    ruby-full \
    sqlite3 \
    make \
    bash \
    nikto

# Set timezone
RUN ln -fs /usr/share/zoneinfo/$TZ /etc/localtime && dpkg-reconfigure --frontend noninteractive tzdata

# Python packages
RUN pip3 install --break-system-packages fastcli requests colorama beautifulsoup4 tqdm dnspython dnstwist

# Build and install GoBGP
RUN git -c http.sslVerify=false clone https://github.com/osrg/gobgp.git /tmp/gobgp-src && \
    cd /tmp/gobgp-src && \
    git checkout v3.37.0 && \
    go build -o gobgp ./cmd/gobgp && \
    go build -o gobgpd ./cmd/gobgpd && \
    mv gobgp gobgpd /usr/local/bin/ && \
    cd / && rm -rf /tmp/gobgp-src

# --- Metasploit (vendor-bundled, isolated) ---
# Keep Bundler + gems local to /opt/metasploit-framework/vendor/bundle and force Ruby platform to avoid musl/native mismatch.
ENV BUNDLE_WITHOUT="development test" \
    BUNDLE_PATH="/opt/metasploit-framework/vendor/bundle" \
    BUNDLE_JOBS="4" \
    DISABLE_BOOTSNAP="1"

RUN git -c http.sslVerify=false clone https://github.com/rapid7/metasploit-framework.git /opt/metasploit-framework && \
    cd /opt/metasploit-framework && \
    gem install bundler -v "~>2.5" --no-document && \
    bundle config set --local path "$BUNDLE_PATH" && \
    bundle config set --local without "$BUNDLE_WITHOUT" && \
    bundle config set --local force_ruby_platform true && \
    bundle install --retry=3

# Wrapper scripts to guarantee bundle exec is used
RUN printf '#!/usr/bin/env bash\ncd /opt/metasploit-framework\nexec bundle exec ./msfconsole "$@"\n' > /usr/local/bin/msfconsole && \
    printf '#!/usr/bin/env bash\ncd /opt/metasploit-framework\nexec bundle exec ./msfvenom "$@"\n'   > /usr/local/bin/msfvenom   && \
    chmod +x /usr/local/bin/msfconsole /usr/local/bin/msfvenom

# Clean up build-time dependencies and cache (keep runtime libs and vendor/bundle)
RUN apt-get purge -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    libpq-dev \
    libreadline-dev \
    zlib1g-dev \
    libxml2-dev \
    libxslt1-dev \
    libyaml-dev \
    pkg-config && \
    apt-get autoremove -y && apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set working directory
WORKDIR /traffgen

# Copy project files into /traffgen
COPY generator.py endpoints.py healthcheck.sh ./

# Copy Metasploit RC scripts
COPY metasploit /opt/metasploit-framework/ms_checks/
RUN ls -la /opt/metasploit-framework/ms_checks/

# Healthcheck
RUN chmod +x /traffgen/healthcheck.sh
HEALTHCHECK --interval=10s --timeout=3s --retries=2 CMD /traffgen/healthcheck.sh

# Entrypoint
ENTRYPOINT ["python3", "-u", "/traffgen/generator.py"]
CMD ["--suite=all", "--size=M", "--max-wait-secs=15", "--loop"]
