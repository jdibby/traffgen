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
    ruby-full \
    sqlite3 \
    make \
    bash \
    nikto && \
    ln -fs /usr/share/zoneinfo/$TZ /etc/localtime && \
    dpkg-reconfigure --frontend noninteractive tzdata

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

# ---------- Metasploit: deterministic vendor bundle + sandboxed wrappers ----------
ENV BUNDLE_WITHOUT="development test" \
    BUNDLE_JOBS="4" \
    DISABLE_BOOTSNAP="1"

RUN git -c http.sslVerify=false clone https://github.com/rapid7/metasploit-framework.git /opt/metasploit-framework && \
    cd /opt/metasploit-framework && \
    gem install bundler -v "~>2.5" --no-document && \
    bundle config set --local path "/opt/metasploit-framework/vendor/bundle" && \
    bundle config set --local without "$BUNDLE_WITHOUT" && \
    bundle config set --local force_ruby_platform true && \
    bundle config set --local deployment true && \
    bundle lock --add-platform x86_64-linux && \
    bundle install --retry=3 && \
    # (Optional) silence the stringio warning globally; harmless to skip
    gem cleanup stringio || true

# Wrapper scripts that isolate gems to vendor/bundle and force bundle exec
RUN bash -lc 'cat > /usr/local/bin/msfconsole << "EOF"\n\
#!/usr/bin/env bash\n\
set -euo pipefail\n\
cd /opt/metasploit-framework\n\
export DISABLE_BOOTSNAP=1\n\
ruby_ver="$(ruby -e '\''print RbConfig::CONFIG[\"ruby_version\"]'\'')"\n\
export GEM_HOME="/opt/metasploit-framework/vendor/bundle/ruby/${ruby_ver}"\n\
export GEM_PATH="$GEM_HOME"\n\
exec bundle exec ./msfconsole "$@"\n\
EOF\n\
chmod +x /usr/local/bin/msfconsole\n\
cat > /usr/local/bin/msfvenom << "EOF"\n\
#!/usr/bin/env bash\n\
set -euo pipefail\n\
cd /opt/metasploit-framework\n\
export DISABLE_BOOTSNAP=1\n\
ruby_ver="$(ruby -e '\''print RbConfig::CONFIG[\"ruby_version\"]'\'')"\n\
export GEM_HOME="/opt/metasploit-framework/vendor/bundle/ruby/${ruby_ver}"\n\
export GEM_PATH="$GEM_HOME"\n\
exec bundle exec ./msfvenom "$@"\n\
EOF\n\
chmod +x /usr/local/bin/msfvenom'

# ---------- End Metasploit block ----------

# Clean up build-time dependencies and cache
RUN apt-get purge -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    libpq-dev \
    libreadline-dev \
    zlib1g-dev \
    libxml2-dev \
    libxslt1-dev \
    libyaml-dev && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# IMPORTANT: do NOT prepend /opt/metasploit-framework to PATH (we use wrappers)
/* no ENV PATH line here on purpose */

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
