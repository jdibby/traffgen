FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Denver

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
    gem update --system && \
    gem install bundler && \
    bundle config set --local without 'development test' && \
    NOKOGIRI_USE_SYSTEM_LIBRARIES=1 bundle install && \
    rm -rf ~/.gem ~/.bundle /root/.bundle /opt/metasploit-framework/vendor/bundle/ruby/*/cache

RUN printf '#!/usr/bin/env bash\ncd /opt/metasploit-framework\nexec bundle exec ./msfconsole "$@"\n' > /usr/local/bin/msfconsole && \
    chmod +x /usr/local/bin/msfconsole && \
    printf '#!/usr/bin/env bash\ncd /opt/metasploit-framework\nexec bundle exec ./msfvenom "$@"\n' > /usr/local/bin/msfvenom && \
    chmod +x /usr/local/bin/msfvenom

# Copy your Metasploit RC scripts (once)
COPY metasploit /opt/metasploit-framework/ms_checks/
RUN ls -la /opt/metasploit-framework/ms_checks/ || true

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
