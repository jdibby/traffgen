# ---------- Stage 1: build GoBGP ----------
FROM ubuntu:24.04 AS gobgp-build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git golang build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/gobgp
RUN git -c http.sslVerify=false clone https://github.com/osrg/gobgp.git . && \
    git checkout v3.37.0 && \
    go build -ldflags="-s -w" -o /tmp/gobgp-bin/gobgp ./cmd/gobgp && \
    go build -ldflags="-s -w" -o /tmp/gobgp-bin/gobgpd ./cmd/gobgpd && \
    strip /tmp/gobgp-bin/gobgp /tmp/gobgp-bin/gobgpd


# ---------- Stage 2: build Metasploit ----------
FROM ubuntu:24.04 AS msf-build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git ruby-full build-essential pkg-config \
    libssl-dev libffi-dev libpcap-dev libreadline-dev zlib1g-dev \
    libxml2-dev libxslt1-dev libyaml-dev libpq-dev \
    sqlite3 libsqlite3-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git -c http.sslVerify=false clone https://github.com/rapid7/metasploit-framework.git metasploit-framework
WORKDIR /opt/metasploit-framework

# Install bundler + gems
RUN gem install --no-document bundler && \
    bundle config set --local without 'development test' && \
    bundle config set --local path 'vendor/bundle' && \
    # Pin fixes
    (grep -Eq "^\s*gem ['\"]stringio['\"]" Gemfile && \
       sed -E -i "s|^\s*gem ['\"]stringio['\"].*|gem 'stringio', '3.1.1'|" Gemfile || \
       echo "gem 'stringio', '3.1.1'" >> Gemfile) && \
    (grep -Eq "^\s*gem ['\"]parallel['\"]" Gemfile || echo "gem 'parallel'" >> Gemfile) && \
    NOKOGIRI_USE_SYSTEM_LIBRARIES=1 bundle install --jobs 4 --retry 3 && \
    bundle clean --force && \
    rm -rf ~/.gem ~/.bundle /root/.bundle vendor/bundle/ruby/*/cache tmp/cache

# ---------- Stage 3: runtime ----------
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Denver

# Core runtime deps only (no compilers, no golang, no ruby-full)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata ca-certificates curl wget git \
    iproute2 traceroute iputils-ping net-tools netcat-openbsd dnsutils openssh-client \
    nmap snmp snmp-mibs-downloader \
    perl python3 python3-pip \
    sqlite3 ruby make bash nikto && \
    ln -fs /usr/share/zoneinfo/$TZ /etc/localtime && \
    dpkg-reconfigure --frontend noninteractive tzdata && \
    rm -rf /var/lib/apt/lists/*

# Python packages
RUN pip3 install --no-cache-dir --break-system-packages \
      fastcli requests colorama beautifulsoup4 tqdm dnspython dnstwist

# Copy stripped GoBGP binaries
COPY --from=gobgp-build /tmp/gobgp-bin/gobgp /usr/local/bin/gobgp
COPY --from=gobgp-build /tmp/gobgp-bin/gobgpd /usr/local/bin/gobgpd

# Copy Metasploit from builder
COPY --from=msf-build /opt/metasploit-framework /opt/metasploit-framework

# Wrappers for msfconsole/msfvenom
RUN printf '#!/usr/bin/env bash\ncd /opt/metasploit-framework\nexec bundle exec ./msfconsole "$@"\n' > /usr/local/bin/msfconsole && \
    printf '#!/usr/bin/env bash\ncd /opt/metasploit-framework\nexec bundle exec ./msfvenom "$@"\n' > /usr/local/bin/msfvenom && \
    chmod +x /usr/local/bin/msfconsole /usr/local/bin/msfvenom

# Workdir and files
WORKDIR /traffgen
COPY generator.py endpoints.py healthcheck.sh ./
COPY metasploit /opt/metasploit-framework/ms_checks/

# Healthcheck
RUN chmod +x /traffgen/healthcheck.sh
HEALTHCHECK --interval=10s --timeout=3s --retries=2 CMD /traffgen/healthcheck.sh

ENTRYPOINT ["python3", "-u", "/traffgen/generator.py"]
CMD ["--suite=all", "--size=M", "--max-wait-secs=15", "--loop"]
