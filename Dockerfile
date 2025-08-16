# --------------------
# Stage 1: Build GoBGP
# --------------------
FROM golang:1.22 AS gobgp-build

WORKDIR /src
RUN git -c http.sslVerify=false clone https://github.com/osrg/gobgp.git . && \
    git checkout v3.37.0 && \
    go build -o gobgp ./cmd/gobgp && \
    go build -o gobgpd ./cmd/gobgpd

# ------------------------
# Stage 2: Main Traffgen + Metasploit
# ------------------------
FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Denver

# Core packages (no snmp-mibs-downloader anymore)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata curl wget git ca-certificates \
    iproute2 traceroute iputils-ping net-tools netcat-openbsd dnsutils openssh-client \
    nmap snmp \
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
 && rm -rf /var/lib/apt/lists/*

# Set timezone
RUN ln -fs /usr/share/zoneinfo/$TZ /etc/localtime && dpkg-reconfigure --frontend noninteractive tzdata

# Python packages
RUN pip3 install --break-system-packages \
      fastcli requests colorama beautifulsoup4 tqdm dnspython dnstwist

# Copy GoBGP from builder stage
COPY --from=gobgp-build /src/gobgp /usr/local/bin/gobgp
COPY --from=gobgp-build /src/gobgpd /usr/local/bin/gobgpd

# --- Metasploit install ---
RUN git -c http.sslVerify=false clone https://github.com/rapid7/metasploit-framework.git /opt/metasploit-framework

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

WORKDIR /opt/metasploit-framework
RUN gem install bundler && \
    bundle config set --local without 'development test' && \
    bundle config set --local path 'vendor/bundle' && \
    # Fix for stringio duplication
    if grep -Eq "^\s*gem ['\"]stringio['\"]" Gemfile; then \
      sed -E -i "s|^\s*gem ['\"]stringio['\"].*|gem 'stringio', '3.1.1'|" Gemfile; \
    else \
      echo "gem 'stringio', '3.1.1'" >> Gemfile; \
    fi && \
    # Ensure 'parallel' is declared
    if ! grep -Eq "^\s*gem ['\"]parallel['\"]" Gemfile; then \
      echo "gem 'parallel'" >> Gemfile; \
    fi && \
    NOKOGIRI_USE_SYSTEM_LIBRARIES=1 bundle install --jobs 4 --retry 3 && \
    bundle exec ruby -e 'require "parallel"' && \
    bundle clean --force && \
    rm -rf ~/.gem ~/.bundle /root/.bundle vendor/bundle/ruby/*/cache tmp/cache && \
    rm -f /usr/lib/ruby/gems/*/specifications/default/stringio-*.gemspec || true && \
    # Wrappers
    printf '#!/usr/bin/env bash\ncd /opt/metasploit-framework\nexec bundle exec ./msfconsole "$@"\n' > /usr/local/bin/msfconsole && \
    chmod +x /usr/local/bin/msfconsole && \
    printf '#!/usr/bin/env bash\ncd /opt/metasploit-framework\nexec bundle exec ./msfvenom "$@"\n' > /usr/local/bin/msfvenom && \
    chmod +x /usr/local/bin/msfvenom

# Smoke test
RUN /usr/local/bin/msfconsole -q -x 'version; exit'

# Copy Metasploit RC scripts + targets
COPY metasploit/checks /opt/metasploit-framework/ms_checks/checks
RUN mv /opt/metasploit-framework/ms_checks/checks/targets.list \
       /opt/metasploit-framework/ms_checks/targets.list

# Workdir and files
WORKDIR /traffgen
COPY generator.py endpoints.py healthcheck.sh ./

# Healthcheck
RUN chmod +x /traffgen/healthcheck.sh
HEALTHCHECK --interval=10s --timeout=3s --retries=2 CMD /traffgen/healthcheck.sh

# Entrypoint
ENTRYPOINT ["python3", "-u", "/traffgen/generator.py"]
CMD ["--suite=all", "--size=M", "--max-wait-secs=15", "--loop"]
