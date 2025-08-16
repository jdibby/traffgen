# ---------- Stage 1: build GoBGP (keep Go 1.22) ----------
FROM golang:1.22 AS gobgp-build

WORKDIR /src
RUN git -c http.sslVerify=false clone https://github.com/osrg/gobgp.git . && \
    git checkout v3.36.0 && \
    go build -ldflags="-s -w" -o gobgp  ./cmd/gobgp  && \
    go build -ldflags="-s -w" -o gobgpd ./cmd/gobgpd

# ---------- Stage 2: build Metasploit (fat builder) ----------
FROM ubuntu:24.04 AS msf-build
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git ruby-full build-essential pkg-config \
    libssl-dev libffi-dev libpcap-dev libreadline-dev zlib1g-dev \
    libxml2-dev libxslt1-dev libyaml-dev libpq-dev sqlite3 libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git -c http.sslVerify=false clone https://github.com/rapid7/metasploit-framework.git metasploit-framework
WORKDIR /opt/metasploit-framework

# Install bundler + vendor gems (no dev/test), small pin fixes
RUN gem install --no-document bundler && \
    bundle config set --local without 'development test' && \
    bundle config set --local path 'vendor/bundle' && \
    (grep -Eq "^\s*gem ['\"]stringio['\"]" Gemfile && \
       sed -E -i "s|^\s*gem ['\"]stringio['\"].*|gem 'stringio', '3.1.1'|" Gemfile || \
       echo "gem 'stringio', '3.1.1'" >> Gemfile) && \
    (grep -Eq "^\s*gem ['\"]parallel['\"]" Gemfile || echo "gem 'parallel'" >> Gemfile) && \
    NOKOGIRI_USE_SYSTEM_LIBRARIES=1 bundle install --jobs 4 --retry 3 && \
    bundle clean --force && \
    rm -rf ~/.gem ~/.bundle /root/.bundle vendor/bundle/ruby/*/cache tmp/cache && \
    # Remove default stringio gemspec in this stage to avoid duplicate warnings
    find / -name "stringio-3.0.4.gemspec" -delete || true

# Optional early smoke test (non-fatal)
RUN bundle exec ./msfconsole -q -x 'version; exit' || true

# ---------- Stage 3: runtime (slim) ----------
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Denver

# Core runtime deps only (no dev toolchains, no MIBs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata ca-certificates curl wget git \
    iproute2 traceroute iputils-ping net-tools netcat-openbsd dnsutils openssh-client \
    nmap snmp \
    perl python3 python3-pip sqlite3 ruby make bash nikto \
  && ln -fs /usr/share/zoneinfo/$TZ /etc/localtime \
  && dpkg-reconfigure --frontend noninteractive tzdata \
  && rm -rf /var/lib/apt/lists/*

# Install Bundler in runtime so wrappers can call `bundle exec`
RUN gem install --no-document bundler

# Python packages (no cache)
RUN pip3 install --no-cache-dir --break-system-packages \
      fastcli requests colorama beautifulsoup4 tqdm dnspython dnstwist

# Copy stripped GoBGP binaries
COPY --from=gobgp-build /src/gobgp  /usr/local/bin/gobgp
COPY --from=gobgp-build /src/gobgpd /usr/local/bin/gobgpd

# Copy Metasploit framework (with vendor bundle) from builder
COPY --from=msf-build /opt/metasploit-framework /opt/metasploit-framework

# Kill duplicate default stringio warning in runtime too (path varies across images)
RUN find / -name "stringio-3.0.4.gemspec" -delete || true

# Wrappers for msfconsole/msfvenom under bundler
RUN printf '#!/usr/bin/env bash\ncd /opt/metasploit-framework\nexec bundle exec ./msfconsole "$@"\n' > /usr/local/bin/msfconsole && \
    printf '#!/usr/bin/env bash\ncd /opt/metasploit-framework\nexec bundle exec ./msfvenom "$@"\n'   > /usr/local/bin/msfvenom && \
    chmod +x /usr/local/bin/msfconsole /usr/local/bin/msfvenom

# App files
WORKDIR /traffgen
COPY generator.py endpoints.py healthcheck.sh ./

# Ensure checks dir exists; copy RC scripts; move targets.list up one level
RUN mkdir -p /opt/metasploit-framework/ms_checks/checks
COPY metasploit/checks/ /opt/metasploit-framework/ms_checks/checks/
RUN mv /opt/metasploit-framework/ms_checks/checks/targets.list \
      /opt/metasploit-framework/ms_checks/targets.list

# Healthcheck
RUN chmod +x /traffgen/healthcheck.sh
HEALTHCHECK --interval=10s --timeout=3s --retries=2 CMD /traffgen/healthcheck.sh

# Final cleanup (docs, manpage
