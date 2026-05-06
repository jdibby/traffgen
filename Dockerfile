# ---------- Stage 1: build GoBGP ----------
# golang:1.26-bookworm fixes 20+ Go stdlib CVEs across crypto/tls, crypto/x509,
#   net/mail, net/url, archive/tar, archive/zip, encoding/asn1, encoding/pem,
#   html/template, and os (CVE-2025-58183 through CVE-2026-32289 series).
FROM golang:1.26-bookworm AS gobgp-build

ARG GOBGP_VERSION=v4.3.0

WORKDIR /tmp/gobgp
# --depth 1 --single-branch fetches only the tagged commit, not the full history
# grpc@v1.79.3  fixes CVE-2026-33186 (gRPC-Go auth bypass via :path)
# x/net@v0.45.0 fixes CVE-2025-22872, CVE-2025-47911, CVE-2025-58190 (html parser DoS/XSS)
RUN git clone --depth 1 --single-branch --branch ${GOBGP_VERSION} \
        https://github.com/osrg/gobgp.git . && \
    go get google.golang.org/grpc@v1.79.3 golang.org/x/net@v0.45.0 && \
    go mod tidy && \
    go build -ldflags="-s -w" -o /tmp/gobgp-bin/gobgp  ./cmd/gobgp  && \
    go build -ldflags="-s -w" -o /tmp/gobgp-bin/gobgpd ./cmd/gobgpd && \
    strip /tmp/gobgp-bin/gobgp /tmp/gobgp-bin/gobgpd

# ---------- Stage 2: build Metasploit (fat builder) ----------
FROM debian:bookworm-slim AS msf-build
ENV DEBIAN_FRONTEND=noninteractive

# Build-time toolchain only — nothing from this layer ships to runtime
RUN apt-get update && apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends \
    ca-certificates git ruby-full build-essential pkg-config \
    libssl-dev libffi-dev libpcap-dev libreadline-dev zlib1g-dev \
    libxml2-dev libxslt1-dev libyaml-dev libpq-dev sqlite3 libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
# --depth 1 skips the full MSF git history (~1 GB uncompressed)
RUN git clone --depth 1 \
        https://github.com/rapid7/metasploit-framework.git metasploit-framework
WORKDIR /opt/metasploit-framework

# Install bundler + vendor gems (no dev/test), small fixes, then aggressive cleanup
RUN gem install --no-document bundler && \
    bundle config set --local without 'development test' && \
    bundle config set --local path '/opt/metasploit-framework/vendor/bundle' && \
    (grep -Eq "^\s*gem ['\"]stringio['\"]" Gemfile && \
       sed -E -i "s|^\s*gem ['\"]stringio['\"].*|gem 'stringio', '3.1.1'|" Gemfile || \
       echo "gem 'stringio', '3.1.1'" >> Gemfile) && \
    (grep -Eq "^\s*gem ['\"]parallel['\"]" Gemfile || echo "gem 'parallel'" >> Gemfile) && \
    NOKOGIRI_USE_SYSTEM_LIBRARIES=1 bundle install --jobs 4 --retry 3 && \
    bundle update --conservative rack rexml webrick json addressable net-imap zlib && \
    bundle clean --force && \
    rm -rf ~/.gem ~/.bundle /root/.bundle vendor/bundle/ruby/*/cache tmp/cache && \
    # Remove default stringio gemspec to avoid duplicate warnings
    find / -name "stringio-3.0.4.gemspec" -delete 2>/dev/null || true

# Aggressive post-install size reduction — everything below is safe for check-only use
RUN \
    # Drop .git — history not needed at runtime (~hundreds of MB)
    rm -rf /opt/metasploit-framework/.git && \
    # Remove MSF module directories not needed for check-only operation
    rm -rf /opt/metasploit-framework/modules/payloads \
           /opt/metasploit-framework/modules/post \
           /opt/metasploit-framework/modules/encoders \
           /opt/metasploit-framework/modules/nops \
           /opt/metasploit-framework/modules/evasion && \
    # Remove documentation, developer tools, and exploit data blobs
    rm -rf /opt/metasploit-framework/documentation \
           /opt/metasploit-framework/tools \
           /opt/metasploit-framework/data/exploits \
           /opt/metasploit-framework/data/meterpreter \
           /opt/metasploit-framework/data/templates && \
    # Strip debug symbols from native extension .so files in the vendor bundle
    find /opt/metasploit-framework/vendor/bundle -name "*.so" \
         -exec strip --strip-debug {} \; 2>/dev/null || true && \
    # Remove gem spec/test directories (not needed at runtime)
    find /opt/metasploit-framework/vendor/bundle -type d \
         \( -name spec -o -name test -o -name tests -o -name "test-unit" \) \
         -exec rm -rf {} + 2>/dev/null || true && \
    # Remove C/C++ source and build artefacts used only during gem compilation
    find /opt/metasploit-framework/vendor/bundle -name "*.c"       -delete 2>/dev/null; \
    find /opt/metasploit-framework/vendor/bundle -name "*.h"       -delete 2>/dev/null; \
    find /opt/metasploit-framework/vendor/bundle -name "Makefile"  -delete 2>/dev/null || true && \
    # Remove cached .gem archives (already installed, wasting space)
    find /opt/metasploit-framework/vendor/bundle -name "*.gem"     -delete 2>/dev/null || true && \
    # Remove Ruby ri documentation from vendor bundle
    find /opt/metasploit-framework/vendor/bundle -type d -name "ri" \
         -exec rm -rf {} + 2>/dev/null || true

# ---------- Stage 3: runtime ----------
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Denver
ENV BUNDLE_GEMFILE=/opt/metasploit-framework/Gemfile
ENV BUNDLE_PATH=/opt/metasploit-framework/vendor/bundle
ENV BUNDLE_WITHOUT=development:test

# Core runtime deps only — no dev headers, no build tools
RUN apt-get update && apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends \
    tzdata ca-certificates curl git \
    iproute2 traceroute iputils-ping netcat-openbsd dnsutils openssh-client \
    nmap snmp openssl procps \
    perl python3 python3-pip sqlite3 ruby bash \
  && ln -fs /usr/share/zoneinfo/$TZ /etc/localtime \
  && echo "$TZ" > /etc/timezone \
  && rm -rf /var/lib/apt/lists/*

ARG NIKTO_VERSION=2.1.6

# nikto is not in Debian repos — install from upstream (Perl script, no extra deps)
RUN git clone --depth 1 --branch ${NIKTO_VERSION} \
        https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# Bundler + CVE-patched gems. json has a C extension so build tools are
# required; install and purge them in the same layer to keep image size down.
# Gems covered: json (CVE-2026-33210), rexml (CVE-2024-35176 through -49761),
# erb (CVE-2026-41316), webrick (CVE-2024-47220, CVE-2025-6442),
# rack (CVE-2025-61780 through CVE-2026-34831, 13 CVEs),
# uri (CVE-2023-28755, CVE-2023-36617), time (CVE-2023-28756),
# cgi (CVE-2025-27219, CVE-2025-27220), resolv (CVE-2025-24294),
# net-imap (CVE-2025-43857, CVE-2026-42256, CVE-2026-42258),
# addressable (CVE-2026-35611)
RUN apt-get update && \
    apt-get install -y --no-install-recommends ruby-dev build-essential && \
    gem install --no-document \
      bundler json rexml erb webrick rack uri time cgi resolv net-imap addressable && \
    apt-get purge -y --auto-remove ruby-dev build-essential && \
    rm -rf /var/lib/apt/lists/*

# Python packages — versions pinned for reproducibility
# pip>=26.1          CVE-2023-5752 (Mercurial cmd injection), CVE-2025-8869
#                    (symlink traversal), CVE-2026-3219, CVE-2026-6357
# setuptools>=78.1.1 CVE-2024-6345 (RCE via crafted URLs), CVE-2025-47273
#                    (path traversal in PackageIndex.download)
RUN pip3 install --no-cache-dir --break-system-packages "pip>=26.1" && \
    pip3 install --no-cache-dir --break-system-packages \
      "setuptools>=78.1.1" \
      fastcli \
      "flask==3.1.3" \
      "requests==2.33.1" \
      "beautifulsoup4==4.14.3" \
      "dnspython==2.8.0" \
      "dnstwist==20250130" \
      "rich==15.0.0" && \
    find /usr -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# Remove static/libtool artefacts BEFORE copying Metasploit so the find
# does not traverse the large vendor tree unnecessarily
RUN find /usr -name '*.a' -o -name '*.la' -o -name '*.o' | xargs -r rm -f

# Copy stripped GoBGP binaries from build stage
COPY --from=gobgp-build /tmp/gobgp-bin/gobgp  /usr/local/bin/gobgp
COPY --from=gobgp-build /tmp/gobgp-bin/gobgpd /usr/local/bin/gobgpd

# Copy Metasploit framework (with vendor bundle) from builder
COPY --from=msf-build /opt/metasploit-framework /opt/metasploit-framework

# Kill duplicate default stringio warning in runtime (path varies by Ruby version)
RUN find / -name "stringio-3.0.4.gemspec" -delete || true

# Wrappers for msfconsole/msfvenom that run under bundler context
RUN printf '#!/usr/bin/env bash\nexport BUNDLE_GEMFILE=/opt/metasploit-framework/Gemfile\nexport BUNDLE_PATH=/opt/metasploit-framework/vendor/bundle\nexport BUNDLE_WITHOUT=development:test\ncd /opt/metasploit-framework\nexec bundle exec ./msfconsole "$@"\n' > /usr/local/bin/msfconsole && \
    printf '#!/usr/bin/env bash\nexport BUNDLE_GEMFILE=/opt/metasploit-framework/Gemfile\nexport BUNDLE_PATH=/opt/metasploit-framework/vendor/bundle\nexport BUNDLE_WITHOUT=development:test\ncd /opt/metasploit-framework\nexec bundle exec ./msfvenom "$@"\n' > /usr/local/bin/msfvenom && \
    chmod +x /usr/local/bin/msfconsole /usr/local/bin/msfvenom

# Point Python's requests library and ssl module at the system CA bundle so
# injected TLS-inspection proxy CAs are picked up automatically at startup.
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# App files
WORKDIR /traffgen
COPY generator.py endpoints.py webui.py healthcheck.sh docker-entrypoint.sh ./
RUN chmod +x /traffgen/docker-entrypoint.sh

# Ensure checks dir exists; copy RC scripts; move targets.list up one level
RUN mkdir -p /opt/metasploit-framework/ms_checks/checks
COPY metasploit/checks/ /opt/metasploit-framework/ms_checks/checks/
RUN mv /opt/metasploit-framework/ms_checks/checks/targets.list \
      /opt/metasploit-framework/ms_checks/targets.list

# Healthcheck
RUN chmod +x /traffgen/healthcheck.sh
HEALTHCHECK --interval=20s --timeout=3s --start-period=120s --retries=3 CMD /traffgen/healthcheck.sh

# Final cleanup — docs, manpages, locale data, caches, i18n tables,
# games/pixmaps, Python .pyc files, Ruby rdoc cache
RUN rm -rf \
      /usr/share/doc \
      /usr/share/man \
      /usr/share/man-db \
      /usr/share/locale \
      /usr/share/i18n \
      /usr/share/games \
      /usr/share/pixmaps \
      /var/cache/* \
      /root/.cache && \
    find /usr -name '*.pyc' -delete 2>/dev/null || true && \
    find /usr -type d -name rdoc -exec rm -rf {} + 2>/dev/null || true

# Entrypoint — installs any custom CA certs before launching the generator.
# Bind-mount a .crt file or pass EXTRA_CA_CERT env var to inject a CA.
EXPOSE 7777

ENTRYPOINT ["/traffgen/docker-entrypoint.sh"]
CMD ["--suite=all", "--size=S", "--max-wait-secs=20", "--loop"]
