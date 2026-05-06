# ---------- Stage 1: build GoBGP ----------
# golang:1.26-bookworm fixes 20+ Go stdlib CVEs across crypto/tls, crypto/x509,
#   net/mail, net/url, archive/tar, archive/zip, encoding/asn1, encoding/pem,
#   html/template, and os (CVE-2025-58183 through CVE-2026-32289 series).
FROM golang:1.26-bookworm AS gobgp-build

ARG GOBGP_VERSION=v4.3.0

WORKDIR /tmp/gobgp
# --depth 1 --single-branch fetches only the tagged commit, not the full history
# grpc@v1.79.3  fixes CVE-2026-33186 (gRPC-Go auth bypass via :path)
# x/net@v0.48.0 fixes CVE-2025-22872, CVE-2025-47911, CVE-2025-58190 (html parser DoS/XSS)
#   (grpc v1.79.3 itself requires x/net >= v0.48.0; using v0.45.0 causes MVS conflicts)
RUN git clone --depth 1 --single-branch --branch ${GOBGP_VERSION} \
        https://github.com/osrg/gobgp.git . && \
    go get google.golang.org/grpc@v1.79.3 golang.org/x/net@v0.48.0 && \
    go mod tidy && \
    go build -ldflags="-s -w" -o /tmp/gobgp-bin/gobgp  ./cmd/gobgp  && \
    go build -ldflags="-s -w" -o /tmp/gobgp-bin/gobgpd ./cmd/gobgpd && \
    strip /tmp/gobgp-bin/gobgp /tmp/gobgp-bin/gobgpd

# ---------- Stage 2: pre-built Metasploit base ----------
# Rebuilt separately via .github/workflows/msf-base-publish.yml whenever
# the Metasploit version or gem set changes.  Pulling this image is fast;
# the 15-25 min bundle-install cost only runs during an msf-base rebuild.
# COPY --from=msf-build below pulls only /opt/metasploit-framework.
FROM jdibby/msf-base:latest AS msf-build

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
      "httpx[http3]" \
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
