#!/bin/bash
set -e

# Install custom CA certificates before launching the generator so every tool
# in the container (Ruby/Metasploit, openssl s_client, curl, Go) trusts them.
#
# TLS-inspection proxies re-sign intercepted HTTPS connections with their own
# CA certificate.  Install that CA here and all outbound connections through
# the proxy will verify cleanly.
#
# ── How to inject the CA ──────────────────────────────────────────────────────
#
#   Option 1 — bind-mount a PEM/CRT file (recommended):
#     docker run \
#       -v /path/to/proxy-ca.crt:/usr/local/share/ca-certificates/proxy-ca.crt \
#       jdibby/traffgen:latest
#
#   Option 2 — inline PEM via environment variable (useful for secrets managers
#              or Kubernetes secrets):
#     docker run -e EXTRA_CA_CERT="$(cat proxy-ca.crt)" jdibby/traffgen:latest
#
#   Option 3 — fully automatic (no configuration required):
#     Just run the container.  The entrypoint probes a known HTTPS host and, if
#     a TLS-inspection proxy is detected, extracts its root CA from the presented
#     certificate chain and installs it automatically.
#
# All options can be combined.  Manual certs (Options 1 & 2) are installed first
# so that if they cover the proxy, the auto-probe (Option 3) sees a clean chain
# and skips redundant work.
# ─────────────────────────────────────────────────────────────────────────────

CERT_DIR=/usr/local/share/ca-certificates
UPDATED=0

# ── Option 1: .crt files bind-mounted into the system cert directory ──────────
if ls "$CERT_DIR"/*.crt 1>/dev/null 2>&1; then
    echo "[entrypoint] Installing custom CA certificate(s) from ${CERT_DIR}/ ..."
    update-ca-certificates 2>&1 | grep -v "^$" || true
    UPDATED=1
fi

# ── Option 2: inline PEM passed as EXTRA_CA_CERT environment variable ─────────
if [ -n "${EXTRA_CA_CERT:-}" ]; then
    echo "[entrypoint] Installing CA certificate from EXTRA_CA_CERT env var..."
    echo "$EXTRA_CA_CERT" > "$CERT_DIR/extra-ca.crt"
    update-ca-certificates 2>&1 | grep -v "^$" || true
    UPDATED=1
fi

# ── Option 3: auto-detect TLS interception and extract the proxy CA ───────────
#
# Probes a set of well-known HTTPS hosts.  If the certificate chain presented
# by the network fails verification against the current trust store (i.e. a
# proxy is re-signing connections), we walk the presented chain looking for a
# CA certificate that is not yet trusted, save it, and run update-ca-certificates.
#
# This covers Cato Networks, Prisma Access, Palo Alto, Zscaler, Netskope, and
# any other inline-inspection platform that injects its own root CA.
auto_trust_proxy_ca() {
    local AUTO_CA="${CERT_DIR}/auto-proxy-ca.crt"
    local PROBES="www.google.com:443 www.cloudflare.com:443 one.one.one.one:443"
    local found=0

    for PROBE in $PROBES; do
        local host="${PROBE%:*}"
        local port="${PROBE##*:}"

        echo "[entrypoint] Auto-CA probe: ${host}:${port} ..."

        # Reachability check (5 s) — skip if the host is blocked entirely
        if ! timeout 5 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
            echo "[entrypoint]   ${host} unreachable — trying next probe host..."
            continue
        fi

        # Check if the cert chain validates against the current trust store.
        # We use || true so set -e doesn't abort on a non-zero openssl exit.
        local verify
        verify=$(echo | timeout 8 openssl s_client \
            -connect "${host}:${port}" \
            -verify_return_error 2>&1 || true)

        if echo "$verify" | grep -q "Verify return code: 0 (ok)"; then
            echo "[entrypoint] TLS: cert verified on ${host} — no interception detected."
            return 0
        fi

        local verify_code
        verify_code=$(echo "$verify" | awk '/Verify return code:/{print $4; exit}')
        echo "[entrypoint] TLS verification failed on ${host} (code ${verify_code:-unknown}) — interception likely."
        echo "[entrypoint] Fetching full certificate chain from ${host}..."

        # Fetch the full chain the proxy is presenting (no verification)
        local chain
        chain=$(echo | timeout 8 openssl s_client \
            -connect "${host}:${port}" \
            -showcerts 2>/dev/null || true)

        if [ -z "$chain" ]; then
            echo "[entrypoint]   Empty chain — trying next probe host..."
            continue
        fi

        # Split the PEM chain into individual cert files
        local tmp_dir
        tmp_dir=$(mktemp -d)
        local cert_idx=0
        local buf=""

        while IFS= read -r line; do
            case "$line" in
                "-----BEGIN CERTIFICATE-----")
                    buf="$line"$'\n' ;;
                "-----END CERTIFICATE-----")
                    buf="${buf}${line}"$'\n'
                    printf '%s' "$buf" > "${tmp_dir}/cert_${cert_idx}.pem"
                    cert_idx=$((cert_idx + 1))
                    buf="" ;;
                *)
                    [ -n "$buf" ] && buf="${buf}${line}"$'\n' ;;
            esac
        done <<< "$chain"

        echo "[entrypoint] ${cert_idx} certificate(s) in chain — scanning for injected CA..."

        # Look for a CA cert that is NOT yet trusted by the system store.
        # A MITM proxy's root CA will have CA:TRUE in Basic Constraints and
        # will fail openssl verify against /etc/ssl/certs.
        for certfile in "${tmp_dir}"/cert_*.pem; do
            [ -f "$certfile" ] || continue

            # Must be a CA certificate
            openssl x509 -in "$certfile" -noout -text 2>/dev/null \
                | grep -q "CA:TRUE" || continue

            # Skip if the system already trusts this cert
            if openssl verify -CApath /etc/ssl/certs "$certfile" 2>/dev/null \
                | grep -q ": OK"; then
                continue
            fi

            local subj
            subj=$(openssl x509 -in "$certfile" -noout -subject 2>/dev/null \
                   | sed 's/^subject=//')
            local expiry
            expiry=$(openssl x509 -in "$certfile" -noout -enddate 2>/dev/null \
                     | sed 's/^notAfter=//')

            echo "[entrypoint] Found injected proxy CA:"
            echo "[entrypoint]   Subject : ${subj}"
            echo "[entrypoint]   Expires : ${expiry}"

            cp "$certfile" "$AUTO_CA"
            found=1
            break
        done

        rm -rf "$tmp_dir"

        if [ "$found" = "1" ]; then
            echo "[entrypoint] Installing proxy CA into trust store..."
            update-ca-certificates 2>&1 | grep -v "^$" || true
            echo "[entrypoint] Proxy CA trusted — TLS interception will work transparently."
            UPDATED=1
            return 0
        else
            echo "[entrypoint]   Could not isolate an untrusted CA on ${host} — trying next probe..."
        fi
    done

    if [ "$found" = "0" ]; then
        echo "[entrypoint] WARNING: TLS verification failed but auto-extraction found no new CA."
        echo "[entrypoint]          Use Option 1 or 2 above to inject the proxy CA manually."
    fi
}

# Only auto-probe if DISABLE_AUTO_CA is not set (opt-out escape hatch)
if [ -z "${DISABLE_AUTO_CA:-}" ]; then
    auto_trust_proxy_ca
fi

[ "$UPDATED" -eq 0 ] && echo "[entrypoint] No custom CA certificates found — using default trust store."

exec python3 -u /traffgen/generator.py "$@"
