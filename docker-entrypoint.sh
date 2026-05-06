#!/bin/bash
set -e

cat <<'DISCLAIMER'
┌─────────────────────────────────────────────────────────────────────────┐
│                             ! DISCLAIMER !                              │
│                                                                         │
│  This tool is intended for AUTHORIZED SECURITY TESTING AND RESEARCH     │
│  in controlled lab environments only.                                   │
│                                                                         │
│  • You are solely responsible for obtaining explicit written            │
│    permission before testing any systems or networks.                   │
│  • The author(s) accept NO liability for misuse, unauthorized access,   │
│    damage, data loss, or legal consequences arising from use of this    │
│    tool.                                                                │
│  • Use of this software constitutes acceptance of these terms.          │
└─────────────────────────────────────────────────────────────────────────┘
DISCLAIMER

# Install custom CA certificates before launching the generator so every tool
# in the container (Ruby/Metasploit, openssl s_client, curl, Go) trusts them.
#
# TLS-inspection proxies re-sign intercepted HTTPS connections with their own
# CA certificate.  Install that CA here and all outbound connections through
# the proxy will verify cleanly.
#
# ── How to inject the CA ──────────────────────────────────────────────────────
#
#   Option 1 — bind-mount a PEM/CRT file:
#     docker run \
#       -v /path/to/proxy-ca.crt:/usr/local/share/ca-certificates/proxy-ca.crt \
#       jdibby/traffgen:latest
#
#   Option 2 — inline PEM via environment variable (Kubernetes secrets, etc.):
#     docker run -e EXTRA_CA_CERT="$(cat proxy-ca.crt)" jdibby/traffgen:latest
#
#   Option 3 — fully automatic (no configuration required):
#     Just run the container.  The entrypoint probes 15 diverse HTTPS hosts,
#     detects TLS interception by fingerprinting CA certs across failures,
#     and installs the most-seen untrusted CA automatically.  Handles partial
#     bypass (some hosts whitelisted by the proxy) by requiring the CA to appear
#     on more than one host before treating it as confirmed.
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

# ── Option 3: auto-detect TLS interception across diverse probe hosts ──────────
#
# Strategy:
#   1. Probe 15 hosts spanning different ASNs, providers, and URL categories.
#      Inspection platforms sometimes whitelist categories (finance, health,
#      government), so using diverse targets catches selective bypass.
#   2. For every host that fails TLS verification, extract CA certs from the
#      presented chain and fingerprint them (SHA-256).
#   3. Vote: a CA fingerprint seen on N > 1 hosts is almost certainly the proxy
#      root CA, not a misconfigured individual server.
#   4. Install the winning CA and run a verification pass on previously-failed
#      hosts to confirm the fix worked.
#   5. Report which hosts were bypassed (clean cert) vs intercepted — useful
#      for understanding the proxy's bypass/whitelist policy.
auto_trust_proxy_ca() {
    local AUTO_CA="${CERT_DIR}/auto-proxy-ca.crt"

    # 15 diverse targets: CDN, cloud, social, developer tools, OS vendors,
    # financial — chosen to surface bypass rules that whitelist specific
    # categories or ASNs.
    local PROBES=(
        "www.google.com:443"
        "www.cloudflare.com:443"
        "www.microsoft.com:443"
        "www.apple.com:443"
        "www.amazon.com:443"
        "github.com:443"
        "login.microsoftonline.com:443"
        "www.reddit.com:443"
        "pypi.org:443"
        "registry.npmjs.org:443"
        "hub.docker.com:443"
        "api.github.com:443"
        "www.digicert.com:443"
        "ocsp.pki.goog:443"
        "one.one.one.one:443"
    )

    local TMP_DIR
    TMP_DIR=$(mktemp -d)
    # Results written by worker subshells: <tmp>/result_<host> contains
    # "PASS", "FAIL", or "UNREACHABLE"
    local CERT_DIR_TMP="${TMP_DIR}/certs"
    mkdir -p "$CERT_DIR_TMP"

    # ── Probe worker (runs in a subshell so it can be backgrounded) ────────────
    probe_host() {
        local host="${1%:*}"
        local port="${1##*:}"
        local result_file="${TMP_DIR}/result_${host}"
        local chain_dir="${CERT_DIR_TMP}/${host}"
        mkdir -p "$chain_dir"

        # Reachability (3 s)
        if ! timeout 2 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
            echo "UNREACHABLE" > "$result_file"
            return 0
        fi

        # TLS verification against system store (4 s)
        local verify
        verify=$(echo | timeout 3 openssl s_client \
            -connect "${host}:${port}" \
            -verify_return_error 2>&1 || true)

        if echo "$verify" | grep -q "Verify return code: 0 (ok)"; then
            echo "PASS" > "$result_file"
            return 0
        fi

        local code
        code=$(echo "$verify" | awk '/Verify return code:/{print $4; exit}')
        echo "FAIL:${code:-?}" > "$result_file"

        # Fetch full chain and split into per-cert PEM files
        local chain
        chain=$(echo | timeout 3 openssl s_client \
            -connect "${host}:${port}" \
            -showcerts 2>/dev/null || true)
        [ -z "$chain" ] && return 0

        local buf="" idx=0
        while IFS= read -r line; do
            case "$line" in
                "-----BEGIN CERTIFICATE-----") buf="$line"$'\n' ;;
                "-----END CERTIFICATE-----")
                    buf="${buf}${line}"$'\n'
                    printf '%s' "$buf" > "${chain_dir}/cert_${idx}.pem"
                    idx=$((idx + 1))
                    buf="" ;;
                *) [ -n "$buf" ] && buf="${buf}${line}"$'\n' ;;
            esac
        done <<< "$chain"
    }

    # ── Launch all probes in parallel ──────────────────────────────────────────
    echo "[entrypoint] Probing ${#PROBES[@]} hosts to detect TLS interception..."
    local pids=()
    for probe in "${PROBES[@]}"; do
        probe_host "$probe" &
        pids+=($!)
    done
    # Wait for all workers
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # ── Tally results ──────────────────────────────────────────────────────────
    local passed=() failed=() unreachable=()
    for probe in "${PROBES[@]}"; do
        local host="${probe%:*}"
        local result_file="${TMP_DIR}/result_${host}"
        [ -f "$result_file" ] || continue
        local result
        result=$(cat "$result_file")
        case "$result" in
            PASS)           passed+=("$host") ;;
            FAIL*)          failed+=("$host") ;;
            UNREACHABLE)    unreachable+=("$host") ;;
        esac
    done

    echo "[entrypoint] Results: ${#passed[@]} clean  ${#failed[@]} intercepted  ${#unreachable[@]} unreachable"

    # Nothing failed — no interception
    if [ "${#failed[@]}" -eq 0 ]; then
        echo "[entrypoint] TLS: all reachable hosts verified — no interception detected."
        rm -rf "$TMP_DIR"
        return 0
    fi

    # Report clean (bypassed) hosts if we also had failures — selective bypass
    if [ "${#passed[@]}" -gt 0 ] && [ "${#failed[@]}" -gt 0 ]; then
        echo "[entrypoint] Selective bypass detected:"
        echo "[entrypoint]   Bypassed (clean cert) : ${passed[*]}"
        echo "[entrypoint]   Intercepted           : ${failed[*]}"
    fi

    # ── Fingerprint-vote across all failed hosts' chains ──────────────────────
    # Use a temp file as an associative store (bash 3 compat fallback):
    # <TMP_DIR>/vote_<fingerprint> contains the vote count.
    # <TMP_DIR>/cacert_<fingerprint>.pem holds the cert.
    echo "[entrypoint] Fingerprinting CA certs across ${#failed[@]} intercepted host(s)..."

    for host in "${failed[@]}"; do
        local chain_dir="${CERT_DIR_TMP}/${host}"
        for certfile in "${chain_dir}"/cert_*.pem; do
            [ -f "$certfile" ] || continue

            # Must be a CA cert
            openssl x509 -in "$certfile" -noout -text 2>/dev/null \
                | grep -q "CA:TRUE" || continue

            # Must not already be trusted
            openssl verify -CApath /etc/ssl/certs "$certfile" 2>/dev/null \
                | grep -q ": OK" && continue

            local fp
            fp=$(openssl x509 -in "$certfile" -noout -fingerprint -sha256 2>/dev/null \
                 | sed 's/.*Fingerprint=//' | tr -d ':')
            [ -z "$fp" ] && continue

            local vote_file="${TMP_DIR}/vote_${fp}"
            local votes=0
            [ -f "$vote_file" ] && votes=$(cat "$vote_file")
            echo $((votes + 1)) > "$vote_file"

            # Save a copy of the cert keyed by fingerprint (idempotent)
            cp "$certfile" "${TMP_DIR}/cacert_${fp}.pem" 2>/dev/null || true
        done
    done

    # ── Find the most-voted CA fingerprint ─────────────────────────────────────
    local best_fp="" best_votes=0
    for vote_file in "${TMP_DIR}"/vote_*.tmp "${TMP_DIR}"/vote_*; do
        [ -f "$vote_file" ] || continue
        local fp votes
        fp=$(basename "$vote_file" | sed 's/^vote_//')
        votes=$(cat "$vote_file")
        if [ "$votes" -gt "$best_votes" ]; then
            best_votes="$votes"
            best_fp="$fp"
        fi
    done

    if [ -z "$best_fp" ]; then
        echo "[entrypoint] WARNING: interception detected but no extractable proxy CA found."
        echo "[entrypoint]          Use Option 1 or 2 to inject the proxy CA manually."
        rm -rf "$TMP_DIR"
        return 0
    fi

    local best_cert="${TMP_DIR}/cacert_${best_fp}.pem"
    local subj expiry
    subj=$(openssl x509 -in "$best_cert" -noout -subject 2>/dev/null | sed 's/^subject=//')
    expiry=$(openssl x509 -in "$best_cert" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')

    echo "[entrypoint] Proxy CA identified (seen on ${best_votes} of ${#failed[@]} intercepted host(s)):"
    echo "[entrypoint]   Subject    : ${subj}"
    echo "[entrypoint]   Expires    : ${expiry}"
    echo "[entrypoint]   SHA-256 fp : ${best_fp}"

    if [ "$best_votes" -eq 1 ] && [ "${#failed[@]}" -gt 1 ]; then
        echo "[entrypoint] WARNING: CA only seen on 1 host — may not be the proxy root."
        echo "[entrypoint]          Installing anyway; verify manually if TLS errors persist."
    fi

    cp "$best_cert" "$AUTO_CA"
    echo "[entrypoint] Installing proxy CA into trust store..."
    update-ca-certificates 2>&1 | grep -v "^$" || true
    UPDATED=1

    # ── Verification pass: re-probe a sample of previously-failed hosts ────────
    echo "[entrypoint] Verification pass..."
    local verify_ok=0 verify_fail=0
    # Check up to 3 of the previously-failed hosts
    local check_hosts=("${failed[@]}")
    [ "${#check_hosts[@]}" -gt 3 ] && check_hosts=("${check_hosts[@]:0:3}")
    for host in "${check_hosts[@]}"; do
        local v
        v=$(echo | timeout 3 openssl s_client \
            -connect "${host}:443" \
            -verify_return_error 2>&1 || true)
        if echo "$v" | grep -q "Verify return code: 0 (ok)"; then
            echo "[entrypoint]   ${host} ✓ now verified"
            verify_ok=$((verify_ok + 1))
        else
            echo "[entrypoint]   ${host} ✗ still failing — proxy CA may not match"
            verify_fail=$((verify_fail + 1))
        fi
    done

    if [ "$verify_ok" -gt 0 ] && [ "$verify_fail" -eq 0 ]; then
        echo "[entrypoint] Proxy CA trusted — TLS interception will work transparently."
    elif [ "$verify_ok" -gt 0 ]; then
        echo "[entrypoint] Partial success (${verify_ok} ok, ${verify_fail} still failing)."
        echo "[entrypoint] The proxy may use different CAs for different destinations."
        echo "[entrypoint] Use Option 1 or 2 to inject additional CAs if needed."
    else
        echo "[entrypoint] WARNING: verification pass failed — installed CA may be wrong."
        echo "[entrypoint]          Use Option 1 or 2 to inject the proxy CA manually."
    fi

    rm -rf "$TMP_DIR"
}

# Only auto-probe if DISABLE_AUTO_CA is not set (opt-out escape hatch)
if [ -z "${DISABLE_AUTO_CA:-}" ]; then
    auto_trust_proxy_ca
fi

[ "$UPDATED" -eq 0 ] && echo "[entrypoint] No custom CA certificates found — using default trust store."

# Start the HTTPS dashboard in the background before launching the generator.
# webui.py generates its own self-signed TLS certificate on first run.
python3 -u /traffgen/webui.py &

exec python3 -u /traffgen/generator.py "$@"
