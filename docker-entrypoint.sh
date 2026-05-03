#!/bin/bash
set -e

# Install custom CA certificates before launching the generator so every tool
# in the container (Ruby/Metasploit, openssl s_client, curl, Go) trusts them.
#
# TLS-inspection proxies (Cato Networks, Zscaler, Palo Alto, etc.) present
# certificates signed by their own CA.  Add that CA here and all outbound
# HTTPS connections through the proxy will verify cleanly.
#
# ── How to inject the CA ──────────────────────────────────────────────────────
#
#   Option 1 — bind-mount a PEM/CRT file (recommended):
#     docker run \
#       -v /path/to/cato-ca.crt:/usr/local/share/ca-certificates/cato-ca.crt \
#       jdibby/traffgen:latest
#
#   Option 2 — inline PEM via environment variable (useful for secrets managers
#              or Kubernetes secrets):
#     docker run -e EXTRA_CA_CERT="$(cat cato-ca.crt)" jdibby/traffgen:latest
#
# Both options can be combined.  Multiple files can be mounted simultaneously.
# ─────────────────────────────────────────────────────────────────────────────

CERT_DIR=/usr/local/share/ca-certificates
UPDATED=0

# Option 1: any .crt files present in the system custom-cert directory
if ls "$CERT_DIR"/*.crt 1>/dev/null 2>&1; then
    echo "[entrypoint] Installing custom CA certificate(s) from ${CERT_DIR}/ ..."
    update-ca-certificates 2>&1 | grep -v "^$" || true
    UPDATED=1
fi

# Option 2: inline PEM passed as EXTRA_CA_CERT environment variable
if [ -n "${EXTRA_CA_CERT:-}" ]; then
    echo "[entrypoint] Installing CA certificate from EXTRA_CA_CERT env var..."
    echo "$EXTRA_CA_CERT" > "$CERT_DIR/extra-ca.crt"
    update-ca-certificates 2>&1 | grep -v "^$" || true
    UPDATED=1
fi

[ "$UPDATED" -eq 0 ] && echo "[entrypoint] No custom CA certificates found — using default trust store."

exec python3 -u /traffgen/generator.py "$@"
