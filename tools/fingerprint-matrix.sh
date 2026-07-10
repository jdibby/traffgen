#!/usr/bin/env bash
#
# Cycles traffgen through every curl-impersonate profile (plus "off" as a
# baseline) against the curl-head-based suites, so the resulting sessions can
# be matched up against your NGFW/SASE dashboard (Cato, Zscaler, Palo Alto,
# etc.) by timestamp to see which profile(s), if any, change how the traffic
# is fingerprinted (Client Class / App-ID / device OS classification).
#
# Only suites built on _curl_head()/_run_head_batch() honor --impersonate —
# see generator.py's --impersonate help text for the current list.
#
# Run from inside the traffgen container on the network you want to test
# from, e.g.:
#   docker exec -it <container> /traffgen/tools/fingerprint-matrix.sh
#   docker exec -it <container> /traffgen/tools/fingerprint-matrix.sh tor-anonymizer
#
# Each run is intentionally --size=XS (smallest volume) to keep the matrix
# fast; it still hits every endpoint in small suites like tor-anonymizer.

set -euo pipefail

SUITES=("$@")
if [ "${#SUITES[@]}" -eq 0 ]; then
    SUITES=(tor-anonymizer llm-dlp)
fi

PROFILES=(off chrome116 chrome116-linux chrome99-android ff117 edge101 safari15-5)

for profile in "${PROFILES[@]}"; do
    for suite in "${SUITES[@]}"; do
        echo "=================================================================="
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] profile=${profile}  suite=${suite}"
        echo "=================================================================="
        python3 /traffgen/generator.py --suite="${suite}" --size=XS --impersonate="${profile}"
        sleep 2
    done
done
