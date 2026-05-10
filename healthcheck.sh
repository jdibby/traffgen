#!/bin/bash
# Healthy if generator.py wrote a heartbeat within the last 60 seconds.
# The heartbeat thread in generator.py writes /tmp/traffgen.health every 2s.
# This is more reliable than pgrep, which may not be available in slim images.
HEALTH_FILE=/tmp/traffgen.health

[ -f "$HEALTH_FILE" ] || exit 1

LAST=$(cat "$HEALTH_FILE" 2>/dev/null)
NOW=$(date +%s)
AGE=$(( NOW - LAST ))

[ "$AGE" -le 60 ] || exit 1
exit 0
