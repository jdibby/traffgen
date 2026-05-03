#!/bin/bash
# Healthcheck: exit 0 if generator.py is running, 1 otherwise.
# Used by Docker HEALTHCHECK — evaluated every 10s with a 3s timeout.
pgrep -f generator.py > /dev/null 2>&1
