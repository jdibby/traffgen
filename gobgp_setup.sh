#!/bin/sh

NEIGHBOR_IP="$1"

if [ -z "$NEIGHBOR_IP" ]; then
    echo "Usage: $0 <neighbor-ip>"
    exit 1
fi

echo "Configuring neighbor $NEIGHBOR_IP..."

gobgp -u 127.0.0.1 -p 50051 neighbor add "$NEIGHBOR_IP" as 65555

gobgp -u 127.0.0.1 -p 50051 neighbor "$NEIGHBOR_IP"