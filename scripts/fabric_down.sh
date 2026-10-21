#!/usr/bin/env bash
# Stop the Fabric bridge and remove the local Fabric test network (containers and volumes).
set -euo pipefail
cd "$(dirname "$0")/.."
FABRIC_DIR="${FABRIC_DIR:-$(pwd)/fabric/.network}"
if [ -f "$FABRIC_DIR/bridge.pid" ]; then
  kill "$(cat "$FABRIC_DIR/bridge.pid")" 2>/dev/null || true
  rm -f "$FABRIC_DIR/bridge.pid"
fi
if [ -x "$FABRIC_DIR/fabric-samples/test-network/network.sh" ]; then
  (cd "$FABRIC_DIR/fabric-samples/test-network" && \
    PATH="$FABRIC_DIR/fabric-samples/bin:$PATH" ./network.sh down)
fi
echo "Fabric network and bridge stopped. Clear FABRIC_BRIDGE_URL in .env to run without it."
