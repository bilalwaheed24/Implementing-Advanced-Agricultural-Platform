#!/usr/bin/env bash
# Start a local Hyperledger Fabric 2.5 test network (2 organisations, 1 Raft orderer, CAs),
# deploy the absp-anchor chaincode with an endorsement policy that needs BOTH organisations,
# and start the bridge the API talks to (http://127.0.0.1:8300).
#
#   ./scripts/fabric_up.sh            # then start the platform: ./scripts/run_local.sh
#   ./scripts/fabric_down.sh          # stop everything and remove the network
#
# Needs Docker, Node.js 18+, curl and git. The first run downloads Fabric images (~2 GB).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
FABRIC_DIR="${FABRIC_DIR:-$ROOT/fabric/.network}"     # git-ignored
FABRIC_VERSION="${FABRIC_VERSION:-2.5.16}"             # LTS
CA_VERSION="${CA_VERSION:-1.5.17}"
BRIDGE_PORT="${BRIDGE_PORT:-8300}"
BRIDGE_HOST="${BRIDGE_HOST:-127.0.0.1}"                # 0.0.0.0 when the API runs in Docker

mkdir -p "$FABRIC_DIR"
cd "$FABRIC_DIR"
if [ ! -x fabric-samples/bin/peer ]; then
  echo "== Downloading Hyperledger Fabric $FABRIC_VERSION (samples, binaries, images) =="
  curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
  chmod +x install-fabric.sh
  ./install-fabric.sh -f "$FABRIC_VERSION" -c "$CA_VERSION" docker samples binary
fi

export PATH="$FABRIC_DIR/fabric-samples/bin:$PATH"
cd "$FABRIC_DIR/fabric-samples/test-network"
echo "== Starting the test network (Org1, Org2, orderer, CAs) =="
./network.sh down >/dev/null 2>&1 || true
./network.sh up createChannel -c mychannel -ca

echo "== Deploying absp-anchor: every write needs BOTH Org1 and Org2 to endorse =="
CC_SRC="$FABRIC_DIR/chaincode-src"
rm -rf "$CC_SRC" && mkdir -p "$CC_SRC"
# Package the source only (no local node_modules); the peer installs dependencies itself.
cp -r "$ROOT/fabric/chaincode/absp-anchor/"{index.js,lib,package.json,npm-shrinkwrap.json} "$CC_SRC/"
./network.sh deployCC -c mychannel -ccn absp-anchor -ccp "$CC_SRC" -ccl javascript \
  -ccep "AND('Org1MSP.peer','Org2MSP.peer')"

echo "== Starting the bridge on http://$BRIDGE_HOST:$BRIDGE_PORT =="
cd "$ROOT"
TOKEN=$(python3 - "$BRIDGE_PORT" <<'PY'
import pathlib, secrets, sys
port = sys.argv[1]
env = pathlib.Path(".env")
if not env.exists():
    env.write_text(pathlib.Path(".env.example").read_text())
lines = env.read_text().splitlines()
values = dict(l.split("=", 1) for l in lines if "=" in l and not l.lstrip().startswith("#"))
token = values.get("FABRIC_BRIDGE_TOKEN", "").strip() or secrets.token_urlsafe(32)
wanted = {"FABRIC_BRIDGE_URL": f"http://127.0.0.1:{port}", "FABRIC_BRIDGE_TOKEN": token}
out, seen = [], set()
for line in lines:
    key = line.split("=", 1)[0].strip()
    if key in wanted and not line.lstrip().startswith("#"):
        out.append(f"{key}={wanted[key]}"); seen.add(key)
    else:
        out.append(line)
out += [f"{k}={v}" for k, v in wanted.items() if k not in seen]
env.write_text("\n".join(out) + "\n")
print(token)
PY
)
cd "$ROOT/fabric/gateway"
[ -d node_modules ] || npm ci --no-audit --no-fund
if [ -f "$FABRIC_DIR/bridge.pid" ]; then kill "$(cat "$FABRIC_DIR/bridge.pid")" 2>/dev/null || true; fi
FABRIC_SAMPLES="$FABRIC_DIR/fabric-samples" BRIDGE_TOKEN="$TOKEN" BRIDGE_PORT="$BRIDGE_PORT" \
  BRIDGE_HOST="$BRIDGE_HOST" nohup node server.js > "$FABRIC_DIR/bridge.log" 2>&1 &
echo $! > "$FABRIC_DIR/bridge.pid"
for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:$BRIDGE_PORT/health" >/dev/null; then
    curl -s "http://127.0.0.1:$BRIDGE_PORT/health"; echo
    echo "Fabric is up. .env now has FABRIC_BRIDGE_URL and FABRIC_BRIDGE_TOKEN;"
    echo "restart the platform (./scripts/run_local.sh) so it starts mirroring anchors."
    exit 0
  fi
  sleep 1
done
echo "The bridge did not start; see $FABRIC_DIR/bridge.log" >&2
exit 1
