#!/usr/bin/env bash
# Start the whole demonstration from a cold boot: the Hyperledger Fabric test network and
# its bridge on the host, then the five-container compose stack on http://127.0.0.1:8080.
# Replaces the sequence of fabric_up.sh + a hand-written `docker compose up` line.
#
#   ./scripts/start.sh             start; a Fabric network that is already up is reused
#   ./scripts/start.sh --rebuild   rebuild the images first (docker compose up --build)
#   ./scripts/start.sh --fresh     tear everything down, demo data included, then start clean
#   ./scripts/start.sh --lan       also publish 8080 on the Wi-Fi, so a phone can scan a QR
#   ./scripts/stop.sh              stop it all again
#
# Safe to re-run. If Fabric is already running, it is left alone rather than torn down and
# rebuilt, so starting twice by accident never destroys a seeded demonstration — only
# --fresh does that, and it asks first.
#
# Needs Docker, curl and (for the Fabric bridge) Node.js 22.12+ — see .nvmrc. The Node
# check lives in fabric_up.sh, which is the script that launches the bridge.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

FABRIC_DIR="${FABRIC_DIR:-$HOME/absp-fabric}"            # where fabric_up.sh keeps the network
CONTAINER_CLI_COMPOSE="${CONTAINER_CLI_COMPOSE:-docker compose}"   # read by fabric-samples
BRIDGE_PORT="${BRIDGE_PORT:-8300}"
BRIDGE_URL="http://127.0.0.1:$BRIDGE_PORT"
APP_URL="${APP_URL:-http://127.0.0.1:8080}"
BRIDGE_TIMEOUT="${BRIDGE_TIMEOUT:-60}"                   # seconds to wait for /health
APP_TIMEOUT="${APP_TIMEOUT:-300}"                        # first start seeds; that takes a while
export FABRIC_DIR CONTAINER_CLI_COMPOSE

usage() {
  cat <<'EOF'
Usage: ./scripts/start.sh [--rebuild] [--fresh [--yes]] [-h|--help]

  (no flags)   Start Fabric (unless already up) and the compose stack, then wait until
               http://127.0.0.1:8080 answers. Re-running this is harmless.
  --rebuild    Pass --build to docker compose, so the images are rebuilt from the Dockerfiles.
  --fresh      Destroy everything first — `docker compose down -v` (database, ledger and
               data volumes) and fabric_down.sh — then start clean. The api re-seeds the
               demonstration dataset on the empty database. Asks for confirmation.
  --yes, -y    Skip the --fresh confirmation (for non-interactive use).
  --lan        Publish 8080 on this machine's Wi-Fi address as well as 127.0.0.1, and print
               that address into the QR codes, so a phone on the same network can scan a
               batch and open the consumer page. Anyone on that network can then reach the
               platform; start again without --lan to close it. Overlay: docker-compose.lan.yml.
  -h, --help   This text.

Environment: FABRIC_DIR (default $HOME/absp-fabric), CONTAINER_CLI_COMPOSE (default
"docker compose"), BRIDGE_PORT (8300), APP_URL, BRIDGE_TIMEOUT, APP_TIMEOUT, and with
--lan either LAN_IP or PUBLIC_BASE_URL to override the detected Wi-Fi address.
EOF
}

die() { echo "$@" >&2; exit 1; }

REBUILD=0
FRESH=0
ASSUME_YES=0
LAN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --rebuild) REBUILD=1 ;;
    --fresh)   FRESH=1 ;;
    -y|--yes)  ASSUME_YES=1 ;;
    --lan)     LAN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "Unknown option: $1" ;;
  esac
  shift
done

# "docker compose" is two words; keep it a string for the environment contract above and an
# array here so nothing depends on word splitting.
read -r -a COMPOSE <<<"$CONTAINER_CLI_COMPOSE"

echo "== Checking prerequisites =="
command -v curl >/dev/null 2>&1 || die "curl is missing. Install it with: sudo apt-get install -y curl"
command -v docker >/dev/null 2>&1 || \
  die "docker is missing. Install Docker Engine: https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || \
  die "The Docker daemon is not reachable. Start it with: sudo systemctl start docker"
"${COMPOSE[@]}" version >/dev/null 2>&1 || \
  die "'$CONTAINER_CLI_COMPOSE' does not work. Install the v2 plugin: sudo apt-get install -y docker-compose-plugin"
[ -d "$FABRIC_DIR" ] || \
  die "FABRIC_DIR ($FABRIC_DIR) does not exist. Create it with: mkdir -p \"$FABRIC_DIR\" — the first run then downloads Fabric (~2 GB). Point FABRIC_DIR elsewhere if the network already lives somewhere else."
[ -f .env ] || \
  die ".env is missing (copy .env.example and fill it in, or run ./scripts/run_local.sh once to generate it)"

COMPOSE_FILES=()
LAN_URL=""
if [ "$LAN" = 1 ]; then
  [ -f docker-compose.lan.yml ] || die "docker-compose.lan.yml is missing; --lan needs it."
  # The address of the interface that carries the default route — the one a phone on the same
  # Wi-Fi can actually reach. Not `hostname -I`, which lists docker0 and the libvirt bridge too
  # and would hand out an address no phone can route to.
  LAN_IP="${LAN_IP:-$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')}"
  [ -n "$LAN_IP" ] || die "Could not work out this machine's address on the network. Join a Wi-Fi network, or set LAN_IP yourself: LAN_IP=192.168.1.23 ./scripts/start.sh --lan"
  PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-http://$LAN_IP:8080}"
  # backend/app/core/config.py refuses to start on a longer value, because it has to fit in a
  # QR code that still scans. Fail here, with the value in hand, rather than in the api's logs.
  [ "${#PUBLIC_BASE_URL}" -le 48 ] || \
    die "PUBLIC_BASE_URL is ${#PUBLIC_BASE_URL} characters ($PUBLIC_BASE_URL); the api allows 48. Use a shorter address."
  export LAN_IP PUBLIC_BASE_URL
  COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.lan.yml)
  LAN_URL="$PUBLIC_BASE_URL"
fi

# Fabric counts as up only when the peer container runs AND the bridge answers: a peer
# without a bridge cannot serve the api, and a stale bridge without a peer answers nothing.
fabric_is_up() {
  docker ps --format '{{.Names}}' | grep -qx 'peer0.org1.example.com' &&
    curl -sf -m 3 "$BRIDGE_URL/health" >/dev/null 2>&1
}

# poll <url> <seconds>
poll() {
  local url=$1 deadline=$(( SECONDS + $2 ))
  while [ "$SECONDS" -lt "$deadline" ]; do
    curl -sf -m 5 -o /dev/null "$url" && return 0
    sleep 2
  done
  return 1
}

if [ "$FRESH" = 1 ]; then
  if [ "$ASSUME_YES" != 1 ]; then
    [ -t 0 ] || die "--fresh needs a terminal to confirm on; pass --yes to skip the question."
    echo
    echo "--fresh DESTROYS the demonstration data:"
    echo "  - docker compose down -v   (PostgreSQL, the ledger chain and the data volume)"
    echo "  - ./scripts/fabric_down.sh (the Fabric network and everything anchored on it)"
    echo "The api re-seeds a fresh dataset afterwards, but anything added by hand is gone."
    read -r -p "Type 'yes' to continue: " reply
    [ "$reply" = "yes" ] || { echo "Nothing was changed."; exit 1; }
  fi
  echo "== Tearing down the compose stack and its volumes =="
  "${COMPOSE[@]}" down -v
  echo "== Tearing down the Fabric network =="
  ./scripts/fabric_down.sh
fi

if [ "$FRESH" != 1 ] && fabric_is_up; then
  echo "== Fabric is already up (peer0.org1.example.com + bridge on $BRIDGE_PORT); leaving it alone =="
else
  # fabric_up.sh starts with `network.sh down`, so it must only ever run when Fabric is
  # genuinely not up. BRIDGE_HOST=0.0.0.0 so the containers reach it via host.docker.internal.
  echo "== Starting Hyperledger Fabric and the bridge =="
  BRIDGE_HOST=0.0.0.0 ./scripts/fabric_up.sh
fi

echo "== Waiting for the Fabric bridge on $BRIDGE_URL =="
poll "$BRIDGE_URL/health" "$BRIDGE_TIMEOUT" || {
  echo "The bridge did not answer within ${BRIDGE_TIMEOUT}s; see $FABRIC_DIR/bridge.log" >&2
  echo "Start again from scratch with: ./scripts/start.sh --fresh" >&2
  exit 1
}

echo "== Starting the compose stack =="
# FABRIC_BRIDGE_TOKEN comes from .env, which fabric_up.sh keeps current and compose reads
# by itself; only the URL differs between the host (127.0.0.1) and the containers.
COMPOSE_ARGS=(up -d)
if [ "$REBUILD" = 1 ]; then COMPOSE_ARGS+=(--build); fi
COMPOSE_FABRIC_BRIDGE_URL="http://host.docker.internal:$BRIDGE_PORT" \
  "${COMPOSE[@]}" ${COMPOSE_FILES[@]+"${COMPOSE_FILES[@]}"} "${COMPOSE_ARGS[@]}"

echo "== Waiting for the platform on $APP_URL =="
poll "$APP_URL/" "$APP_TIMEOUT" || {
  echo "The platform did not answer within ${APP_TIMEOUT}s." >&2
  echo "Look at the logs with: $CONTAINER_CLI_COMPOSE logs api" >&2
  exit 1
}

cat <<EOF

ABSP is up: $APP_URL     (repository: $ROOT)
Consumer verification, no login needed: $APP_URL/verify.html

Demo accounts — password DemoPassw0rd!2026:
  admin@absp.demo         Administrator
  farmer@absp.demo        Farm operator
  agronomist@absp.demo    Agronomist
  analyst@absp.demo       Security analyst
  researcher@absp.demo    Biotech researcher
  biosafety@absp.demo     Biosafety officer
  supply@absp.demo        Supply chain operator
  certifier@absp.demo     Certifier
  regulator@absp.demo     Regulator

Follow a service with: $CONTAINER_CLI_COMPOSE logs -f api
Stop everything with:  ./scripts/stop.sh
EOF

if [ "$LAN" = 1 ]; then
  cat <<EOF
On a phone joined to the same Wi-Fi: $LAN_URL
Batch QR codes now carry that address instead of 127.0.0.1.

Port 8080 is open to every device on this network for as long as the stack runs this way.
Note that Docker publishes it through its own iptables chain, so a ufw rule denying 8080
does not close it. Start again without --lan (./scripts/start.sh) to go back to
127.0.0.1 only.
EOF
fi
