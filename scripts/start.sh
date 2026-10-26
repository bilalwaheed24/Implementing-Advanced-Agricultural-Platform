#!/usr/bin/env bash
# Start the whole demonstration from a cold boot: the Hyperledger Fabric test network and
# its bridge on the host, then the five-container compose stack on http://127.0.0.1:8080.
# Replaces the sequence of fabric_up.sh + a hand-written `docker compose up` line.
#
#   ./scripts/start.sh             start; a Fabric network that is already up is reused
#   ./scripts/start.sh --rebuild   rebuild the images first (docker compose up --build)
#   ./scripts/start.sh --fresh     tear everything down, demo data included, then start clean
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
  -h, --help   This text.

Environment: FABRIC_DIR (default $HOME/absp-fabric), CONTAINER_CLI_COMPOSE (default
"docker compose"), BRIDGE_PORT (8300), APP_URL, BRIDGE_TIMEOUT, APP_TIMEOUT.
EOF
}

die() { echo "$@" >&2; exit 1; }

REBUILD=0
FRESH=0
ASSUME_YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --rebuild) REBUILD=1 ;;
    --fresh)   FRESH=1 ;;
    -y|--yes)  ASSUME_YES=1 ;;
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
  "${COMPOSE[@]}" "${COMPOSE_ARGS[@]}"

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
