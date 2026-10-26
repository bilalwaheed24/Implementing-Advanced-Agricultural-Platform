#!/usr/bin/env bash
# Stop everything ./scripts/start.sh started: the compose stack and the Fabric network.
# fabric_down.sh only handles Fabric, so teardown was two commands; this is the other half.
#
#   ./scripts/stop.sh              stop the containers; the demonstration data survives
#   ./scripts/stop.sh --volumes    also delete the volumes (database, ledger, data) — asks first
set -euo pipefail
cd "$(dirname "$0")/.."

FABRIC_DIR="${FABRIC_DIR:-$HOME/absp-fabric}"
CONTAINER_CLI_COMPOSE="${CONTAINER_CLI_COMPOSE:-docker compose}"
export FABRIC_DIR CONTAINER_CLI_COMPOSE

usage() {
  cat <<'EOF'
Usage: ./scripts/stop.sh [--volumes [--yes]] [-h|--help]

  (no flags)   docker compose down, then scripts/fabric_down.sh. Keeps the demo data, so
               ./scripts/start.sh brings the same demonstration back.
  --volumes    Also `docker compose down -v`: deletes PostgreSQL, the ledger chain and the
               data volume. Asks for confirmation.
  --yes, -y    Skip the --volumes confirmation.
  -h, --help   This text.
EOF
}

die() { echo "$@" >&2; exit 1; }

VOLUMES=0
ASSUME_YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --volumes|-v) VOLUMES=1 ;;
    -y|--yes)     ASSUME_YES=1 ;;
    -h|--help)    usage; exit 0 ;;
    *) usage >&2; die "Unknown option: $1" ;;
  esac
  shift
done

read -r -a COMPOSE <<<"$CONTAINER_CLI_COMPOSE"

DOWN_ARGS=(down)
if [ "$VOLUMES" = 1 ]; then
  if [ "$ASSUME_YES" != 1 ]; then
    [ -t 0 ] || die "--volumes needs a terminal to confirm on; pass --yes to skip the question."
    echo "--volumes DELETES the demonstration data (PostgreSQL, the ledger chain, the data volume)."
    read -r -p "Type 'yes' to continue: " reply
    [ "$reply" = "yes" ] || { echo "Nothing was changed."; exit 1; }
  fi
  DOWN_ARGS+=(-v)
fi

echo "== Stopping the compose stack =="
"${COMPOSE[@]}" "${DOWN_ARGS[@]}"

echo "== Stopping Fabric and the bridge =="
./scripts/fabric_down.sh

echo "Everything is stopped. Start it again with: ./scripts/start.sh"
