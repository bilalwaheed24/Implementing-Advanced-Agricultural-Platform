#!/usr/bin/env bash
# Run the five-service stack on a local Kubernetes cluster (k3d), the same way
# `docker compose up` runs it on Docker (ADR-016).
#
#   ./scripts/k8s_up.sh          build images if missing, create the cluster, deploy
#   ./scripts/k8s_down.sh        delete the cluster (and everything in it)
#
# Environment: K8S_HOST_PORT (default 8080) is the host port the UI is published on, bound to
# 127.0.0.1; K8S_CLUSTER (default absp) names the cluster. Set both to run beside another stack.
#
# Leaves your current kubectl context alone: every command uses --context k3d-absp.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER="${K8S_CLUSTER:-absp}"
HOST_PORT="${K8S_HOST_PORT:-8080}"
CTX="k3d-$CLUSTER"
K="kubectl --context $CTX -n absp"
IMAGES=(absp-api:local absp-ai:local absp-ledger:local absp-frontend:local)

[ -f .env ] || { echo ".env is missing (copy .env.example and fill it in)"; exit 1; }
set -a; source .env; set +a
for var in JWT_SECRET ENCRYPTION_KEY SERVICE_TOKEN POSTGRES_PASSWORD; do
  [ -n "${!var:-}" ] || { echo "$var must be set in .env"; exit 1; }
done

echo "== Images =="
for image in "${IMAGES[@]}"; do
  docker image inspect "$image" >/dev/null 2>&1 || { BUILDX_BUILDER=default docker compose build; break; }
done

echo "== Cluster =="
if ! k3d cluster list "$CLUSTER" >/dev/null 2>&1; then
  # Host 127.0.0.1:$HOST_PORT -> NodePort 30080 (the frontend). Traefik is not needed.
  k3d cluster create "$CLUSTER" --agents 0 --wait \
    -p "127.0.0.1:${HOST_PORT}:30080@server:0" \
    --k3s-arg "--disable=traefik@server:0" \
    --kubeconfig-update-default --kubeconfig-switch-context=false
fi

echo "== Loading images into the cluster (the ai image is large; first time takes a while) =="
k3d image import -c "$CLUSTER" "${IMAGES[@]}"

echo "== Secret (from .env, never written to disk) =="
kubectl --context "$CTX" apply -f infrastructure/k8s/base/namespace.yaml
$K create secret generic absp-secrets \
  --from-literal=JWT_SECRET="${JWT_SECRET}" \
  --from-literal=ENCRYPTION_KEY="${ENCRYPTION_KEY}" \
  --from-literal=SERVICE_TOKEN="${SERVICE_TOKEN}" \
  --from-literal=POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
  --from-literal=DATABASE_URL="postgresql+psycopg://absp:${POSTGRES_PASSWORD}@db:5432/absp" \
  --dry-run=client -o yaml | kubectl --context "$CTX" apply -f -

echo "== Deploying =="
kubectl --context "$CTX" apply -k infrastructure/k8s/local
# local/ allows the browser origin on 8080; follow K8S_HOST_PORT when it differs.
if [ "$HOST_PORT" != 8080 ]; then
  $K patch configmap absp-config --type merge \
    -p "{\"data\":{\"CORS_ORIGINS\":\"http://127.0.0.1:${HOST_PORT},http://localhost:${HOST_PORT}\"}}"
fi
# Pods started before a re-import keep the old image; restart them onto the new one.
$K rollout restart deployment/api deployment/ai deployment/frontend statefulset/ledger >/dev/null

echo "== Waiting for rollout =="
$K rollout status statefulset/db --timeout=180s
$K rollout status statefulset/ledger --timeout=180s
$K rollout status deployment/ai --timeout=300s
$K wait --for=condition=complete job/db-init --timeout=600s
$K rollout status deployment/api --timeout=300s
$K rollout status deployment/frontend --timeout=120s

$K get pods -o wide
echo
echo "ABSP is up on Kubernetes: http://127.0.0.1:${HOST_PORT}   (demo password DemoPassw0rd!2026)"
echo "Inspect with: kubectl --context $CTX -n absp get all"
