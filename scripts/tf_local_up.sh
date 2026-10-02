#!/usr/bin/env bash
# Deploy the five-service stack to this machine's Docker with Terraform
# (infrastructure/terraform-local). The AWS configuration in infrastructure/terraform
# is not touched.
#
#   ./scripts/tf_local_up.sh       build images if missing, terraform init + apply
#   ./scripts/tf_local_down.sh     terraform destroy (containers, networks, volumes)
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo ".env is missing (copy .env.example and fill it in)"; exit 1; }
set -a; source .env; set +a
export TF_VAR_jwt_secret="${JWT_SECRET}" TF_VAR_encryption_key="${ENCRYPTION_KEY}" \
       TF_VAR_service_token="${SERVICE_TOKEN}" TF_VAR_postgres_password="${POSTGRES_PASSWORD}"

for image in absp-api:local absp-ai:local absp-ledger:local absp-frontend:local; do
  docker image inspect "$image" >/dev/null 2>&1 || { BUILDX_BUILDER=default docker compose build; break; }
done

cd infrastructure/terraform-local
terraform init -input=false
terraform apply -input=false -auto-approve "$@"
