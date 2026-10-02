#!/usr/bin/env bash
# Destroy everything scripts/tf_local_up.sh created, including the data volumes.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
export TF_VAR_jwt_secret="${JWT_SECRET}" TF_VAR_encryption_key="${ENCRYPTION_KEY}" \
       TF_VAR_service_token="${SERVICE_TOKEN}" TF_VAR_postgres_password="${POSTGRES_PASSWORD}"
cd infrastructure/terraform-local
terraform destroy -input=false -auto-approve
