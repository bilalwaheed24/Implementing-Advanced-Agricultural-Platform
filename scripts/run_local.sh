#!/usr/bin/env bash
# One-command local startup (brief §32, PRD.md SC-2).
#   ./scripts/run_local.sh          start fresh (seeds demo data if the DB is empty)
#   ./scripts/run_local.sh --reset  wipe and reseed first
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "Creating .env from .env.example with generated secrets..."
  cp .env.example .env
  JWT_SECRET=$(python3 -c "import secrets;print(secrets.token_urlsafe(48))")
  ENC_KEY=$(python3 -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())")
  # Portable in-place edit (works on both GNU and BSD sed).
  python3 - "$JWT_SECRET" "$ENC_KEY" <<'PY'
import sys, pathlib
jwt_secret, enc_key = sys.argv[1], sys.argv[2]
path = pathlib.Path(".env")
text = path.read_text()
text = text.replace("JWT_SECRET=CHANGE_ME_generate_a_48_byte_url_safe_random_string", f"JWT_SECRET={jwt_secret}")
text = text.replace("ENCRYPTION_KEY=CHANGE_ME_base64_encoded_32_byte_key", f"ENCRYPTION_KEY={enc_key}")
path.write_text(text)
PY
  echo "Generated .env with fresh secrets (never commit this file)."
fi
set -a; source .env; set +a

RESET_FLAG=""
if [ "${1:-}" = "--reset" ]; then
  RESET_FLAG="--reset"
  rm -f absp.db absp.db-wal absp.db-shm demo_device_secrets.json
  rm -rf ledger_data
fi

echo "== Training AI models (synthetic data; skip with SKIP_TRAIN=1) =="
# The full training path is used on purpose: --fast undertrains the crop-vision CNN
# and it confuses LEAF_BLIGHT with RUST during a live demonstration. Costs a few
# minutes, and only runs when no model card is present.
if [ "${SKIP_TRAIN:-0}" != "1" ] && [ ! -f ai/models/crop_vision_model_card.json ]; then
  python3 scripts/train_models.py
fi

echo "== Seeding demonstration data =="
python3 scripts/seed_demo.py $RESET_FLAG

echo "== Starting the API on http://127.0.0.1:${PORT:-8000} =="
echo "   Demo accounts: see the output above (password DemoPassw0rd!2026)"
echo "   Public verification page: http://127.0.0.1:${PORT:-8000}/verify.html"
exec python3 -m uvicorn app.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}" \
  --app-dir backend
