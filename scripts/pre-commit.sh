#!/usr/bin/env bash
# Pre-commit gate (Development-rules.md §4). Runs entirely offline.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Secret scan =="
python3 scripts/secret_scan.py

echo "== Fast unit tests =="
python3 -m pytest backend/tests/test_security_primitives.py backend/tests/test_ledger.py \
  backend/tests/test_ai.py -q

echo "== Syntax check: Python =="
python3 -m py_compile $(find backend ai ledger iot scripts -name "*.py")

echo "== Syntax check: frontend JS =="
for f in frontend/app.js frontend/verify.js frontend/assets/*.js frontend/views/*.js; do
  node --check "$f"
done

echo "All pre-commit checks passed."
