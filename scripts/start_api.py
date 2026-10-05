#!/usr/bin/env python3
"""Container entrypoint for the `api` service (ADR-016).

Brings the database schema up to date, optionally seeds the demonstration dataset, then
replaces itself with uvicorn. Safe to run on every start: create_all() only creates
missing tables, the migration runner skips applied versions, and the seed is a no-op
once organisations exist.

    python3 scripts/start_api.py [--seed] [--no-serve] [--port 8000]

Kubernetes runs `--seed --no-serve` once as a Job, and the api Deployment without either.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "backend" / "migrations"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", action="store_true",
                        help="seed the DEMO/SIMULATION dataset when the database is empty")
    parser.add_argument("--no-serve", action="store_true",
                        help="prepare the database (and seed) then exit instead of serving")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    from app.core.database import create_all                          # noqa: PLC0415

    create_all()
    import run as migrations                                          # noqa: PLC0415

    migrations.run()

    if args.seed:
        sys.path.insert(0, str(ROOT / "scripts"))
        import seed_demo                                              # noqa: PLC0415

        seed_demo.seed(reset_first=False)

    if args.no_serve:
        return
    os.execvp(sys.executable, [
        sys.executable, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0",
        "--port", str(args.port), "--app-dir", str(ROOT / "backend"), "--proxy-headers",
        # Trust X-Forwarded-* from any peer. Safe only because nothing but the frontend
        # proxy can reach the api: an unpublished port in compose, a NetworkPolicy in
        # Kubernetes. The proxy overwrites X-Forwarded-For (docker/nginx/default.conf).
        "--forwarded-allow-ips", "*"])


if __name__ == "__main__":
    main()
