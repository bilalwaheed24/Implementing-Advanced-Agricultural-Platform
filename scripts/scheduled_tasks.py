#!/usr/bin/env python3
"""Background sweeps: ledger anchor retry and Fabric re-mirror, device silence, data-theft
scoring, certification and GMO-approval expiry.

Run periodically (cron, Kubernetes CronJob, or a simple loop) against a live deployment.
Each sweep is independent and safe to run repeatedly: it runs in its own database session
and commits on its own, and one that fails is logged and rolled back without stopping the
sweeps after it.

Usage: python3 scripts/scheduled_tasks.py              # one pass (cron / Kubernetes CronJob)
       python3 scripts/scheduled_tasks.py --every 300  # loop (the compose `scheduler` service)
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.core.database import SessionLocal                     # noqa: E402
from app.core.security import utcnow                            # noqa: E402
from app.services import anchoring                               # noqa: E402
from app.services import devices as device_service               # noqa: E402
from app.services import gmo, security_ops, supplychain        # noqa: E402
from app.services import telemetry as telemetry_service          # noqa: E402

# Wall-clock budget for one Fabric re-mirror pass. Each bridge call has its own timeout
# (fabric_bridge._call), but a hanging gateway times out on every row; without a budget a
# backlog could hold the pass past the Kubernetes job deadline (activeDeadlineSeconds 600)
# before the expiry sweeps ran. Rows left over are taken by the next pass.
REMIRROR_BUDGET_SECONDS = 120.0
REMIRROR_LIMIT_PER_PASS = 100


def sweep_expiring_certifications(db, warn_days: int = 30) -> int:
    """Expire certificates past valid_to and warn about those close to it. Both reach the
    certified organisation and the holders of every batch the certificate is claimed on."""
    result = supplychain.sweep_certification_expiry(db, warn_days)
    return result["expired"] + result["expiring"]


def sweep_expired_gmo_approvals(db) -> int:
    """Propagate lapsed GMO approvals to the developer and every holder of the event."""
    return len(gmo.sweep_expired_approvals(db))


def sweep_anchor_retry(db) -> str:
    """Replay unanchored ledger writes in order (one replay at a time, see anchoring)."""
    retried = anchoring.retry_pending(db)
    if retried.get("busy"):
        return "Anchor retry sweep: another replay is in progress, skipped"
    return (f"Anchor retry sweep: {retried['anchored']} anchored, "
            f"{retried['already_anchored']} already on the ledger, {retried['failed']} failed, "
            f"{retried['blocked']} waiting behind them, {retried['rejected']} rejected, "
            f"{retried['deferred']} deferred (circuit open)")


def sweep_remirror(db) -> str:
    mirrored = anchoring.remirror(db, limit=REMIRROR_LIMIT_PER_PASS,
                                  time_budget_seconds=REMIRROR_BUDGET_SECONDS)
    if not mirrored["enabled"]:
        return "Fabric re-mirror sweep: no bridge configured"
    return (f"Fabric re-mirror sweep: {mirrored['mirrored']} mirrored, "
            f"{mirrored['already_mirrored']} already on Fabric, {mirrored['failed']} failed, "
            f"{mirrored['skipped']} left for the next pass")


def sweep_silent(db) -> str:
    return f"Silent-device sweep: {len(device_service.sweep_silent_devices(db))} device(s) flagged"


def sweep_rescore(db) -> str:
    return (f"Telemetry rescore: {telemetry_service.rescore_unscored(db)} "
            f"unscored reading(s) scored")


def sweep_theft(db) -> str:
    return f"Data-theft sweep: {len(security_ops.sweep_data_theft(db))} principal(s) flagged"


def sweep_certifications(db) -> str:
    return f"Certification-expiry sweep: {sweep_expiring_certifications(db)} certification(s) flagged"


def sweep_gmo(db) -> str:
    return f"GMO-approval expiry sweep: {sweep_expired_gmo_approvals(db)} approval(s) lapsed"


# Order matters only for the first two: the replay commits before the re-mirror reads, so
# writes anchored by the replay are mirrored in the same pass.
SWEEPS: list[tuple[str, Callable]] = [
    ("anchor-retry", sweep_anchor_retry),
    ("fabric-remirror", sweep_remirror),
    ("silent-devices", sweep_silent),
    ("telemetry-rescore", sweep_rescore),
    ("data-theft", sweep_theft),
    ("certification-expiry", sweep_certifications),
    ("gmo-approval-expiry", sweep_gmo),
]


def run_sweep(name: str, sweep: Callable) -> bool:
    """One sweep in its own session and transaction. A failure is logged and rolled back;
    it never stops the sweeps after it. True when the sweep succeeded."""
    try:
        with SessionLocal() as db:
            try:
                message = sweep(db)
                db.commit()
            except Exception:
                db.rollback()
                raise
        print(message, flush=True)
        return True
    except Exception as exc:              # noqa: BLE001 - isolate each sweep
        print(f"{name} sweep failed: {exc}", flush=True)
        traceback.print_exc(file=sys.stdout)
        return False


def run_once() -> int:
    """Run every sweep once. Returns the number that failed."""
    failed = [name for name, sweep in SWEEPS if not run_sweep(name, sweep)]
    stamp = utcnow().isoformat(timespec="seconds")
    if failed:
        print(f"[{stamp}] Scheduled sweeps complete; failed: {', '.join(failed)}", flush=True)
    else:
        print(f"[{stamp}] Scheduled sweeps complete.", flush=True)
    return len(failed)


def main() -> int:
    import argparse
    import time

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--every", type=int, default=0,
                        help="repeat every N seconds (0 = run once and exit, for cron/CronJob)")
    args = parser.parse_args()
    while True:
        try:
            failures = run_once()
        except Exception as exc:              # noqa: BLE001 - a failed pass must not stop the loop
            print(f"sweep pass failed: {exc}", flush=True)
            failures = 1
        if not args.every:
            return 1 if failures else 0
        time.sleep(args.every)


if __name__ == "__main__":
    sys.exit(main())
