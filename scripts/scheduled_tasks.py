#!/usr/bin/env python3
"""Background sweeps: ledger anchor retry and Fabric re-mirror, device silence, data-theft
scoring, certification expiry.

Run periodically (cron, Kubernetes CronJob, or a simple loop) against a live deployment.
Each sweep is independent and safe to run repeatedly.

Usage: python3 scripts/scheduled_tasks.py              # one pass (cron / Kubernetes CronJob)
       python3 scripts/scheduled_tasks.py --every 300  # loop (the compose `scheduler` service)
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.core.database import SessionLocal                     # noqa: E402
from app.core.security import utcnow                            # noqa: E402
from app.models import Certification                             # noqa: E402
from app.services import anchoring                               # noqa: E402
from app.services import devices as device_service               # noqa: E402
from app.services import notifications, security_ops             # noqa: E402
from sqlalchemy import select                                    # noqa: E402


def sweep_expiring_certifications(db, warn_days: int = 30) -> int:
    from datetime import timedelta

    horizon = utcnow() + timedelta(days=warn_days)
    count = 0
    for certification in db.execute(select(Certification).where(
            Certification.status == "ACTIVE",
            Certification.valid_to <= horizon)).scalars():
        if notifications.has_open_alert(db, "CERTIFICATION", certification.id):
            continue
        notifications.raise_alert(
            db, "CERTIFICATION", "WARNING",
            f"Certification {certification.cert_code} expires soon",
            detail=f"Valid until {certification.valid_to.isoformat()}.",
            org_id=certification.issuer_org_id, entity_type="Certification",
            entity_id=certification.id, open_incident=False)
        count += 1
    return count


def sweep_anchors(db) -> None:
    """Replay unanchored ledger writes in order, then re-mirror anchors to Fabric. Committed
    on their own: the replayed writes are already on the ledger, so a later sweep failing
    must not roll back their ANCHORED status (a rerun would resolve them idempotently anyway)."""
    retried = anchoring.retry_pending(db)
    db.commit()
    print(f"Anchor retry sweep: {retried['anchored']} anchored, "
          f"{retried['already_anchored']} already on the ledger, {retried['failed']} failed, "
          f"{retried['blocked']} waiting behind them, {retried['rejected']} rejected, "
          f"{retried['deferred']} deferred (circuit open)")
    mirrored = anchoring.remirror(db)
    db.commit()
    if mirrored["enabled"]:
        print(f"Fabric re-mirror sweep: {mirrored['mirrored']} mirrored, "
              f"{mirrored['already_mirrored']} already on Fabric, {mirrored['failed']} failed")


def run_once() -> None:
    with SessionLocal() as db:
        sweep_anchors(db)

        silent = device_service.sweep_silent_devices(db)
        print(f"Silent-device sweep: {len(silent)} device(s) flagged")

        theft = security_ops.sweep_data_theft(db)
        print(f"Data-theft sweep: {len(theft)} principal(s) flagged")

        expiring = sweep_expiring_certifications(db)
        print(f"Certification-expiry sweep: {expiring} certification(s) flagged")

        db.commit()
    print(f"[{utcnow().isoformat(timespec='seconds')}] Scheduled sweeps complete.", flush=True)


def main() -> int:
    import argparse
    import time

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--every", type=int, default=0,
                        help="repeat every N seconds (0 = run once and exit, for cron/CronJob)")
    args = parser.parse_args()
    while True:
        try:
            run_once()
        except Exception as exc:              # noqa: BLE001 - a failed pass must not stop the loop
            print(f"sweep failed: {exc}", flush=True)
            if not args.every:
                return 1
        if not args.every:
            return 0
        time.sleep(args.every)


if __name__ == "__main__":
    sys.exit(main())
