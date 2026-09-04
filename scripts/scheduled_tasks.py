#!/usr/bin/env python3
"""Background sweeps: device silence, data-theft scoring, certification expiry.

Run periodically (cron, Kubernetes CronJob, or a simple loop) against a live deployment.
Each sweep is independent and safe to run repeatedly.

Usage: python3 scripts/scheduled_tasks.py
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
        notifications.raise_alert(
            db, "CERTIFICATION", "WARNING",
            f"Certification {certification.cert_code} expires soon",
            detail=f"Valid until {certification.valid_to.isoformat()}.",
            org_id=certification.issuer_org_id, entity_type="Certification",
            entity_id=certification.id, open_incident=False)
        count += 1
    return count


def main() -> int:
    with SessionLocal() as db:
        silent = device_service.sweep_silent_devices(db)
        print(f"Silent-device sweep: {len(silent)} device(s) flagged")

        theft = security_ops.sweep_data_theft(db)
        print(f"Data-theft sweep: {len(theft)} principal(s) flagged")

        expiring = sweep_expiring_certifications(db)
        print(f"Certification-expiry sweep: {expiring} certification(s) flagged")

        db.commit()
    print("Scheduled sweeps complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
