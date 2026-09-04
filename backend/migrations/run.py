#!/usr/bin/env python3
"""Forward-only SQL migration runner (ADR-014, Backend.md §"Migrations and seed data").

`create_all()` builds the schema for a brand-new database; this runner brings an
*existing* database up to date by applying the numbered `.sql` files in this
directory exactly once each, recording every applied version in `schema_version`.

    python3 backend/migrations/run.py            # apply pending migrations
    python3 backend/migrations/run.py --status   # show applied / pending

Migrations are forward-only and must be idempotent at the file level: the runner
skips any version already present in `schema_version`.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import text                                            # noqa: E402

from app.core.database import engine                                   # noqa: E402

MIGRATIONS_DIR = Path(__file__).resolve().parent


def _discover() -> list[tuple[str, Path]]:
    return sorted(((p.stem, p) for p in MIGRATIONS_DIR.glob("[0-9]*.sql")),
                  key=lambda item: item[0])


def _applied(connection) -> set[str]:
    connection.execute(text(
        "CREATE TABLE IF NOT EXISTS schema_version ("
        " version VARCHAR(20) PRIMARY KEY,"
        " applied_at TIMESTAMP NOT NULL)"))
    rows = connection.execute(text("SELECT version FROM schema_version")).fetchall()
    return {row[0] for row in rows}


def _statements(sql: str) -> list[str]:
    """Split on ';' and drop blank/comment-only fragments."""
    out = []
    for chunk in sql.split(";"):
        lines = [ln for ln in chunk.splitlines() if not ln.strip().startswith("--")]
        statement = "\n".join(lines).strip()
        if statement:
            out.append(statement)
    return out


def run(status_only: bool = False) -> int:
    migrations = _discover()
    if not migrations:
        print("No migration files found.")
        return 0

    with engine.begin() as connection:
        applied = _applied(connection)

        if status_only:
            for version, _ in migrations:
                print(f"  {'applied' if version in applied else 'PENDING':8s}  {version}")
            return 0

        pending = [(v, p) for v, p in migrations if v not in applied]
        if not pending:
            print(f"Database is up to date ({len(applied)} migration(s) applied).")
            return 0

        for version, path in pending:
            print(f"Applying {version} ...")
            for statement in _statements(path.read_text()):
                try:
                    connection.execute(text(statement))
                except Exception as error:                      # noqa: BLE001
                    # A column added by create_all() on a fresh database is not an
                    # error: record the version and move on.
                    if "duplicate column" in str(error).lower():
                        print(f"  already present, recording {version}")
                        break
                    raise
            connection.execute(
                text("INSERT INTO schema_version (version, applied_at) "
                     "VALUES (:v, CURRENT_TIMESTAMP)"), {"v": version})
        print(f"Applied {len(pending)} migration(s).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status", action="store_true", help="list applied and pending versions")
    args = parser.parse_args()
    return run(status_only=args.status)


if __name__ == "__main__":
    raise SystemExit(main())
