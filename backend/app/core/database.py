"""Engine, session and schema management.

SQLite needs `PRAGMA foreign_keys=ON` per connection — it is OFF by default, which
would silently disable referential integrity (ADR-002).
"""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings


def _build_engine() -> Engine:
    settings = get_settings()
    url = settings.database_url
    kwargs: dict = {"pool_pre_ping": True, "future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_connection, _record) -> None:  # noqa: ANN001
    if type(dbapi_connection).__module__.startswith("sqlite3"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, always closed."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_all() -> None:
    from .. import models  # noqa: F401  (import registers the mappers)
    from ..models import Base

    Base.metadata.create_all(bind=engine)


def drop_all() -> None:
    from ..models import Base

    Base.metadata.drop_all(bind=engine)
