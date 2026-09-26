"""
SQLAlchemy engine/session setup for the Privacy-Preserving Threat
Intelligence Network database.

The database holds:
  - threat_reports : sanitized threat intelligence only (no raw sensitive data)
  - admins         : platform administrator accounts
  - clients        : participating client organizations
  - audit_logs     : immutable audit trail

Only sanitized data ever reaches the threat_reports table.
No raw sensitive fields (company_name, internal_ip, username, hostname,
raw_log, privacy secret, password, or API key plaintext) are defined
anywhere in the ORM layer — see app/db_models.py.
"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings


class Base(DeclarativeBase):
    """Base class for all ORM models."""


# check_same_thread=False is required for SQLite when used with FastAPI's
# threaded request handling; this is safe here because every request
# gets its own short-lived Session via get_db().
_connect_args = (
    {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
)

engine = create_engine(settings.database_url, connect_args=_connect_args)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    """Create all tables if they do not already exist.

    Safe to call repeatedly (e.g. on every application start-up) - no
    manual SQL setup is required for this prototype.
    """
    # Import ALL models here so they are registered on Base.metadata
    # before create_all() runs, without creating a circular import at
    # module load time.
    from app import db_models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
