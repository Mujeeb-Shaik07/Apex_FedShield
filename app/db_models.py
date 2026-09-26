"""
ORM models for the Privacy-Preserving Threat Intelligence Network.

Tables:
  - threat_reports  : sanitized threat intelligence (no raw sensitive data)
  - admins          : platform administrators (MAIN_ADMIN + ADMIN)
  - clients         : participating client organizations
  - audit_logs      : immutable audit trail of administrative actions

CRITICAL PRIVACY INVARIANT (threat_reports):
  This model intentionally has NO columns for company_name, internal_ip,
  raw_log, username, hostname, or any privacy secret. Only pseudonymous
  correlation tokens and threat-intelligence fields are persisted.
  Do not add a raw sensitive field to this model.

SECURITY INVARIANT (admins):
  password_hash is stored, NEVER password.
  token_version enables immediate session invalidation on deactivation/removal.

SECURITY INVARIANT (clients):
  api_key_hash is stored, NEVER the plaintext api_key.
  The plaintext key is shown ONCE at creation time only.

SECURITY INVARIANT (audit_logs):
  Must NEVER store passwords, API keys, privacy secrets, JWTs,
  raw threat logs, or internal IP addresses.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


# ---------------------------------------------------------------------------
# Threat Reports
# ---------------------------------------------------------------------------


class ThreatReport(Base):
    """A single sanitized threat intelligence report."""

    __tablename__ = "threat_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    # Pseudonymous, internal-correlation-only tokens. These are one-way
    # HMAC-SHA256 outputs; the original company name / IP address cannot
    # be recovered from them without the secret key.
    organization_token: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    indicator_token: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    indicator_type: Mapped[str] = mapped_column(String(64), nullable=False)

    threat_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    impact_percentage: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    attack_pattern: Mapped[str] = mapped_column(String(255), nullable=False)
    mitigation: Mapped[str] = mapped_column(String(500), nullable=False)
    target_service: Mapped[str] = mapped_column(String(100), nullable=False)


Index("ix_threat_reports_created_severity", ThreatReport.created_at, ThreatReport.severity)


# ---------------------------------------------------------------------------
# Admins (platform administrators)
# ---------------------------------------------------------------------------


class AdminRole:
    MAIN_ADMIN = "MAIN_ADMIN"
    ADMIN = "ADMIN"

    ALL = {MAIN_ADMIN, ADMIN}


class Admin(Base):
    """
    Platform administrator account.

    Stores a bcrypt/argon2 password_hash, NEVER the plaintext password.
    token_version enables immediate invalidation of all existing JWT tokens
    when an admin is deactivated or removed: the JWT payload carries the
    token_version at issuance time and is rejected if the stored version
    has been incremented since then.
    """

    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    admin_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)

    # SECURITY: Store hash only. Never store the plaintext password.
    password_hash: Mapped[str] = mapped_column(String(500), nullable=False)

    role: Mapped[str] = mapped_column(String(20), nullable=False)  # MAIN_ADMIN | ADMIN
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Incremented on deactivation/removal to invalidate all outstanding tokens.
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Whether the admin must change their temporary password on first login.
    force_password_change: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


# ---------------------------------------------------------------------------
# Clients (participating threat-intelligence organizations)
# ---------------------------------------------------------------------------


class ClientStatus:
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"

    ALL = {ACTIVE, SUSPENDED, REVOKED}


class Client(Base):
    """
    A client organization participating in the threat-intelligence network.

    SECURITY: api_key_hash is stored, NEVER the plaintext api_key.
    The plaintext key is returned ONCE at creation/regeneration time,
    and is NEVER stored or retrievable after that.
    """

    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    contact_email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)

    # SECURITY: Store hash only. The plaintext API key is shown once and discarded.
    api_key_hash: Mapped[str] = mapped_column(String(500), nullable=False)

    status: Mapped[str] = mapped_column(String(20), nullable=False, default=ClientStatus.ACTIVE)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ---------------------------------------------------------------------------
# Audit Logs (immutable administrative action trail)
# ---------------------------------------------------------------------------


class AuditLog(Base):
    """
    Immutable audit trail entry for all significant administrative actions.

    SECURITY INVARIANT: Must NEVER store passwords, API keys, privacy secrets,
    JWTs, raw threat logs, or internal IP addresses. Only safe metadata.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    actor_admin_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    actor_role: Mapped[str | None] = mapped_column(String(20), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    # Safe descriptive text only — no secrets, no keys, no IPs
    metadata_summary: Mapped[str | None] = mapped_column(Text, nullable=True)


Index("ix_audit_logs_created", AuditLog.created_at)
