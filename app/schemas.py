"""
Pydantic v2 schemas for the Privacy-Preserving Threat Intelligence Network.

Schema categories:

  THREAT INTELLIGENCE (client-facing):
    RawLog                  — sensitive ingest payload (never persisted/returned as-is)
    ThreatAnalysis          — AI engine output (internal)
    InternalSanitizedRecord — privacy-engine output (internal, never returned)
    SanitizedReport         — external threat-intel report (public, no PII)
    ThreatFeedResponse      — feed envelope
    StatsResponse           — aggregate statistics
    HealthResponse          — liveness check

  ADMIN AUTHENTICATION:
    AdminLoginRequest       — email + password (handled server-side only)
    AdminTokenResponse      — access token response (no password/hash)

  ADMIN MANAGEMENT (MAIN_ADMIN operations):
    AdminCreateRequest      — create new ADMIN
    AdminResponse           — safe admin representation (no password_hash)
    AdminListResponse       — list of admins

  CLIENT MANAGEMENT (ADMIN/MAIN_ADMIN operations):
    ClientCreateRequest     — create new client org
    ClientCreateResponse    — includes ONE-TIME api_key
    ClientResponse          — safe client representation (no api_key or api_key_hash)
    ClientListResponse      — list of clients

  AUDIT:
    AuditLogResponse        — safe audit log entry
    AuditLogListResponse    — list of audit entries

SECURITY INVARIANTS:
  - AdminResponse NEVER includes password_hash.
  - ClientResponse and ClientListResponse NEVER include api_key or api_key_hash.
  - ClientCreateResponse includes api_key ONLY in the creation response.
  - AdminLoginRequest is NEVER logged in full.
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

MAX_COMPANY_NAME_LENGTH = 120
MIN_COMPANY_NAME_LENGTH = 2
MAX_ATTACK_TYPE_LENGTH = 100
MAX_TARGET_SERVICE_LENGTH = 100
MIN_TARGET_SERVICE_LENGTH = 1
MAX_FAILED_ATTEMPTS = 1_000_000_000


# ---------------------------------------------------------------------------
# Threat Intelligence schemas (client-facing)
# ---------------------------------------------------------------------------


class RawLog(BaseModel):
    """
    Raw security event as submitted by an organization.

    SECURITY-SENSITIVE MODEL: an instance of this class exists ONLY in
    memory during request processing. It is never persisted to the
    database, never logged in full, and never returned as-is by any API
    response. Only app.privacy_engine and app.ai_engine should read its
    fields directly.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    company_name: str = Field(..., description="Sensitive: reporting organization's name.")
    internal_ip: IPvAnyAddress = Field(..., description="Sensitive: internal IPv4 or IPv6 address.")
    attack_type: str = Field(..., description="Free-text hint of the observed attack type.")
    failed_attempts: int = Field(..., ge=0, le=MAX_FAILED_ATTEMPTS)
    target_service: str = Field(..., description="Targeted service, e.g. SSH, HTTP, RDP.")
    timestamp: dt.datetime = Field(..., description="Timezone-aware event timestamp.")

    @field_validator("company_name")
    @classmethod
    def _validate_company_name(cls, value: str) -> str:
        value = value.strip()
        if len(value) < MIN_COMPANY_NAME_LENGTH:
            raise ValueError(f"company_name must be at least {MIN_COMPANY_NAME_LENGTH} characters")
        if len(value) > MAX_COMPANY_NAME_LENGTH:
            raise ValueError(f"company_name must be at most {MAX_COMPANY_NAME_LENGTH} characters")
        return value

    @field_validator("attack_type")
    @classmethod
    def _validate_attack_type(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("attack_type must not be empty")
        if len(value) > MAX_ATTACK_TYPE_LENGTH:
            raise ValueError(f"attack_type must be at most {MAX_ATTACK_TYPE_LENGTH} characters")
        return value

    @field_validator("target_service")
    @classmethod
    def _validate_target_service(cls, value: str) -> str:
        value = value.strip()
        if len(value) < MIN_TARGET_SERVICE_LENGTH:
            raise ValueError("target_service must not be empty")
        if len(value) > MAX_TARGET_SERVICE_LENGTH:
            raise ValueError(f"target_service must be at most {MAX_TARGET_SERVICE_LENGTH} characters")
        return value

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, value: dt.datetime) -> dt.datetime:
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("timestamp must be timezone-aware")
        return value


class ThreatAnalysis(BaseModel):
    """Output of the deterministic mock AI threat-analysis engine."""

    threat_type: str
    severity: str
    impact_percentage: int = Field(..., ge=0, le=100)
    confidence: float = Field(..., ge=0.0, le=1.0)
    attack_pattern: str
    mitigation: str


class InternalSanitizedRecord(BaseModel):
    """
    Internal-only sanitized record, as produced by the privacy engine
    and persisted to the database.

    Carries pseudonymous correlation tokens. This model is NEVER
    returned directly by any API endpoint - it is always mapped to
    SanitizedReport (dropping the tokens) before crossing the trust
    boundary. See app.privacy_engine.to_external_report.
    """

    report_id: str
    created_at: dt.datetime
    organization_token: str
    indicator_token: str
    indicator_type: str
    threat_type: str
    severity: str
    impact_percentage: int
    confidence: float
    attack_pattern: str
    mitigation: str
    target_service: str


class SanitizedReport(BaseModel):
    """
    External/public threat-intelligence report.

    Contains ONLY fields approved for external distribution. Deliberately
    excludes company_name, internal_ip, username, hostname, raw_log, and
    any privacy secret or correlation token that could be used to
    re-identify the reporting organization from outside the trust
    boundary. This is the only report shape ever returned by the API.
    """

    model_config = ConfigDict(from_attributes=True)

    report_id: str
    created_at: dt.datetime
    threat_type: str
    severity: str
    impact_percentage: int
    confidence: float
    attack_pattern: str
    mitigation: str
    indicator_type: str
    target_service: str


class ThreatFeedResponse(BaseModel):
    """Envelope returned by GET /api/threat-feed."""

    count: int
    reports: list[SanitizedReport]


class StatsResponse(BaseModel):
    """Safe aggregate statistics. Contains no organization identifiers."""

    total_reports: int
    critical_reports: int
    high_reports: int
    medium_reports: int
    low_reports: int


class HealthResponse(BaseModel):
    """Liveness response. Exposes no internal secrets or DB credentials."""

    status: str


# ---------------------------------------------------------------------------
# Admin authentication schemas
# ---------------------------------------------------------------------------


class AdminLoginRequest(BaseModel):
    """
    Admin login credentials.

    SECURITY: This model is handled server-side only and NEVER logged
    in full. Only safe metadata (e.g., email address without password)
    should appear in any log.
    """

    email: str = Field(..., description="Administrator email address")
    password: str = Field(..., description="Administrator password — never logged or stored")


class AdminTokenResponse(BaseModel):
    """
    Admin access token response.

    SECURITY: Never includes the password, password_hash, or JWT signing secret.
    """

    access_token: str
    token_type: str = "bearer"
    role: str
    admin_id: str
    name: str
    force_password_change: bool = False


# ---------------------------------------------------------------------------
# Admin management schemas (MAIN_ADMIN operations)
# ---------------------------------------------------------------------------


class AdminCreateRequest(BaseModel):
    """Request body for creating a new secondary ADMIN."""

    name: str = Field(..., min_length=1, max_length=200)
    email: str = Field(..., description="Admin email address")
    temporary_password: str = Field(..., min_length=8, description="Temporary password — hashed immediately")


class AdminResponse(BaseModel):
    """
    Safe admin representation for API responses.

    SECURITY: NEVER includes password_hash, password, or JWT tokens.
    """

    model_config = ConfigDict(from_attributes=True)

    admin_id: str
    name: str
    email: str
    role: str
    is_active: bool
    created_at: dt.datetime
    updated_at: dt.datetime
    last_login_at: Optional[dt.datetime] = None
    force_password_change: bool


class AdminListResponse(BaseModel):
    """Envelope for the admin list."""

    count: int
    admins: list[AdminResponse]


class PasswordChangeRequest(BaseModel):
    """Request body for changing admin password."""

    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


# ---------------------------------------------------------------------------
# Client management schemas (ADMIN / MAIN_ADMIN operations)
# ---------------------------------------------------------------------------

class ClientLoginRequest(BaseModel):
    """Client UI login request."""
    model_config = ConfigDict(str_strip_whitespace=True)

    display_name: str = Field(..., description="Organization Name")
    api_key: str = Field(..., description="Client API Key")

class ClientCreateRequest(BaseModel):
    """Request body for creating a new client organization."""

    model_config = ConfigDict(str_strip_whitespace=True)

    display_name: str = Field(..., min_length=1, max_length=200)
    contact_email: str = Field(..., description="Client contact email")


class ClientCreateResponse(BaseModel):
    """
    Response for newly created client — includes the one-time API key.

    SECURITY: api_key is returned ONLY in this response. It is NEVER
    stored in the database and NEVER returned again after this point.
    The admin must store the key securely now.
    """

    client_id: str
    display_name: str
    contact_email: str
    status: str
    created_at: dt.datetime
    # ONE-TIME plaintext API key — shown only on creation
    api_key: str
    warning: str = (
        "This API key will be shown only once. "
        "Store it securely — it cannot be retrieved again."
    )


class ClientResponse(BaseModel):
    """
    Safe client representation for API responses.

    SECURITY: NEVER includes api_key or api_key_hash.
    """

    model_config = ConfigDict(from_attributes=True)

    client_id: str
    display_name: str
    contact_email: str
    status: str
    created_at: dt.datetime
    updated_at: dt.datetime
    last_seen_at: Optional[dt.datetime] = None
    last_login_ip: Optional[str] = None
    revoked_at: Optional[dt.datetime] = None


class ClientListResponse(BaseModel):
    """Envelope for the client list."""

    count: int
    clients: list[ClientResponse]


class ClientKeyRegenerateResponse(BaseModel):
    """
    Response for API key regeneration — includes the one-time new API key.

    SECURITY: api_key is returned ONLY in this response.
    """

    client_id: str
    display_name: str
    api_key: str
    warning: str = (
        "The new API key will be shown only once. "
        "Store it securely — it cannot be retrieved again."
    )


# ---------------------------------------------------------------------------
# Audit log schemas
# ---------------------------------------------------------------------------


class AuditLogResponse(BaseModel):
    """
    Safe audit log entry representation.

    SECURITY: metadata_summary NEVER contains passwords, API keys,
    hashes, JWTs, privacy secrets, or internal IP addresses.
    """

    model_config = ConfigDict(from_attributes=True)

    event_id: str
    actor_admin_id: Optional[str] = None
    actor_role: Optional[str] = None
    action: str
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    success: bool
    created_at: dt.datetime
    metadata_summary: Optional[str] = None


class AuditLogListResponse(BaseModel):
    """Envelope for the audit log list."""

    count: int
    logs: list[AuditLogResponse]


# ---------------------------------------------------------------------------
# Admin Dashboard schema
# ---------------------------------------------------------------------------


class DashboardResponse(BaseModel):
    """Safe aggregate dashboard statistics for the admin portal."""

    total_reports: int
    critical_reports: int
    high_reports: int
    medium_reports: int
    low_reports: int
    total_clients: int
    active_clients: int
    suspended_clients: int
    revoked_clients: int
    total_admins: int
    active_admins: int
