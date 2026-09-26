"""
Privacy engine: converts raw sensitive identifiers into pseudonymous
HMAC-SHA256 tokens, enforces data minimization, and builds the two
sanitized report representations (InternalSanitizedRecord and
SanitizedReport).

SECURITY-SENSITIVE MODULE:
  - sanitize_event() is the ONLY function in this codebase that should
    read raw_log.company_name or raw_log.internal_ip.
  - Raw sensitive values exist only as local variables here, for the
    minimum time needed to compute their pseudonymous tokens. They are
    never logged, never stored, and never returned.
  - Plain SHA-256 is intentionally NOT used for pseudonymization. A
    company name (or an internal IP drawn from a small private-range
    space) is a low-entropy, guessable value. An attacker who obtained
    the sanitized database could brute-force a plain
    sha256(company_name) offline in seconds by hashing a wordlist of
    likely company names, effectively de-anonymizing every record.
    HMAC-SHA256 with a secret key that never leaves the server makes
    that offline dictionary attack infeasible, because the attacker
    would also need the secret key to reproduce any candidate token.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import ipaddress
import uuid

from app.ai_engine import INDICATOR_TYPE
from app.config import settings
from app.schemas import InternalSanitizedRecord, RawLog, SanitizedReport, ThreatAnalysis


def _compute_hmac(secret_key: str, key_version: str, normalized_value: str) -> str:
    """
    Compute HMAC-SHA256(secret_key, normalized_value) and format it as
    hmac_v<version>_<64 hex characters>.

    This low-level function takes the secret explicitly (rather than
    reading app.config.settings itself) so it can be exercised directly
    and deterministically in tests without touching global state - see
    tests/test_privacy.py.
    """
    digest = hmac.new(
        key=secret_key.encode("utf-8"),
        msg=normalized_value.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    return f"hmac_v{key_version}_{digest}"


def normalize_company_name(company_name: str) -> str:
    """Normalize a company name before pseudonymization: trim + casefold.

    Casefolding (rather than .lower()) and trimming ensure that trivial
    variants such as "Alpha Cyber Systems", "ALPHA CYBER SYSTEMS", and
    "  alpha cyber systems  " all pseudonymize to the SAME token, which
    is required for internal correlation to work.
    """
    return company_name.strip().casefold()


def normalize_ip(internal_ip: str) -> str:
    """
    Normalize an IP address to its canonical string form before
    pseudonymization, so that equivalent representations of the same
    address (e.g. an IPv6 address with or without a leading-zero
    expansion) always produce the same token.
    """
    parsed = ipaddress.ip_address(str(internal_ip).strip())
    return str(parsed)


def generate_hmac_token(normalized_value: str) -> str:
    """Generate a versioned HMAC-SHA256 token using the server's secret key.

    This is the standard entry point used by the rest of the
    application; it always uses app.config.settings for the key
    material and key version.
    """
    return _compute_hmac(settings.privacy_secret_key, settings.privacy_key_version, normalized_value)


def sanitize_event(raw_log: RawLog) -> dict[str, str]:
    """
    Convert raw sensitive identifiers into pseudonymous tokens.

    Returns ONLY the tokens - never the original company_name or
    internal_ip values. This is the single point in the codebase where
    those two sensitive fields are read.
    """
    organization_token = generate_hmac_token(normalize_company_name(raw_log.company_name))
    indicator_token = generate_hmac_token(normalize_ip(raw_log.internal_ip))
    return {
        "organization_token": organization_token,
        "indicator_token": indicator_token,
    }


def create_sanitized_report(raw_log: RawLog, analysis: ThreatAnalysis) -> InternalSanitizedRecord:
    """
    Build the InternalSanitizedRecord that will be persisted to the
    database: threat intelligence plus pseudonymous correlation tokens
    only. No raw sensitive field is copied onto this object - only its
    HMAC tokens (via sanitize_event) and the non-sensitive
    target_service value.
    """
    tokens = sanitize_event(raw_log)

    return InternalSanitizedRecord(
        report_id=str(uuid.uuid4()),
        created_at=dt.datetime.now(dt.timezone.utc),
        organization_token=tokens["organization_token"],
        indicator_token=tokens["indicator_token"],
        indicator_type=INDICATOR_TYPE,
        threat_type=analysis.threat_type,
        severity=analysis.severity,
        impact_percentage=analysis.impact_percentage,
        confidence=analysis.confidence,
        attack_pattern=analysis.attack_pattern,
        mitigation=analysis.mitigation,
        target_service=raw_log.target_service,
    )


def to_external_report(record) -> SanitizedReport:
    """
    Map an InternalSanitizedRecord (or a ThreatReport ORM row with the
    same field names) to the external SanitizedReport representation.

    This is the single choke point through which data must pass before
    leaving the trust boundary via any API response. organization_token
    and indicator_token are deliberately dropped here - the SQLAlchemy
    ORM row is NEVER serialized directly into an API response.
    """
    return SanitizedReport(
        report_id=record.report_id,
        created_at=record.created_at,
        threat_type=record.threat_type,
        severity=record.severity,
        impact_percentage=record.impact_percentage,
        confidence=record.confidence,
        attack_pattern=record.attack_pattern,
        mitigation=record.mitigation,
        indicator_type=record.indicator_type,
        target_service=record.target_service,
    )
