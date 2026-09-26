"""
Unit tests for app.privacy_engine, app.ai_engine, and RawLog validation,
covering the privacy guarantees of the system (spec tests 1-9).
"""

from __future__ import annotations

import datetime as dt

import pytest
from pydantic import ValidationError

from app.ai_engine import analyze_threat
from app.privacy_engine import (
    _compute_hmac,
    create_sanitized_report,
    generate_hmac_token,
    normalize_company_name,
    normalize_ip,
    sanitize_event,
)
from app.schemas import RawLog


def _make_raw_log(**overrides) -> RawLog:
    data = {
        "company_name": "Alpha Cyber Systems",
        "internal_ip": "10.0.0.25",
        "attack_type": "Brute Force",
        "failed_attempts": 150,
        "target_service": "SSH",
        "timestamp": dt.datetime(2026, 9, 25, 10, 30, tzinfo=dt.timezone.utc),
    }
    data.update(overrides)
    return RawLog(**data)


# TEST 1: Valid RawLog is accepted.
def test_valid_raw_log_is_accepted():
    raw_log = _make_raw_log()
    assert str(raw_log.internal_ip) == "10.0.0.25"
    assert raw_log.company_name == "Alpha Cyber Systems"


# TEST 2: Invalid IP is rejected.
def test_invalid_ip_is_rejected():
    with pytest.raises(ValidationError):
        _make_raw_log(internal_ip="not-an-ip-address")


# TEST 3: Negative failed_attempts is rejected.
def test_negative_failed_attempts_is_rejected():
    with pytest.raises(ValidationError):
        _make_raw_log(failed_attempts=-1)


def test_empty_attack_type_is_rejected():
    with pytest.raises(ValidationError):
        _make_raw_log(attack_type="   ")


def test_naive_timestamp_is_rejected():
    with pytest.raises(ValidationError):
        _make_raw_log(timestamp=dt.datetime(2026, 9, 25, 10, 30))  # no tzinfo


# TEST 4: HMAC of same normalized value using same key is identical.
def test_hmac_is_deterministic_for_same_key():
    token_1 = generate_hmac_token(normalize_company_name("Alpha Cyber Systems"))
    token_2 = generate_hmac_token(normalize_company_name("Alpha Cyber Systems"))
    assert token_1 == token_2


# TEST 5: Different input creates different HMAC token.
def test_different_input_creates_different_token():
    token_1 = generate_hmac_token(normalize_company_name("Alpha Cyber Systems"))
    token_2 = generate_hmac_token(normalize_company_name("Beta Cyber Systems"))
    assert token_1 != token_2


# TEST 6: Different secret creates different token.
def test_different_secret_creates_different_token():
    normalized = normalize_company_name("Alpha Cyber Systems")
    token_with_secret_one = _compute_hmac("secret-one-xxxxxxxxxxxxxxxxxxxx", "1", normalized)
    token_with_secret_two = _compute_hmac("secret-two-xxxxxxxxxxxxxxxxxxxx", "1", normalized)
    assert token_with_secret_one != token_with_secret_two


def test_token_format_matches_hmac_v_version_scheme():
    token = generate_hmac_token(normalize_company_name("Alpha Cyber Systems"))
    assert token.startswith("hmac_v1_")
    hex_part = token.removeprefix("hmac_v1_")
    assert len(hex_part) == 64
    int(hex_part, 16)  # raises ValueError if not valid hex


# TEST 7 & 8: Sanitization removes company_name and internal_ip.
def test_sanitize_event_returns_only_tokens():
    raw_log = _make_raw_log()
    tokens = sanitize_event(raw_log)

    assert set(tokens.keys()) == {"organization_token", "indicator_token"}
    assert "Alpha Cyber Systems" not in str(tokens)
    assert "10.0.0.25" not in str(tokens)
    assert tokens["organization_token"].startswith("hmac_v")
    assert tokens["indicator_token"].startswith("hmac_v")


# TEST 9: Sanitized report contains threat intelligence.
def test_sanitized_record_contains_threat_intelligence():
    raw_log = _make_raw_log()
    analysis = analyze_threat(raw_log)
    record = create_sanitized_report(raw_log, analysis)

    assert record.threat_type == "Brute Force"
    assert record.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert 0 <= record.impact_percentage <= 100
    assert 0.0 <= record.confidence <= 1.0
    assert record.target_service == "SSH"

    # And, critically, no raw sensitive value anywhere on the record.
    record_text = record.model_dump_json()
    assert "Alpha Cyber Systems" not in record_text
    assert "10.0.0.25" not in record_text


def test_ip_normalization_is_canonical():
    assert normalize_ip("10.0.0.25") == "10.0.0.25"
    assert normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == normalize_ip("2001:db8::1")


def test_ai_engine_worked_example_from_spec():
    """Brute Force + 150 failed attempts must produce exactly the
    worked example documented in the project spec and README."""
    raw_log = _make_raw_log(attack_type="Brute Force", failed_attempts=150)
    analysis = analyze_threat(raw_log)

    assert analysis.threat_type == "Brute Force"
    assert analysis.severity == "HIGH"
    assert analysis.impact_percentage == 75
    assert analysis.confidence == 0.95
