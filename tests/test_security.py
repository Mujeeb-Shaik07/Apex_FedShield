"""
Security-focused tests (spec tests 18-20) plus the single most
important test in the project (spec section 19): proving that raw
sensitive data never appears in the API response, the threat feed, or
the database contents.
"""

from __future__ import annotations

import os

from sqlalchemy import select

from app.database import SessionLocal
from app.db_models import ThreatReport

SENSITIVE_EVENT = {
    "company_name": "Alpha Cyber Systems",
    "internal_ip": "10.0.0.25",
    "attack_type": "Brute Force",
    "failed_attempts": 150,
    "target_service": "SSH",
    "timestamp": "2026-09-25T10:30:00+05:30",
}


def _dump_all_rows_as_text() -> str:
    """Read every column of every row back out of the database as text."""
    with SessionLocal() as session:
        rows = session.execute(select(ThreatReport)).scalars().all()
    pieces = []
    for row in rows:
        values = {
            "report_id": row.report_id,
            "organization_token": row.organization_token,
            "indicator_token": row.indicator_token,
            "indicator_type": row.indicator_type,
            "threat_type": row.threat_type,
            "severity": row.severity,
            "impact_percentage": row.impact_percentage,
            "confidence": row.confidence,
            "attack_pattern": row.attack_pattern,
            "mitigation": row.mitigation,
            "target_service": row.target_service,
        }
        pieces.append(str(values))
    return " ".join(pieces)


# TEST 18: Insert a report and verify raw values do not exist in stored fields.
def test_database_never_stores_raw_sensitive_values(client, client_a_headers):
    client.post("/api/ingest-log", json=SENSITIVE_EVENT, headers=client_a_headers)

    db_text = _dump_all_rows_as_text()
    assert "Alpha Cyber Systems" not in db_text
    assert "10.0.0.25" not in db_text


def test_database_has_no_sensitive_columns():
    """The ORM table must not define any column that could hold raw sensitive data."""
    column_names = {column.name for column in ThreatReport.__table__.columns}
    forbidden = {"company_name", "internal_ip", "raw_log", "username", "hostname", "privacy_secret"}
    assert column_names.isdisjoint(forbidden)


# TEST 19: API never exposes the privacy secret.
def test_api_never_exposes_privacy_secret(client, client_a_headers):
    secret = os.environ["PRIVACY_SECRET_KEY"]

    response = client.post("/api/ingest-log", json=SENSITIVE_EVENT, headers=client_a_headers)
    assert secret not in response.text

    response = client.get("/api/threat-feed", headers=client_a_headers)
    assert secret not in response.text

    response = client.get("/api/health")
    assert secret not in response.text

    response = client.get("/api/stats")
    assert secret not in response.text


# TEST 20: API never exposes API keys.
def test_api_never_exposes_api_keys(client, client_a_headers, client_b_headers, client_c_headers):
    keys = [
        os.environ["CLIENT_A_API_KEY"],
        os.environ["CLIENT_B_API_KEY"],
        os.environ["CLIENT_C_API_KEY"],
    ]

    response = client.post("/api/ingest-log", json=SENSITIVE_EVENT, headers=client_a_headers)
    for key in keys:
        assert key not in response.text

    response = client.get("/api/threat-feed", headers=client_a_headers)
    for key in keys:
        assert key not in response.text


def test_invalid_api_key_error_does_not_echo_submitted_key(client):
    submitted_key = "super-secret-guess-12345"
    response = client.get("/api/threat-feed", headers={"X-API-Key": submitted_key})
    assert response.status_code == 401
    assert submitted_key not in response.text


def test_unhandled_exception_does_not_leak_details(client_a_headers, monkeypatch):
    """An unexpected internal error must return a generic 500 message only."""
    import app.main as main_module
    from fastapi.testclient import TestClient

    def _boom(*args, **kwargs):
        raise RuntimeError("this should never reach the client")

    monkeypatch.setattr(main_module.ai_engine, "analyze_threat", _boom)

    # raise_server_exceptions=False so the TestClient exercises our
    # registered exception handler (the default behavior re-raises the
    # exception into the test itself, bypassing the handler entirely).
    with TestClient(main_module.app, raise_server_exceptions=False) as no_raise_client:
        response = no_raise_client.post("/api/ingest-log", json=SENSITIVE_EVENT, headers=client_a_headers)

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "RuntimeError" not in response.text
    assert "this should never reach the client" not in response.text


# ---------------------------------------------------------------------------
# SECTION 19: MOST IMPORTANT SECURITY TEST
#
# Demonstrates the central project claim end-to-end: after ingesting an
# event containing a real company name and internal IP, neither value
# appears anywhere in the ingest response, the threat-feed response, or
# the database contents.
# ---------------------------------------------------------------------------


def test_central_privacy_claim_end_to_end(client, client_a_headers, client_b_headers):
    company_name = SENSITIVE_EVENT["company_name"]
    internal_ip = SENSITIVE_EVENT["internal_ip"]

    ingest_response = client.post("/api/ingest-log", json=SENSITIVE_EVENT, headers=client_a_headers)
    assert ingest_response.status_code == 201
    assert company_name not in ingest_response.text
    assert internal_ip not in ingest_response.text

    feed_response = client.get("/api/threat-feed", headers=client_b_headers)
    assert feed_response.status_code == 200
    assert company_name not in feed_response.text
    assert internal_ip not in feed_response.text

    db_text = _dump_all_rows_as_text()
    assert company_name not in db_text
    assert internal_ip not in db_text
