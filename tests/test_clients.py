"""
Client organization management tests (requirements 39-44, 58-60).

Covers:
  16. MAIN_ADMIN can create a client.
  17. Client API key works while ACTIVE.
  18. Client API key stops working after REVOKED.
  19. Suspended client cannot access threat feed.
  20. Client API key is not stored in plaintext.
  21. Client API key is shown only during creation.
  22. API responses never expose api_key_hash.
  23. Audit event is created when admin/client changes occur.
  24. Audit logs never contain passwords.
  25. Audit logs never contain API keys.
  26. Audit logs never contain privacy secrets.
  27. Existing privacy tests continue to pass (smoke).
  28. Existing threat ingestion tests continue to pass (smoke).
  29. Existing threat-feed tests continue to pass (smoke).

  API KEY REVOCATION TEST (Requirement 60):
    - Create Client A
    - Obtain API key
    - Call /api/threat-feed — success
    - Revoke Client A
    - Same API key -> /api/threat-feed — 401/403
"""

from __future__ import annotations

import os

from sqlalchemy import select

from app.database import SessionLocal
from app.db_models import AuditLog, Client, ClientStatus

# ---------------------------------------------------------------------------
# Sample threat event for smoke tests
# ---------------------------------------------------------------------------

SAMPLE_EVENT = {
    "company_name": "Test Corp",
    "internal_ip": "192.168.1.1",
    "attack_type": "Port Scan",
    "failed_attempts": 50,
    "target_service": "HTTP",
    "timestamp": "2026-09-25T10:00:00+00:00",
}


# ---------------------------------------------------------------------------
# 16: MAIN_ADMIN can create a client
# ---------------------------------------------------------------------------


def test_main_admin_can_create_client(client, main_admin_headers):
    """Test 16: MAIN_ADMIN can create a client organization."""
    resp = client.post(
        "/api/admin/clients",
        json={"display_name": "Client Org 16", "contact_email": "org16@example.com"},
        headers=main_admin_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["display_name"] == "Client Org 16"
    assert body["status"] == ClientStatus.ACTIVE
    assert "api_key" in body
    assert len(body["api_key"]) > 20  # Must be a substantial key


def test_created_client_can_log_in_with_normalized_credentials(client, main_admin_headers):
    """A created organization's one-time key authenticates despite pasted whitespace."""
    create_resp = client.post(
        "/api/admin/clients",
        json={"display_name": "  Login Flow Org  ", "contact_email": "loginflow@example.com"},
        headers=main_admin_headers,
    )
    assert create_resp.status_code == 201
    created = create_resp.json()

    login_resp = client.post(
        "/api/client/login",
        json={
            "display_name": " login flow org ",
            "api_key": f" {created['api_key']}\n",
        },
    )

    assert login_resp.status_code == 200, login_resp.text
    assert login_resp.json()["client_id"] == created["client_id"]


# ---------------------------------------------------------------------------
# 17: Client API key works while ACTIVE
# ---------------------------------------------------------------------------


def test_active_client_api_key_grants_access(client, main_admin_headers, managed_client):
    """Test 17: A newly created (ACTIVE) client can access the threat feed."""
    api_key = managed_client["api_key"]
    resp = client.get("/api/threat-feed", headers={"X-API-Key": api_key})
    assert resp.status_code == 200


def test_active_client_can_ingest_events(client, main_admin_headers, managed_client):
    """Test 17: An ACTIVE client can submit threat events."""
    api_key = managed_client["api_key"]
    resp = client.post(
        "/api/ingest-log",
        json=SAMPLE_EVENT,
        headers={"X-API-Key": api_key},
    )
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# 18: Client API key stops working after REVOKED (Requirement 60)
# ---------------------------------------------------------------------------


def test_revoked_client_api_key_is_rejected(client, main_admin_headers):
    """
    Test 18 & Requirement 60: API key revocation takes effect immediately.

    1. Create client, get API key
    2. Verify key works
    3. Revoke client
    4. Same key must be rejected
    """
    # Create client
    create_resp = client.post(
        "/api/admin/clients",
        json={"display_name": "Client To Revoke", "contact_email": "revoke@example.com"},
        headers=main_admin_headers,
    )
    assert create_resp.status_code == 201
    client_id = create_resp.json()["client_id"]
    api_key = create_resp.json()["api_key"]

    # Verify key works
    resp = client.get("/api/threat-feed", headers={"X-API-Key": api_key})
    assert resp.status_code == 200, "Key should work before revocation"

    # Revoke client
    resp = client.delete(f"/api/admin/clients/{client_id}", headers=main_admin_headers)
    assert resp.status_code == 204

    # Key must no longer work
    resp = client.get("/api/threat-feed", headers={"X-API-Key": api_key})
    assert resp.status_code in (401, 403), (
        f"Revoked client key should be rejected, but got {resp.status_code}"
    )

    # Ingest must also fail
    resp = client.post(
        "/api/ingest-log",
        json=SAMPLE_EVENT,
        headers={"X-API-Key": api_key},
    )
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# 19: Suspended client cannot access threat feed
# ---------------------------------------------------------------------------


def test_suspended_client_cannot_access_feed(client, main_admin_headers):
    """Test 19: Suspended client's API key is rejected for all protected endpoints."""
    # Create client
    create_resp = client.post(
        "/api/admin/clients",
        json={"display_name": "Client To Suspend", "contact_email": "suspend@example.com"},
        headers=main_admin_headers,
    )
    assert create_resp.status_code == 201
    client_id = create_resp.json()["client_id"]
    api_key = create_resp.json()["api_key"]

    # Confirm it works
    resp = client.get("/api/threat-feed", headers={"X-API-Key": api_key})
    assert resp.status_code == 200

    # Suspend client
    resp = client.patch(f"/api/admin/clients/{client_id}/suspend", headers=main_admin_headers)
    assert resp.status_code == 200

    # Key must be rejected
    resp = client.get("/api/threat-feed", headers={"X-API-Key": api_key})
    assert resp.status_code in (401, 403)

    resp = client.post("/api/ingest-log", json=SAMPLE_EVENT, headers={"X-API-Key": api_key})
    assert resp.status_code in (401, 403)


def test_reactivated_client_can_access_feed_again(client, main_admin_headers):
    """After reactivation, a suspended client can access the feed again."""
    create_resp = client.post(
        "/api/admin/clients",
        json={"display_name": "Client Reactivate", "contact_email": "reactivate@example.com"},
        headers=main_admin_headers,
    )
    assert create_resp.status_code == 201
    client_id = create_resp.json()["client_id"]
    api_key = create_resp.json()["api_key"]

    # Suspend
    client.patch(f"/api/admin/clients/{client_id}/suspend", headers=main_admin_headers)
    resp = client.get("/api/threat-feed", headers={"X-API-Key": api_key})
    assert resp.status_code in (401, 403)

    # Reactivate
    client.patch(f"/api/admin/clients/{client_id}/activate", headers=main_admin_headers)
    resp = client.get("/api/threat-feed", headers={"X-API-Key": api_key})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 20 & 21: API key storage security
# ---------------------------------------------------------------------------


def test_client_api_key_not_stored_as_plaintext(client, main_admin_headers):
    """Test 20: The plaintext API key is NOT in the database."""
    create_resp = client.post(
        "/api/admin/clients",
        json={"display_name": "Security Check Client", "contact_email": "seccheck@example.com"},
        headers=main_admin_headers,
    )
    assert create_resp.status_code == 201
    plaintext_key = create_resp.json()["api_key"]
    client_id = create_resp.json()["client_id"]

    # Verify the plaintext key is NOT stored in the database
    with SessionLocal() as db:
        db_client = db.query(Client).filter(Client.client_id == client_id).first()
    assert db_client is not None
    assert db_client.api_key_hash != plaintext_key
    # The hash should look like a SHA-256 hex digest (64 chars)
    assert len(db_client.api_key_hash) == 64
    assert plaintext_key not in db_client.api_key_hash


def test_client_api_key_shown_only_once(client, main_admin_headers):
    """Test 21: The API key does not appear in subsequent GET client list responses."""
    create_resp = client.post(
        "/api/admin/clients",
        json={"display_name": "One Time Key Client", "contact_email": "onetimekey@example.com"},
        headers=main_admin_headers,
    )
    assert create_resp.status_code == 201
    plaintext_key = create_resp.json()["api_key"]

    # GET /api/admin/clients must NOT return the API key
    list_resp = client.get("/api/admin/clients", headers=main_admin_headers)
    assert list_resp.status_code == 200
    assert plaintext_key not in list_resp.text


# ---------------------------------------------------------------------------
# 22: API responses never expose api_key_hash
# ---------------------------------------------------------------------------


def test_client_list_never_exposes_api_key_hash(client, main_admin_headers, managed_client):
    """Test 22: GET /api/admin/clients never returns api_key_hash."""
    resp = client.get("/api/admin/clients", headers=main_admin_headers)
    assert resp.status_code == 200
    body_text = resp.text
    assert "api_key_hash" not in body_text
    # No SHA-256 hex hashes (64-char hex strings) should appear
    # (This is a heuristic — the exact hash must definitely not be there)
    with SessionLocal() as db:
        clients = db.query(Client).all()
    for c in clients:
        assert c.api_key_hash not in body_text


def test_client_creation_response_does_not_expose_hash(client, main_admin_headers):
    """Test 22: The creation response includes api_key but never api_key_hash."""
    resp = client.post(
        "/api/admin/clients",
        json={"display_name": "Hash Check Client", "contact_email": "hashcheck@example.com"},
        headers=main_admin_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "api_key" in body        # One-time key present
    assert "api_key_hash" not in body  # Hash must NOT be present


# ---------------------------------------------------------------------------
# 23: Audit events are created for admin/client changes
# ---------------------------------------------------------------------------


def test_audit_log_created_on_client_creation(client, main_admin_headers):
    """Test 23: CLIENT_CREATED audit event is recorded when a client is created."""
    resp = client.post(
        "/api/admin/clients",
        json={"display_name": "Audit Test Client", "contact_email": "audit@example.com"},
        headers=main_admin_headers,
    )
    assert resp.status_code == 201
    client_id = resp.json()["client_id"]

    # Check audit log
    with SessionLocal() as db:
        log = db.query(AuditLog).filter(
            AuditLog.action == "CLIENT_CREATED",
            AuditLog.target_id == client_id,
        ).first()
    assert log is not None
    assert log.success is True


def test_audit_log_created_on_client_revocation(client, main_admin_headers):
    """Test 23: CLIENT_REVOKED audit event is recorded."""
    create_resp = client.post(
        "/api/admin/clients",
        json={"display_name": "Revoke Audit Client", "contact_email": "revokeaudit@example.com"},
        headers=main_admin_headers,
    )
    client_id = create_resp.json()["client_id"]

    client.delete(f"/api/admin/clients/{client_id}", headers=main_admin_headers)

    with SessionLocal() as db:
        log = db.query(AuditLog).filter(
            AuditLog.action == "CLIENT_REVOKED",
            AuditLog.target_id == client_id,
        ).first()
    assert log is not None


def test_audit_log_created_on_admin_creation(client, main_admin_headers):
    """Test 23: ADMIN_CREATED audit event is recorded."""
    resp = client.post(
        "/api/admin/admins",
        json={
            "name": "Audit Admin Test",
            "email": f"auditadmin_{os.urandom(3).hex()}@test.local",
            "temporary_password": "TempPass123!",
        },
        headers=main_admin_headers,
    )
    assert resp.status_code == 201
    admin_id = resp.json()["admin_id"]

    with SessionLocal() as db:
        log = db.query(AuditLog).filter(
            AuditLog.action == "ADMIN_CREATED",
            AuditLog.target_id == admin_id,
        ).first()
    assert log is not None


def test_audit_log_created_on_admin_login(client):
    """Test 23: ADMIN_LOGIN_SUCCESS audit event is recorded on successful login."""
    client.post(
        "/api/admin/login",
        json={
            "email": os.environ["BOOTSTRAP_ADMIN_EMAIL"],
            "password": os.environ["BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    with SessionLocal() as db:
        log = db.query(AuditLog).filter(
            AuditLog.action == "ADMIN_LOGIN_SUCCESS",
        ).first()
    assert log is not None


# ---------------------------------------------------------------------------
# 24, 25, 26: Audit logs never contain secrets
# ---------------------------------------------------------------------------


def _get_all_audit_logs_text() -> str:
    with SessionLocal() as db:
        logs = db.query(AuditLog).all()
    pieces = []
    for log in logs:
        pieces.append(str({
            "action": log.action,
            "metadata_summary": log.metadata_summary,
            "actor_admin_id": log.actor_admin_id,
            "target_id": log.target_id,
        }))
    return " ".join(pieces)


def test_audit_logs_never_contain_passwords(client, main_admin_headers):
    """Test 24: Audit logs never contain passwords."""
    log_text = _get_all_audit_logs_text()
    bootstrap_password = os.environ["BOOTSTRAP_ADMIN_PASSWORD"]
    assert bootstrap_password not in log_text
    # No argon2 hashes either
    assert "$argon2" not in log_text


def test_audit_logs_never_contain_api_keys(client, main_admin_headers, managed_client):
    """Test 25: Audit logs never contain API keys (plaintext or hashed)."""
    api_key = managed_client["api_key"]
    client_id = managed_client["client_id"]

    # Get the hash from the database
    with SessionLocal() as db:
        db_client = db.query(Client).filter(Client.client_id == client_id).first()
    api_key_hash = db_client.api_key_hash

    log_text = _get_all_audit_logs_text()
    assert api_key not in log_text
    assert api_key_hash not in log_text


def test_audit_logs_never_contain_privacy_secrets(client, main_admin_headers, client_a_headers):
    """Test 26: Audit logs never contain the privacy secret key."""
    privacy_secret = os.environ["PRIVACY_SECRET_KEY"]
    jwt_secret = os.environ["JWT_SECRET_KEY"]

    log_text = _get_all_audit_logs_text()
    assert privacy_secret not in log_text
    assert jwt_secret not in log_text


# ---------------------------------------------------------------------------
# Key regeneration
# ---------------------------------------------------------------------------


def test_api_key_regeneration(client, main_admin_headers):
    """Regenerating the API key immediately invalidates the old key."""
    create_resp = client.post(
        "/api/admin/clients",
        json={"display_name": "Regen Key Client", "contact_email": "regen@example.com"},
        headers=main_admin_headers,
    )
    assert create_resp.status_code == 201
    client_id = create_resp.json()["client_id"]
    old_key = create_resp.json()["api_key"]

    # Old key works
    resp = client.get("/api/threat-feed", headers={"X-API-Key": old_key})
    assert resp.status_code == 200

    # Regenerate
    regen_resp = client.post(
        f"/api/admin/clients/{client_id}/regenerate-key",
        headers=main_admin_headers,
    )
    assert regen_resp.status_code == 200
    new_key = regen_resp.json()["api_key"]
    assert new_key != old_key

    # Old key must no longer work
    resp = client.get("/api/threat-feed", headers={"X-API-Key": old_key})
    assert resp.status_code in (401, 403)

    # New key must work
    resp = client.get("/api/threat-feed", headers={"X-API-Key": new_key})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 27, 28, 29: Existing tests still pass (smoke)
# ---------------------------------------------------------------------------


def test_privacy_guarantee_still_holds(client, client_a_headers):
    """Test 27/28/29: The core privacy and ingest pipeline still works."""
    sensitive_event = {
        "company_name": "Smoke Test Corp",
        "internal_ip": "10.10.10.10",
        "attack_type": "SQL Injection",
        "failed_attempts": 1,
        "target_service": "MySQL",
        "timestamp": "2026-09-25T12:00:00+00:00",
    }

    # Ingest
    resp = client.post("/api/ingest-log", json=sensitive_event, headers=client_a_headers)
    assert resp.status_code == 201
    body = resp.json()
    assert "Smoke Test Corp" not in resp.text
    assert "10.10.10.10" not in resp.text
    assert "company_name" not in body
    assert "internal_ip" not in body


def test_threat_feed_still_works_for_legacy_clients(client, client_a_headers, client_b_headers, client_c_headers):
    """Test 29: Existing legacy client keys still work for the threat feed."""
    for headers in (client_a_headers, client_b_headers, client_c_headers):
        resp = client.get("/api/threat-feed", headers=headers)
        assert resp.status_code == 200
