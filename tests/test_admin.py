"""
Admin authentication and management tests (requirements 32-65).

Covers:
  1.  Bootstrap MAIN_ADMIN is created on first startup.
  2.  Password is stored only as a hash.
  3.  Plaintext password does not appear in database.
  4.  MAIN_ADMIN can log in.
  5.  Invalid admin password is rejected.
  6.  Inactive admin cannot log in.
  7.  MAIN_ADMIN can create ADMIN.
  8.  ADMIN receives role ADMIN.
  9.  ADMIN can perform normal operational admin functions.
  10. ADMIN cannot remove MAIN_ADMIN.
  11. ADMIN cannot create MAIN_ADMIN.
  12. ADMIN cannot remove another ADMIN.
  13. MAIN_ADMIN can deactivate ADMIN.
  14. Deactivated ADMIN loses access immediately.
  15. Existing token from removed ADMIN is rejected.

  CRITICAL PRIVILEGE REVOCATION TEST (requirement 59):
    - MAIN_ADMIN creates ADMIN A
    - ADMIN A logs in and gets valid token
    - ADMIN A can access admin endpoint
    - MAIN_ADMIN deactivates ADMIN A
    - ADMIN A's token is immediately rejected
"""

from __future__ import annotations

import os

from sqlalchemy import select

from app.database import SessionLocal
from app.db_models import Admin, AdminRole


# ---------------------------------------------------------------------------
# 1 & 4: Bootstrap and login
# ---------------------------------------------------------------------------


def test_main_admin_exists_after_startup(client):
    """Test 1: MAIN_ADMIN is created on startup via bootstrap credentials."""
    with SessionLocal() as db:
        main_admin = db.query(Admin).filter(Admin.role == AdminRole.MAIN_ADMIN).first()
    assert main_admin is not None
    assert main_admin.email == os.environ["BOOTSTRAP_ADMIN_EMAIL"]
    assert main_admin.is_active is True


def test_main_admin_can_login(client):
    """Test 4: MAIN_ADMIN can log in with bootstrap credentials."""
    resp = client.post(
        "/api/admin/login",
        json={
            "email": os.environ["BOOTSTRAP_ADMIN_EMAIL"],
            "password": os.environ["BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["role"] == AdminRole.MAIN_ADMIN
    assert body["token_type"] == "bearer"


# ---------------------------------------------------------------------------
# 2 & 3: Password storage security
# ---------------------------------------------------------------------------


def test_password_stored_as_hash_not_plaintext(client):
    """Tests 2 & 3: Bootstrap password is stored as a hash, never as plaintext."""
    plaintext_password = os.environ["BOOTSTRAP_ADMIN_PASSWORD"]
    with SessionLocal() as db:
        admin = db.query(Admin).filter(Admin.role == AdminRole.MAIN_ADMIN).first()
    assert admin is not None
    # The stored value must NOT be the plaintext password
    assert admin.password_hash != plaintext_password
    # The stored value must look like an Argon2 hash
    assert admin.password_hash.startswith("$argon2")
    # The plaintext must not appear anywhere in the hash string
    assert plaintext_password not in admin.password_hash


# ---------------------------------------------------------------------------
# 5: Invalid credentials rejected
# ---------------------------------------------------------------------------


def test_invalid_password_is_rejected(client):
    """Test 5: Wrong password returns 401."""
    resp = client.post(
        "/api/admin/login",
        json={
            "email": os.environ["BOOTSTRAP_ADMIN_EMAIL"],
            "password": "completely-wrong-password",
        },
    )
    assert resp.status_code == 401
    # Must not echo back the password
    assert "completely-wrong-password" not in resp.text


def test_invalid_email_is_rejected(client):
    """Non-existent admin returns 401 (not 404, to prevent enumeration)."""
    resp = client.post(
        "/api/admin/login",
        json={
            "email": "nobody@nowhere.example",
            "password": "any-password",
        },
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 6: Inactive admin cannot log in
# ---------------------------------------------------------------------------


def test_inactive_admin_cannot_login(client, main_admin_headers):
    """Test 6: A deactivated admin is rejected at login."""
    # Create an admin
    resp = client.post(
        "/api/admin/admins",
        json={
            "name": "Inactive Test Admin",
            "email": "inactive_test@threatnet.test",
            "temporary_password": "TempPass123!",
        },
        headers=main_admin_headers,
    )
    assert resp.status_code == 201
    admin_id = resp.json()["admin_id"]

    # Deactivate them
    resp = client.patch(
        f"/api/admin/admins/{admin_id}/deactivate",
        headers=main_admin_headers,
    )
    assert resp.status_code == 200

    # Try to login — must fail
    resp = client.post(
        "/api/admin/login",
        json={"email": "inactive_test@threatnet.test", "password": "TempPass123!"},
    )
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# 7 & 8: MAIN_ADMIN can create ADMIN with correct role
# ---------------------------------------------------------------------------


def test_main_admin_can_create_admin(client, main_admin_headers):
    """Test 7: MAIN_ADMIN can create a secondary admin account."""
    resp = client.post(
        "/api/admin/admins",
        json={
            "name": "Secondary Admin",
            "email": "secondary_test7@threatnet.test",
            "temporary_password": "TempPass123!",
        },
        headers=main_admin_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "Secondary Admin"
    assert body["email"] == "secondary_test7@threatnet.test"


def test_created_admin_has_admin_role(client, main_admin_headers):
    """Test 8: Newly created admin always receives role=ADMIN, never MAIN_ADMIN."""
    resp = client.post(
        "/api/admin/admins",
        json={
            "name": "Role Check Admin",
            "email": "rolecheck@threatnet.test",
            "temporary_password": "TempPass123!",
        },
        headers=main_admin_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["role"] == AdminRole.ADMIN
    # Must never be MAIN_ADMIN
    assert resp.json()["role"] != AdminRole.MAIN_ADMIN


# ---------------------------------------------------------------------------
# 9: ADMIN can perform operational functions
# ---------------------------------------------------------------------------


def test_admin_can_access_dashboard(client, secondary_admin_headers):
    """Test 9: Secondary ADMIN can access the admin dashboard."""
    resp = client.get("/api/admin/dashboard", headers=secondary_admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "total_reports" in body
    assert "total_clients" in body


def test_admin_can_list_clients(client, secondary_admin_headers):
    """Test 9: Secondary ADMIN can list clients."""
    resp = client.get("/api/admin/clients", headers=secondary_admin_headers)
    assert resp.status_code == 200


def test_admin_can_create_client(client, secondary_admin_headers):
    """Test 9: Secondary ADMIN can create a client."""
    resp = client.post(
        "/api/admin/clients",
        json={"display_name": "ADMIN Created Client", "contact_email": "adminclient@example.com"},
        headers=secondary_admin_headers,
    )
    assert resp.status_code == 201
    assert "api_key" in resp.json()


# ---------------------------------------------------------------------------
# 10: ADMIN cannot remove MAIN_ADMIN
# ---------------------------------------------------------------------------


def test_admin_cannot_delete_main_admin(client, secondary_admin_headers):
    """Test 10: Secondary ADMIN cannot delete/remove MAIN_ADMIN."""
    with SessionLocal() as db:
        main_admin = db.query(Admin).filter(Admin.role == AdminRole.MAIN_ADMIN).first()
    assert main_admin is not None

    resp = client.delete(
        f"/api/admin/admins/{main_admin.admin_id}",
        headers=secondary_admin_headers,
    )
    # Must be 403 (not enough privileges — ADMIN cannot delete any admin)
    assert resp.status_code == 403


def test_admin_cannot_deactivate_main_admin(client, secondary_admin_headers):
    """Test 10: Secondary ADMIN cannot deactivate MAIN_ADMIN."""
    with SessionLocal() as db:
        main_admin = db.query(Admin).filter(Admin.role == AdminRole.MAIN_ADMIN).first()

    resp = client.patch(
        f"/api/admin/admins/{main_admin.admin_id}/deactivate",
        headers=secondary_admin_headers,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 11: ADMIN cannot create MAIN_ADMIN
# ---------------------------------------------------------------------------


def test_admin_cannot_create_admin_at_all(client, secondary_admin_headers):
    """Test 11: Secondary ADMIN cannot call POST /api/admin/admins at all."""
    resp = client.post(
        "/api/admin/admins",
        json={
            "name": "Rogue Admin",
            "email": "rogue@threatnet.test",
            "temporary_password": "TempPass123!",
        },
        headers=secondary_admin_headers,
    )
    # Must be 403 — admin management requires MAIN_ADMIN
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 12: ADMIN cannot remove another ADMIN
# ---------------------------------------------------------------------------


def test_admin_cannot_remove_another_admin(client, main_admin_headers, secondary_admin_headers, secondary_admin):
    """Test 12: Secondary ADMIN cannot delete another ADMIN account."""
    # Create a second secondary admin as MAIN_ADMIN
    resp = client.post(
        "/api/admin/admins",
        json={
            "name": "Admin To Keep",
            "email": "admintokeep@threatnet.test",
            "temporary_password": "TempPass123!",
        },
        headers=main_admin_headers,
    )
    assert resp.status_code == 201
    other_admin_id = resp.json()["admin_id"]

    # Now secondary_admin tries to delete them — must fail
    resp = client.delete(
        f"/api/admin/admins/{other_admin_id}",
        headers=secondary_admin_headers,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 13 & 14: MAIN_ADMIN can deactivate ADMIN; deactivated ADMIN loses access
# ---------------------------------------------------------------------------


def test_main_admin_can_deactivate_admin(client, main_admin_headers, secondary_admin):
    """Test 13: MAIN_ADMIN can deactivate a secondary admin."""
    resp = client.patch(
        f"/api/admin/admins/{secondary_admin['admin_id']}/deactivate",
        headers=main_admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


def test_deactivated_admin_cannot_access_endpoints(client, main_admin_headers):
    """Test 14: Deactivated admin token is immediately rejected."""
    # Create admin, get their token, then deactivate them
    create_resp = client.post(
        "/api/admin/admins",
        json={
            "name": "Soon Deactivated",
            "email": f"deactivate_{os.urandom(4).hex()}@test.local",
            "temporary_password": "TempPass123!",
        },
        headers=main_admin_headers,
    )
    assert create_resp.status_code == 201
    admin_id = create_resp.json()["admin_id"]
    email = create_resp.json()["email"]

    # Get their token
    login_resp = client.post(
        "/api/admin/login",
        json={"email": email, "password": "TempPass123!"},
    )
    assert login_resp.status_code == 200
    their_token = login_resp.json()["access_token"]
    their_headers = {"Authorization": f"Bearer {their_token}"}

    # Verify they can access the dashboard
    resp = client.get("/api/admin/dashboard", headers=their_headers)
    assert resp.status_code == 200

    # MAIN_ADMIN deactivates them
    deactivate_resp = client.patch(
        f"/api/admin/admins/{admin_id}/deactivate",
        headers=main_admin_headers,
    )
    assert deactivate_resp.status_code == 200

    # Their token must now be rejected
    resp = client.get("/api/admin/dashboard", headers=their_headers)
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# 15: Token from removed ADMIN is rejected (Requirement 59 — Critical)
# ---------------------------------------------------------------------------


def test_critical_privilege_revocation(client, main_admin_headers):
    """
    Critical integration test (Requirement 59):

    1. MAIN_ADMIN creates ADMIN A
    2. ADMIN A logs in and gets a valid token
    3. ADMIN A can access an admin endpoint
    4. MAIN_ADMIN deactivates ADMIN A
    5. ADMIN A's existing token is immediately rejected
    """
    # Step 1: Create ADMIN A
    create_resp = client.post(
        "/api/admin/admins",
        json={
            "name": "Admin A",
            "email": f"admin_a_{os.urandom(4).hex()}@test.local",
            "temporary_password": "AdminAPass123!",
        },
        headers=main_admin_headers,
    )
    assert create_resp.status_code == 201
    admin_a_id = create_resp.json()["admin_id"]
    admin_a_email = create_resp.json()["email"]

    # Step 2: ADMIN A logs in
    login_resp = client.post(
        "/api/admin/login",
        json={"email": admin_a_email, "password": "AdminAPass123!"},
    )
    assert login_resp.status_code == 200
    admin_a_token = login_resp.json()["access_token"]
    admin_a_headers = {"Authorization": f"Bearer {admin_a_token}"}

    # Step 3: ADMIN A can access an admin endpoint
    resp = client.get("/api/admin/dashboard", headers=admin_a_headers)
    assert resp.status_code == 200, "ADMIN A should have access before deactivation"

    # Step 4: MAIN_ADMIN deactivates ADMIN A
    resp = client.patch(
        f"/api/admin/admins/{admin_a_id}/deactivate",
        headers=main_admin_headers,
    )
    assert resp.status_code == 200

    # Step 5: ADMIN A's existing token must now be rejected
    resp = client.get("/api/admin/dashboard", headers=admin_a_headers)
    assert resp.status_code in (401, 403), (
        f"ADMIN A's token should be rejected after deactivation, "
        f"but got {resp.status_code}: {resp.text}"
    )


def test_removed_admin_token_rejected(client, main_admin_headers):
    """Test 15: Token from a 'removed' (DELETE endpoint) admin is rejected."""
    # Create admin
    create_resp = client.post(
        "/api/admin/admins",
        json={
            "name": "To Be Removed",
            "email": f"remove_{os.urandom(4).hex()}@test.local",
            "temporary_password": "TempPass123!",
        },
        headers=main_admin_headers,
    )
    assert create_resp.status_code == 201
    admin_id = create_resp.json()["admin_id"]
    email = create_resp.json()["email"]

    # Login
    login_resp = client.post(
        "/api/admin/login",
        json={"email": email, "password": "TempPass123!"},
    )
    assert login_resp.status_code == 200
    their_token = login_resp.json()["access_token"]
    their_headers = {"Authorization": f"Bearer {their_token}"}

    # Confirm access
    resp = client.get("/api/admin/dashboard", headers=their_headers)
    assert resp.status_code == 200

    # Remove via DELETE
    resp = client.delete(f"/api/admin/admins/{admin_id}", headers=main_admin_headers)
    assert resp.status_code == 204

    # Token must be rejected
    resp = client.get("/api/admin/dashboard", headers=their_headers)
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# MAIN_ADMIN immutability
# ---------------------------------------------------------------------------


def test_main_admin_cannot_be_deleted_via_api(client, main_admin_headers):
    """MAIN_ADMIN account cannot be deleted through the API."""
    with SessionLocal() as db:
        main_admin = db.query(Admin).filter(Admin.role == AdminRole.MAIN_ADMIN).first()

    resp = client.delete(
        f"/api/admin/admins/{main_admin.admin_id}",
        headers=main_admin_headers,
    )
    assert resp.status_code == 403


def test_main_admin_cannot_be_deactivated_via_api(client, main_admin_headers):
    """MAIN_ADMIN account cannot be deactivated through the API."""
    with SessionLocal() as db:
        main_admin = db.query(Admin).filter(Admin.role == AdminRole.MAIN_ADMIN).first()

    resp = client.patch(
        f"/api/admin/admins/{main_admin.admin_id}/deactivate",
        headers=main_admin_headers,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Unauthenticated access denied
# ---------------------------------------------------------------------------


def test_admin_endpoints_require_authentication(client):
    """All admin endpoints must require authentication."""
    endpoints = [
        ("GET", "/api/admin/dashboard"),
        ("GET", "/api/admin/clients"),
        ("GET", "/api/admin/admins"),
        ("GET", "/api/admin/audit-logs"),
        ("GET", "/api/admin/stats"),
    ]
    for method, path in endpoints:
        resp = client.request(method, path)
        assert resp.status_code in (401, 403), f"Expected auth failure for {method} {path}, got {resp.status_code}"


# ---------------------------------------------------------------------------
# Response safety: never expose password hashes
# ---------------------------------------------------------------------------


def test_admin_responses_never_expose_password_hash(client, main_admin_headers):
    """Admin list/detail responses must never include password_hash or Argon2 hashes."""
    resp = client.get("/api/admin/admins", headers=main_admin_headers)
    assert resp.status_code == 200
    body_text = resp.text
    # The field 'password_hash' must never appear (force_password_change is acceptable)
    assert "password_hash" not in body_text
    # No Argon2 hash strings should be exposed
    assert "$argon2" not in body_text


def test_login_response_never_exposes_password_hash(client):
    """Login response must never include password or hash."""
    resp = client.post(
        "/api/admin/login",
        json={
            "email": os.environ["BOOTSTRAP_ADMIN_EMAIL"],
            "password": os.environ["BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    assert resp.status_code == 200
    body_text = resp.text
    assert "password_hash" not in body_text
    assert "$argon2" not in body_text
    # The submitted password must never appear in the response
    assert os.environ["BOOTSTRAP_ADMIN_PASSWORD"] not in body_text
