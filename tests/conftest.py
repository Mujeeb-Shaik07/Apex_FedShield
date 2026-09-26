"""
Shared pytest fixtures.

Sets a dedicated, disposable test configuration — including an isolated
SQLite database file and isolated test-only secret/API-key values —
BEFORE any `app.*` module is imported, because app.config loads its
Settings singleton once at import time.

os.environ.setdefault() is used deliberately: it only sets a value if
one is not already present. Since app.config's load_dotenv() call also
never overrides an already-set environment variable, this guarantees
these isolated test values win over anything in a local .env file,
without ever touching that file.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

_TEST_DB_DIR = tempfile.mkdtemp(prefix="threat_intel_test_")
_TEST_DB_PATH = Path(_TEST_DB_DIR) / "test_threat_intelligence.db"

# Core settings
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TEST_DB_PATH}")
os.environ.setdefault("PRIVACY_SECRET_KEY", "test-only-secret-key-do-not-use-in-production-1234567890")
os.environ.setdefault("PRIVACY_KEY_VERSION", "1")
os.environ.setdefault("CLIENT_A_API_KEY", "test-client-a-key")
os.environ.setdefault("CLIENT_B_API_KEY", "test-client-b-key")
os.environ.setdefault("CLIENT_C_API_KEY", "test-client-c-key")

# Admin bootstrap settings for tests
os.environ.setdefault("BOOTSTRAP_ADMIN_EMAIL", "testadmin@threatnet.test")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "TestBootstrapPassword123!")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-do-not-use-in-production-9876543210")
os.environ.setdefault("ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES", "30")

from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, engine, init_db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _setup_test_database():
    """Create a clean set of tables once for the whole test session."""
    Base.metadata.drop_all(bind=engine)
    init_db()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client() -> TestClient:
    """A FastAPI TestClient bound to the application under test."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def client_a_headers() -> dict[str, str]:
    return {"X-API-Key": os.environ["CLIENT_A_API_KEY"]}


@pytest.fixture()
def client_b_headers() -> dict[str, str]:
    return {"X-API-Key": os.environ["CLIENT_B_API_KEY"]}


@pytest.fixture()
def client_c_headers() -> dict[str, str]:
    return {"X-API-Key": os.environ["CLIENT_C_API_KEY"]}


# ---------------------------------------------------------------------------
# Admin fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def main_admin_token(client: TestClient) -> str:
    """Login as MAIN_ADMIN and return the JWT access token."""
    resp = client.post(
        "/api/admin/login",
        json={
            "email": os.environ["BOOTSTRAP_ADMIN_EMAIL"],
            "password": os.environ["BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    assert resp.status_code == 200, f"MAIN_ADMIN login failed: {resp.text}"
    return resp.json()["access_token"]


@pytest.fixture()
def main_admin_headers(main_admin_token: str) -> dict[str, str]:
    """Authorization headers for MAIN_ADMIN requests."""
    return {"Authorization": f"Bearer {main_admin_token}"}


@pytest.fixture()
def secondary_admin(client: TestClient, main_admin_headers: dict) -> dict:
    """
    Create a secondary ADMIN via the API and return their credentials dict.
    Cleans up after the test by revoking the admin.
    """
    resp = client.post(
        "/api/admin/admins",
        json={
            "name": "Test Secondary Admin",
            "email": f"secondary_{os.urandom(4).hex()}@test.local",
            "temporary_password": "TempPassword123!",
        },
        headers=main_admin_headers,
    )
    assert resp.status_code == 201
    admin_data = resp.json()
    admin_data["_password"] = "TempPassword123!"
    return admin_data


@pytest.fixture()
def secondary_admin_token(client: TestClient, secondary_admin: dict) -> str:
    """Login as the secondary ADMIN and return their JWT access token."""
    resp = client.post(
        "/api/admin/login",
        json={
            "email": secondary_admin["email"],
            "password": secondary_admin["_password"],
        },
    )
    assert resp.status_code == 200, f"Secondary admin login failed: {resp.text}"
    return resp.json()["access_token"]


@pytest.fixture()
def secondary_admin_headers(secondary_admin_token: str) -> dict[str, str]:
    """Authorization headers for secondary ADMIN requests."""
    return {"Authorization": f"Bearer {secondary_admin_token}"}


@pytest.fixture()
def managed_client(client: TestClient, main_admin_headers: dict) -> dict:
    """
    Create a managed client via the API. Returns the creation response
    which includes the one-time API key.
    """
    resp = client.post(
        "/api/admin/clients",
        json={
            "display_name": f"Test Client {os.urandom(3).hex()}",
            "contact_email": "testclient@example.com",
        },
        headers=main_admin_headers,
    )
    assert resp.status_code == 201
    return resp.json()
