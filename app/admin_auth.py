"""
Administrator authentication and authorization for the
Privacy-Preserving Threat Intelligence Network.

SECURITY-SENSITIVE MODULE:
  - Password verification uses Argon2 via pwdlib (constant-time).
  - JWT access tokens are signed with HS256; the secret is read from
    app.config (environment variable JWT_SECRET_KEY).
  - Tokens carry admin_id, role, token_version, and expiration.
  - Tokens NEVER carry passwords or password hashes.
  - Every protected endpoint must call get_current_admin() or a role-
    specific derivative (require_main_admin).
  - Token version is verified on every request against the live DB row,
    so deactivating/removing an admin immediately invalidates all
    outstanding tokens — even unexpired ones.
  - This module must NEVER log passwords, tokens, or signing secrets.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import Depends, Header, HTTPException, status
from jose import JWTError, jwt
from pwdlib import PasswordHash
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.db_models import Admin, AdminRole, AuditLog

# ---------------------------------------------------------------------------
# Password hashing — Argon2 via pwdlib
# ---------------------------------------------------------------------------

_password_hasher: PasswordHash = PasswordHash.recommended()


def hash_password(plaintext: str) -> str:
    """Hash a plaintext password with Argon2. Return the hash string only."""
    return _password_hasher.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    """Verify a plaintext password against its Argon2 hash.

    Uses constant-time comparison internally (pwdlib / argon2-cffi).
    Returns True only if the password matches.
    """
    try:
        return _password_hasher.verify(plaintext, hashed)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JWT token generation / decoding
# ---------------------------------------------------------------------------

_ALGORITHM = "HS256"
_TOKEN_TYPE = "bearer"


def create_access_token(admin_id: str, role: str, token_version: int) -> str:
    """
    Generate a signed JWT access token for an admin user.

    Payload fields:
      sub           — admin_id (subject)
      role          — MAIN_ADMIN | ADMIN
      tv            — token_version (incremented on deactivation/removal)
      exp           — expiration timestamp
      iat           — issued-at timestamp
      jti           — unique token ID (allows future blacklisting if needed)

    SECURITY: The token NEVER includes the password or password_hash.
    """
    now = dt.datetime.now(dt.timezone.utc)
    expire = now + dt.timedelta(minutes=settings.admin_access_token_expire_minutes)

    payload = {
        "sub": admin_id,
        "role": role,
        "tv": token_version,
        "exp": expire,
        "iat": now,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=_ALGORITHM)


def _decode_token(token: str) -> dict:
    """
    Decode and verify the JWT. Raises HTTPException 401 on any failure.

    Does NOT check the database — that is done by get_current_admin().
    """
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[_ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------


def _extract_bearer_token(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> str:
    """Extract the raw token from 'Authorization: Bearer <token>'."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return authorization[len("Bearer "):]


def get_current_admin(
    token: str = Depends(_extract_bearer_token),
    db: Session = Depends(get_db),
) -> Admin:
    """
    FastAPI dependency: validate the JWT and return the live Admin ORM row.

    Checks (in order):
      1. Valid JWT signature and structure
      2. Token not expired (handled by jose)
      3. Admin row exists in the database
      4. Admin is_active == True
      5. token_version in JWT matches the stored token_version
         (ensures deactivation/removal immediately invalidates tokens)
      6. Role is a known admin role

    Raises HTTP 401 or 403 on any failure.
    NEVER leaks which specific check failed to the caller.
    """
    payload = _decode_token(token)

    admin_id: str | None = payload.get("sub")
    role: str | None = payload.get("role")
    token_version: int | None = payload.get("tv")

    if not admin_id or not role or token_version is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    # Verify admin still exists, is active, and token_version matches.
    admin: Admin | None = db.query(Admin).filter(Admin.admin_id == admin_id).first()
    if admin is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin account not found",
        )
    if not admin.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin account is not active",
        )
    if admin.token_version != token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )
    if admin.role not in AdminRole.ALL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unknown role",
        )

    return admin


def require_main_admin(
    current_admin: Admin = Depends(get_current_admin),
) -> Admin:
    """
    FastAPI dependency: require the current admin to be MAIN_ADMIN.

    ADMIN role is rejected with 403 Forbidden.
    """
    if current_admin.role != AdminRole.MAIN_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires MAIN_ADMIN privileges",
        )
    return current_admin


# ---------------------------------------------------------------------------
# Audit logging helper
# ---------------------------------------------------------------------------


def create_audit_log(
    db: Session,
    *,
    actor_admin_id: str | None,
    actor_role: str | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    success: bool = True,
    metadata_summary: str | None = None,
) -> None:
    """
    Persist a single audit log entry.

    SECURITY: metadata_summary must NEVER contain passwords, API keys,
    hashes, JWTs, privacy secrets, or internal IP addresses.
    """
    entry = AuditLog(
        event_id=uuid.uuid4().hex,
        actor_admin_id=actor_admin_id,
        actor_role=actor_role,
        action=action,
        target_type=target_type,
        target_id=target_id,
        success=success,
        created_at=dt.datetime.now(dt.timezone.utc),
        metadata_summary=metadata_summary,
    )
    db.add(entry)
    # Caller is responsible for commit (allows batching with the main operation).
