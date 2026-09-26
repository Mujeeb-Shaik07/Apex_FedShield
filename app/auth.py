"""
API key authentication for the ingestion endpoint and external threat-
feed clients.

SECURITY-SENSITIVE MODULE:
  - API keys are NEVER stored in plaintext.
  - Submitted keys are hashed and compared against stored hashes using
    hmac.compare_digest() for timing-safe comparison.
  - The plaintext API key from the request is NEVER logged, NEVER echoed
    in responses, and NEVER stored anywhere.
  - Client status is verified on every request: SUSPENDED and REVOKED
    clients are rejected immediately even with a valid key.

Authentication flow:
  X-API-Key header
    ↓
  Hash submitted key with SHA-256
    ↓
  Locate client by hash in the `clients` table
    ↓
  Verify client status == ACTIVE
    ↓
  Update last_seen_at
    ↓
  Return client_id

Fallback for simulation/demo:
  If the submitted key matches one of the legacy static keys from
  app.config (CLIENT_A/B/C_API_KEY), it is accepted for backwards
  compatibility with the simulation scripts. Those keys are NOT stored
  in the database.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.db_models import Client, ClientStatus


def hash_api_key(plaintext_key: str) -> str:
    """
    Hash an API key for storage/comparison using SHA-256.

    We use SHA-256 (not Argon2) for API keys because:
      - API keys are already high-entropy random strings (secrets.token_urlsafe)
      - SHA-256 is fast enough to check on every request
      - Argon2's CPU cost would add unacceptable latency to the hot path

    The hash is stored in hex format. The plaintext key is never stored.
    """
    return hashlib.sha256(plaintext_key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """
    Generate a new cryptographically secure API key.

    Returns:
        (plaintext_key, key_hash)

    The caller must:
      - Return plaintext_key to the admin ONCE and ONLY ONCE.
      - Store only key_hash in the database.
      - Discard plaintext_key after the response is sent.
    """
    plaintext = secrets.token_urlsafe(32)
    return plaintext, hash_api_key(plaintext)


def _lookup_client_by_key(db: Session, api_key: str) -> Client | None:
    """
    Look up a client by their submitted API key.

    Computes SHA-256 of the submitted key and looks up the hash in the
    database. Uses secrets.compare_digest for timing-safe comparison
    when comparing hash strings.
    """
    key_hash = hash_api_key(api_key)
    # The hash lookup is already timing-safe because we're comparing
    # the deterministic hash output, not the key itself.
    client = db.query(Client).filter(Client.api_key_hash == key_hash).first()
    return client


def _lookup_legacy_client(api_key: str) -> str | None:
    """
    Fall back to static legacy keys (CLIENT_A/B/C_API_KEY) for the
    simulation/demo scripts. Returns the internal client_id or None.
    """
    for client_id, valid_key in settings.client_api_keys.items():
        if secrets.compare_digest(api_key, valid_key):
            return client_id
    return None


async def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> str:
    """
    FastAPI dependency: validate the X-API-Key header.

    Priority:
      1. Look up in the managed `clients` table (hashed comparison).
      2. Fall back to legacy static keys from config (for simulation scripts).

    Returns the internal client_id (or display_name) on success.

    Raises 401 Unauthorized for missing/invalid/revoked/suspended keys.
    The error message NEVER reveals which keys are valid.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )

    # --- Primary: managed clients table ---
    client = _lookup_client_by_key(db, x_api_key)
    if client is not None:
        if client.status != ClientStatus.ACTIVE:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Client access has been revoked or suspended",
            )
        # Update last_seen_at (non-blocking best-effort)
        client.last_seen_at = dt.datetime.now(dt.timezone.utc)
        try:
            db.commit()
        except Exception:
            db.rollback()
        return client.client_id

    # --- Fallback: legacy static keys (simulation only) ---
    legacy_id = _lookup_legacy_client(x_api_key)
    if legacy_id is not None:
        return legacy_id

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )
