"""
Application configuration.

Loads all runtime configuration from environment variables (via a local
.env file during development, or real process environment variables in
production). No secret value is ever hard-coded in this file.

SECURITY-SENSITIVE MODULE:
  - PRIVACY_SECRET_KEY, CLIENT_A/B/C_API_KEY, JWT_SECRET_KEY, and
    BOOTSTRAP_ADMIN_PASSWORD are read here once and held only in memory
    for the lifetime of the process.
  - This module must never print, log, or return these values.
  - The bootstrap password is used ONLY once to seed the MAIN_ADMIN
    account and is immediately discarded after hashing.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

from dotenv import load_dotenv

# Load variables from a .env file if present. load_dotenv() never
# overwrites a variable that is already set in the real process
# environment (override=False by default), so real deployment secrets
# always take precedence over a local .env file.
load_dotenv()


class ConfigurationError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


def _require_env(name: str) -> str:
    """Fetch a required environment variable or raise a safe error.

    The error message intentionally names only the variable, never its
    (absent) value, so it is always safe to log or print.
    """
    value = os.getenv(name)
    if not value or not value.strip():
        raise ConfigurationError(
            f"Missing required environment variable: {name}. "
            "Copy .env.example to .env and fill in a real value."
        )
    return value.strip()


@dataclass
class Settings:
    """Application settings, populated once at process start-up."""

    # Required fields (no defaults) — must come first in dataclass
    database_url: str
    privacy_secret_key: str
    privacy_key_version: str
    client_a_api_key: str
    client_b_api_key: str
    client_c_api_key: str

    # Admin JWT / auth settings
    jwt_secret_key: str = field(repr=False, default="")
    bootstrap_admin_email: str = field(repr=False, default="")
    bootstrap_admin_password: str = field(repr=False, default="")

    # Fields with defaults
    admin_access_token_expire_minutes: int = 30

    # Computed field — init=False means it is set in __post_init__
    client_api_keys: dict = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Mapping of internal client_id -> API key, used by app.auth.
        # repr=False and a plain dict (not printed anywhere) keep this
        # out of accidental logs / debugger output.
        self.client_api_keys = {
            "client_a": self.client_a_api_key,
            "client_b": self.client_b_api_key,
            "client_c": self.client_c_api_key,
        }

    def __repr__(self) -> str:  # pragma: no cover - defensive only
        # Never allow secrets to leak via repr()/print(settings).
        return "Settings(<redacted>)"


def load_settings() -> Settings:
    """
    Build the Settings object from environment variables.

    Raises ConfigurationError with a safe (non-sensitive) message if a
    required variable is missing.
    """
    return Settings(
        database_url=os.getenv("DATABASE_URL", "sqlite:///./threat_intelligence.db").strip(),
        privacy_secret_key=_require_env("PRIVACY_SECRET_KEY"),
        privacy_key_version=os.getenv("PRIVACY_KEY_VERSION", "1").strip(),
        client_a_api_key=_require_env("CLIENT_A_API_KEY"),
        client_b_api_key=_require_env("CLIENT_B_API_KEY"),
        client_c_api_key=_require_env("CLIENT_C_API_KEY"),
        jwt_secret_key=_require_env("JWT_SECRET_KEY"),
        admin_access_token_expire_minutes=int(
            os.getenv("ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES", "30").strip()
        ),
        bootstrap_admin_email=_require_env("BOOTSTRAP_ADMIN_EMAIL"),
        bootstrap_admin_password=_require_env("BOOTSTRAP_ADMIN_PASSWORD"),
    )


try:
    settings = load_settings()
except ConfigurationError as exc:
    # Fail fast with a clear, non-sensitive message instead of a
    # confusing traceback from deep inside privacy_engine.py later on.
    print(f"[CONFIGURATION ERROR] {exc}", file=sys.stderr)
    raise
