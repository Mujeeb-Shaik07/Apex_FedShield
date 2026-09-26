"""
OPTIONAL multi-client network demonstration for the Privacy-Preserving
Threat Intelligence Network.

This script is purely a demonstration client. It does NOT modify the
existing FastAPI backend, does NOT implement its own privacy hashing,
and does NOT assume any endpoint, field, or status code that isn't
actually present in app/main.py and app/schemas.py.

Confirmed by inspecting the existing backend before writing this file:

  * POST /api/ingest-log
      - request body: app.schemas.RawLog
          company_name: str
          internal_ip: str (IPv4/IPv6)
          attack_type: str
          failed_attempts: int (>= 0)
          target_service: str
          timestamp: timezone-aware ISO-8601 datetime
      - auth: X-API-Key header, validated by app.auth.require_api_key
      - success status: 201 Created
      - response body: app.schemas.SanitizedReport (report_id,
        created_at, threat_type, severity, impact_percentage,
        confidence, attack_pattern, mitigation, indicator_type,
        target_service) - company_name/internal_ip are never present
        in this model, by construction (see app/schemas.py).

  * GET /api/threat-feed
      - auth: X-API-Key header (same dependency)
      - query params: limit (1-100, default 20), offset (>=0)
      - success status: 200 OK
      - response body: app.schemas.ThreatFeedResponse
          count: int
          reports: list[SanitizedReport]

The simulator uses these exactly as they exist. No backend code was
modified to make this script work.

Flow per round, per simulated organization (run concurrently with
Python threads - NOT asyncio, NOT multiprocessing):

    Simulated Organization
            |
            v
    Raw Security Event (RawLog-shaped dict, kept local to this script)
            |
            v
    POST /api/ingest-log  (X-API-Key: <that org's real API key>)
            |
            v
    FastAPI Backend -> AI Analysis -> Privacy Engine -> SQLite
            |
            v
    GET /api/threat-feed
            |
            v
    Sanitized Threat Intelligence (printed - safe fields only)

Usage:

    # Terminal 1
    uvicorn app.main:app --reload

    # Terminal 2
    python simulate_network.py

Configuration (env vars, all optional except the three API keys which
are already required by the running backend):

    SIMULATE_BASE_URL   default: http://127.0.0.1:8000
    NUMBER_OF_ROUNDS     default: 5
    DELAY_SECONDS        default: 3
"""

from __future__ import annotations

import ipaddress
import os
import random
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration - overridable via environment variables, nothing hard-coded.
# ---------------------------------------------------------------------------

BASE_URL = os.getenv("SIMULATE_BASE_URL", "http://127.0.0.1:8000")
NUMBER_OF_ROUNDS = int(os.getenv("NUMBER_OF_ROUNDS", "5"))
DELAY_SECONDS = float(os.getenv("DELAY_SECONDS", "3"))
REQUEST_TIMEOUT_SECONDS = 10
FEED_LIMIT = 20

# API keys are read from the environment/.env only - never hard-coded,
# never printed. These are the exact same variable names app/config.py
# requires of the running backend.
_KEY_ENV_VARS = ("CLIENT_A_API_KEY", "CLIENT_B_API_KEY", "CLIENT_C_API_KEY")


def _require_client_keys() -> dict[str, str]:
    keys = {name: os.getenv(name) for name in _KEY_ENV_VARS}
    missing = [name for name, value in keys.items() if not value]
    if missing:
        print(f"Missing environment variables: {', '.join(missing)}.")
        print("Copy .env.example to .env (or use the provided .env) and try again.")
        sys.exit(1)
    return keys  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Simulated organizations.
#
# Each organization's real name and internal IP range are used ONLY to
# build the local RawLog-shaped payload sent to POST /api/ingest-log.
# They are never printed by this script - see SimClient.run_round()
# below, which only ever prints the safe CLIENT-* label.
# ---------------------------------------------------------------------------

_ATTACK_TYPES = [
    "Brute Force",
    "SQL Injection",
    "Malware",
    "Phishing",
    "DDoS",
    "Port Scanning",
    "Credential Stuffing",
    "Ransomware",
]
_TARGET_SERVICES = ["SSH", "HTTP", "HTTPS", "RDP", "VPN", "FTP", "SMTP", "DNS"]


@dataclass
class SimOrganization:
    """A simulated external organization. Never printed as-is."""

    company_name: str
    ip_network: str  # private CIDR this org's fake internal hosts live in
    safe_label: str  # the ONLY identifier this script ever prints
    api_key_env: str


ORGANIZATIONS: list[SimOrganization] = [
    SimOrganization("Apex Bank", "10.20.0.0/16", "CLIENT-A", "CLIENT_A_API_KEY"),
    SimOrganization("HealthCare Plus", "10.30.0.0/16", "CLIENT-B", "CLIENT_B_API_KEY"),
    SimOrganization("Retail Corporation", "10.40.0.0/16", "CLIENT-C", "CLIENT_C_API_KEY"),
]


def _generate_raw_event(org: SimOrganization) -> dict:
    """
    Build one fake-but-realistic RawLog-shaped payload for `org`.

    Every field required by app.schemas.RawLog is included. This
    function returns a plain dict that lives only in local memory for
    the caller; it is never logged or printed by this script.
    """
    network = ipaddress.ip_network(org.ip_network)
    host_int = random.randint(1, network.num_addresses - 2)
    fake_internal_ip = str(network[host_int])

    return {
        "company_name": org.company_name,
        "internal_ip": fake_internal_ip,
        "attack_type": random.choice(_ATTACK_TYPES),
        "failed_attempts": random.randint(1, 800),
        "target_service": random.choice(_TARGET_SERVICES),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Thread-safe run summary.
# ---------------------------------------------------------------------------


@dataclass
class RunSummary:
    lock: threading.Lock = field(default_factory=threading.Lock)
    events_submitted: dict[str, int] = field(default_factory=lambda: {o.safe_label: 0 for o in ORGANIZATIONS})
    sanitized_reports_received: int = 0
    company_identity_exposed: bool = False
    internal_ip_exposed: bool = False
    api_key_exposed: bool = False  # this script never sends a key anywhere but the header, so stays False
    privacy_secret_exposed: bool = False  # this script never has access to the privacy secret at all

    def record_event(self, label: str) -> None:
        with self.lock:
            self.events_submitted[label] += 1

    def record_feed_fetch(self, report_count: int) -> None:
        with self.lock:
            self.sanitized_reports_received += report_count

    def flag_company_exposed(self) -> None:
        with self.lock:
            self.company_identity_exposed = True

    def flag_ip_exposed(self) -> None:
        with self.lock:
            self.internal_ip_exposed = True


_print_lock = threading.Lock()


def _safe_print(message: str) -> None:
    """Serialize prints across threads so lines from different clients don't interleave."""
    with _print_lock:
        print(message)


# ---------------------------------------------------------------------------
# Per-client worker.
# ---------------------------------------------------------------------------


class SimClient:
    """
    Runs NUMBER_OF_ROUNDS ingest+feed cycles for one simulated
    organization, on its own thread, using that organization's real
    API key (via require_api_key on the backend). Behaves purely as an
    external HTTP client of the existing API - no direct DB or
    privacy-engine access.
    """

    def __init__(self, org: SimOrganization, api_key: str, summary: RunSummary) -> None:
        self.org = org
        self.api_key = api_key
        self.summary = summary
        self.session = requests.Session()

    def _headers(self) -> dict[str, str]:
        return {"X-API-Key": self.api_key}

    def _ingest_event(self, round_number: int) -> dict | None:
        raw_event = _generate_raw_event(self.org)

        try:
            response = self.session.post(
                f"{BASE_URL}/api/ingest-log",
                json=raw_event,
                headers=self._headers(),
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            _safe_print(f"[{self.org.safe_label}] round {round_number}: request failed ({type(exc).__name__})")
            return None

        if response.status_code != 201:
            _safe_print(
                f"[{self.org.safe_label}] round {round_number}: "
                f"unexpected status {response.status_code} from /api/ingest-log"
            )
            return None

        sanitized = response.json()
        response_text = str(sanitized)

        # Privacy checks - compare against the raw values held only in
        # this function's local scope; never print the raw values
        # themselves, only the pass/fail outcome.
        if raw_event["company_name"] in response_text:
            self.summary.flag_company_exposed()
            _safe_print(f"[{self.org.safe_label}] round {round_number}: *** PRIVACY VIOLATION: company identity exposed ***")
        if raw_event["internal_ip"] in response_text:
            self.summary.flag_ip_exposed()
            _safe_print(f"[{self.org.safe_label}] round {round_number}: *** PRIVACY VIOLATION: internal IP exposed ***")

        self.summary.record_event(self.org.safe_label)
        _safe_print(
            f"[{self.org.safe_label}] round {round_number}: submitted event -> "
            f"report_id={sanitized['report_id']} severity={sanitized['severity']} "
            f"impact={sanitized['impact_percentage']}%"
        )
        return sanitized

    def _fetch_feed(self, round_number: int) -> None:
        try:
            response = self.session.get(
                f"{BASE_URL}/api/threat-feed",
                headers=self._headers(),
                params={"limit": FEED_LIMIT},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            _safe_print(f"[{self.org.safe_label}] round {round_number}: feed request failed ({type(exc).__name__})")
            return

        if response.status_code != 200:
            _safe_print(
                f"[{self.org.safe_label}] round {round_number}: "
                f"unexpected status {response.status_code} from /api/threat-feed"
            )
            return

        payload = response.json()
        reports = payload["reports"]
        self.summary.record_feed_fetch(len(reports))

        _safe_print(f"[{self.org.safe_label}] round {round_number}: threat feed has {payload['count']} available threat(s)")
        for report in reports[:3]:
            # Only ever prints fields present on SanitizedReport - no
            # raw/company/IP fields exist on this model to begin with.
            _safe_print(
                f"    - {report['threat_type']} | severity={report['severity']} "
                f"| impact={report['impact_percentage']}% | confidence={report['confidence']} "
                f"| indicator_type={report['indicator_type']} | target={report['target_service']}"
            )

    def run(self) -> None:
        for round_number in range(1, NUMBER_OF_ROUNDS + 1):
            self._ingest_event(round_number)
            self._fetch_feed(round_number)
            if round_number < NUMBER_OF_ROUNDS:
                time.sleep(DELAY_SECONDS)


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def _check_backend_reachable() -> bool:
    try:
        response = requests.get(f"{BASE_URL}/api/health", timeout=REQUEST_TIMEOUT_SECONDS)
        return response.status_code == 200
    except requests.RequestException:
        return False


def main() -> None:
    keys_by_env = _require_client_keys()

    if not _check_backend_reachable():
        print(f"Could not reach the backend at {BASE_URL}/api/health.")
        print("Start it first with: uvicorn app.main:app --reload")
        sys.exit(1)

    print("=" * 60)
    print("MULTI-CLIENT NETWORK SIMULATION")
    print(f"Organizations: {len(ORGANIZATIONS)} | Rounds: {NUMBER_OF_ROUNDS} | Delay: {DELAY_SECONDS}s")
    print("=" * 60)

    summary = RunSummary()
    clients = [SimClient(org, keys_by_env[org.api_key_env], summary) for org in ORGANIZATIONS]

    threads = [threading.Thread(target=client.run, name=client.org.safe_label) for client in clients]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print("\n" + "=" * 40)
    print("MULTI-CLIENT NETWORK SUMMARY")
    print("=" * 40)
    for org in ORGANIZATIONS:
        print(f"Client {org.safe_label[-1]}: events submitted = {summary.events_submitted[org.safe_label]}")
    print(f"\nSanitized reports received: {summary.sanitized_reports_received}")
    print("\nPrivacy checks:")
    print(f"Company identities exposed: {'YES' if summary.company_identity_exposed else 'NO'}")
    print(f"Internal IPs exposed: {'YES' if summary.internal_ip_exposed else 'NO'}")
    print(f"API keys exposed: {'YES' if summary.api_key_exposed else 'NO'}")
    print(f"Privacy secrets exposed: {'YES' if summary.privacy_secret_exposed else 'NO'}")

    if summary.company_identity_exposed or summary.internal_ip_exposed:
        sys.exit(1)


if __name__ == "__main__":
    main()
