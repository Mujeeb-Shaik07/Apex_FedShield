"""
Client simulation script for the Privacy-Preserving Threat Intelligence
Network.

Demonstrates the full hackathon workflow end-to-end:

  1. Client A ingests a raw security event (containing a company name
     and an internal IP address that must never leave the server).
  2. The sanitized response is printed - and we explicitly prove the
     company name and internal IP are absent from it.
  3. Clients A, B, and C each retrieve the sanitized threat feed.
  4. Each client "acts" on the intelligence by printing a SIMULATED
     firewall / security-control recommendation. This script does NOT
     touch the real operating system firewall or any network device in
     any way - it only prints text.

Usage:

    # Terminal 1
    uvicorn app.main:app --reload

    # Terminal 2
    python simulate_clients.py
"""

from __future__ import annotations

import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()

BASE_URL = os.getenv("SIMULATE_BASE_URL", "http://127.0.0.1:8000")

# API keys are read from the environment only. This script never prints
# them, and never hard-codes them.
CLIENT_A_API_KEY = os.getenv("CLIENT_A_API_KEY")
CLIENT_B_API_KEY = os.getenv("CLIENT_B_API_KEY")
CLIENT_C_API_KEY = os.getenv("CLIENT_C_API_KEY")


def _require_client_keys() -> None:
    missing = [
        name
        for name, value in (
            ("CLIENT_A_API_KEY", CLIENT_A_API_KEY),
            ("CLIENT_B_API_KEY", CLIENT_B_API_KEY),
            ("CLIENT_C_API_KEY", CLIENT_C_API_KEY),
        )
        if not value
    ]
    if missing:
        print(f"Missing environment variables: {', '.join(missing)}.")
        print("Copy .env.example to .env (or use the provided .env) and try again.")
        sys.exit(1)


def ingest_sample_event() -> dict:
    """
    Steps 1-4: Client A submits a raw event to /api/ingest-log.

    The raw event dictionary exists only inside this function, in
    memory, for the single purpose of demonstrating the ingestion flow.
    It is intentionally never printed by this script.
    """
    raw_event = {
        "company_name": "Alpha Cyber Systems",
        "internal_ip": "10.10.20.25",
        "attack_type": "Brute Force",
        "failed_attempts": 150,
        "target_service": "SSH",
        "timestamp": "2026-09-25T10:30:00+05:30",
    }

    print("=" * 72)
    print("STEP 1: Client A submits a raw security event to /api/ingest-log")
    print("(Raw input is intentionally NOT printed by this script.)")
    print("=" * 72)

    response = requests.post(
        f"{BASE_URL}/api/ingest-log",
        json=raw_event,
        headers={"X-API-Key": CLIENT_A_API_KEY},
        timeout=10,
    )
    response.raise_for_status()
    sanitized = response.json()

    print("\nSanitized response returned to Client A:")
    for key, value in sanitized.items():
        print(f"  {key}: {value}")

    # Explicitly demonstrate that no sensitive raw data leaked out.
    response_text = str(sanitized)
    company_present = raw_event["company_name"] in response_text
    ip_present = raw_event["internal_ip"] in response_text

    print(f"\nCompany name present in response? {company_present}")
    print(f"Internal IP present in response? {ip_present}")

    if company_present or ip_present:
        print("\n*** PRIVACY VIOLATION DETECTED - sensitive data leaked into the response! ***")
        sys.exit(1)

    return sanitized


def fetch_feed(client_label: str, api_key: str) -> list[dict]:
    """Retrieve the sanitized threat feed for one client."""
    response = requests.get(
        f"{BASE_URL}/api/threat-feed",
        headers={"X-API-Key": api_key},
        params={"limit": 20},
        timeout=10,
    )
    response.raise_for_status()
    payload = response.json()
    reports = payload["reports"]

    print(f"\n{client_label} -> sanitized intelligence ({len(reports)} report(s) returned):")
    for report in reports[:3]:
        print(
            f"  - {report['threat_type']} | severity={report['severity']} "
            f"| impact={report['impact_percentage']}% | confidence={report['confidence']}"
        )

    return reports


def simulate_firewall_action(client_label: str, reports: list[dict]) -> None:
    """
    Print a SIMULATED firewall / security-control action based on the
    threat feed.

    IMPORTANT: this function does NOT modify any real operating system
    firewall, network device, or security appliance. It only prints
    text to demonstrate what a downstream consumer of the feed might do.
    """
    if not reports:
        print(f"[{client_label} Firewall] No threats in feed yet - nothing to act on.")
        return

    latest = reports[0]
    print(f"[{client_label} Firewall] Threat received: {latest['threat_type']}")
    print(f"[{client_label} Firewall] Action recommendation: {latest['mitigation']}")
    print(f"[{client_label} Firewall] (SIMULATED ONLY - no real firewall or OS setting was changed)")


def main() -> None:
    _require_client_keys()

    ingest_sample_event()

    print("\n" + "=" * 72)
    print("STEPS 5-7: Clients A, B, and C retrieve the sanitized threat feed")
    print("=" * 72)

    reports_a = fetch_feed("Client A", CLIENT_A_API_KEY)
    reports_b = fetch_feed("Client B", CLIENT_B_API_KEY)
    reports_c = fetch_feed("Client C", CLIENT_C_API_KEY)

    print("\n" + "=" * 72)
    print("Simulated downstream security-control actions (no OS changes made)")
    print("=" * 72)
    simulate_firewall_action("Client A", reports_a)
    simulate_firewall_action("Client B", reports_b)
    simulate_firewall_action("Client C", reports_c)

    print("\nDemo complete. No company names, internal IPs, or secrets were ever printed.")


if __name__ == "__main__":
    main()
