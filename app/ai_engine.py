"""
Deterministic MOCK AI threat-analysis engine.

This module does NOT call OpenAI, Gemini, Claude, or any other external
AI/LLM service. It implements a fully offline, deterministic scoring
system so the hackathon prototype can run without network access or
third-party API keys.

This AI analysis layer is a deterministic mock engine used to
demonstrate the architecture. A production deployment could replace it
with a validated ML/AI model.

Scoring rules (see README.md "Threat-analysis logic" for the same
documentation):

  1. Each canonical attack type has a BASE_IMPACT score (0-100) and a
     BASE_CONFIDENCE score (0.0-1.0).
  2. failed_attempts is bucketed and adds a deterministic modifier to
     both impact and confidence:

         0-9      -> impact +0,  confidence +0.00
         10-49    -> impact +5,  confidence +0.05
         50-99    -> impact +10, confidence +0.10
         100-499  -> impact +15, confidence +0.15
         500+     -> impact +20, confidence +0.20

  3. impact_percentage = min(100, base_impact + impact_modifier)
     confidence         = min(1.00, base_confidence + confidence_modifier)
  4. severity is derived from the FINAL impact_percentage:

         0-39    -> LOW
         40-69   -> MEDIUM
         70-89   -> HIGH
         90-100  -> CRITICAL

Notably, this engine only reads raw_log.attack_type and
raw_log.failed_attempts - it never reads company_name or internal_ip,
because organizational identity is not needed to assess a threat.
"""

from __future__ import annotations

from app.schemas import RawLog, ThreatAnalysis

# ---------------------------------------------------------------------------
# Deterministic scoring tables
# ---------------------------------------------------------------------------

BASE_IMPACT: dict[str, int] = {
    "Brute Force": 60,
    "SQL Injection": 85,
    "Malware": 90,
    "Phishing": 65,
    "DDoS": 95,
    "Port Scanning": 35,
    "Credential Stuffing": 75,
    "Ransomware": 98,
}

# Base confidence values are chosen so that the worked example in the
# project spec (Brute Force + 150 failed attempts -> confidence 0.95)
# holds exactly: 0.80 base + 0.15 modifier (100-499 bucket) = 0.95.
BASE_CONFIDENCE: dict[str, float] = {
    "Brute Force": 0.80,
    "SQL Injection": 0.85,
    "Malware": 0.75,
    "Phishing": 0.70,
    "DDoS": 0.85,
    "Port Scanning": 0.65,
    "Credential Stuffing": 0.80,
    "Ransomware": 0.75,
}

ATTACK_PATTERNS: dict[str, str] = {
    "Brute Force": "Repeated authentication failures detected",
    "SQL Injection": "Malicious SQL syntax detected in request parameters",
    "Malware": "Indicators consistent with malicious executable activity",
    "Phishing": "Deceptive communication designed to harvest credentials",
    "DDoS": "High-volume traffic consistent with distributed denial of service",
    "Port Scanning": "Sequential connection attempts observed across multiple ports",
    "Credential Stuffing": "Automated login attempts consistent with leaked credential pairs",
    "Ransomware": "File-access behavior consistent with ransomware activity",
}

MITIGATIONS: dict[str, str] = {
    "Brute Force": "Enable MFA, apply rate limiting, and temporarily block repeated failed authentication attempts",
    "SQL Injection": "Use parameterized queries, apply input validation, and deploy a web application firewall",
    "Malware": "Isolate affected hosts, run endpoint detection scans, and update signature databases",
    "Phishing": "Alert affected users, block sender domains, and enforce SPF/DKIM/DMARC email authentication",
    "DDoS": "Enable upstream traffic scrubbing, rate limiting, and DDoS protection services",
    "Port Scanning": "Restrict exposed ports, enable intrusion detection, and review firewall rules",
    "Credential Stuffing": "Enforce MFA, deploy credential-stuffing detection, and monitor for leaked credential dumps",
    "Ransomware": "Isolate affected systems immediately, restore from clean backups, and rotate all credentials",
}

# Keyword synonyms mapped to canonical attack-type names, checked in
# order so more specific phrases are matched before more general ones
# (e.g. "credential stuffing" is checked before "brute force").
_KEYWORD_MAP: list[tuple[str, str]] = [
    ("ransomware", "Ransomware"),
    ("credential stuffing", "Credential Stuffing"),
    ("credential_stuffing", "Credential Stuffing"),
    ("sql injection", "SQL Injection"),
    ("sql_injection", "SQL Injection"),
    ("sqli", "SQL Injection"),
    ("ddos", "DDoS"),
    ("denial of service", "DDoS"),
    ("denial-of-service", "DDoS"),
    ("port scan", "Port Scanning"),
    ("port_scan", "Port Scanning"),
    ("phishing", "Phishing"),
    ("malware", "Malware"),
    ("trojan", "Malware"),
    ("virus", "Malware"),
    ("brute force", "Brute Force"),
    ("brute_force", "Brute Force"),
    ("bruteforce", "Brute Force"),
]

DEFAULT_THREAT_TYPE = "Unknown"
DEFAULT_BASE_IMPACT = 50
DEFAULT_BASE_CONFIDENCE = 0.40
DEFAULT_ATTACK_PATTERN = "Anomalous activity that did not match a known attack signature"
DEFAULT_MITIGATION = "Escalate to a security analyst for manual triage and further investigation"

# All events processed by this MVP originate from internal network
# telemetry (failed logins, scans, etc.), so every report is tagged
# with the same indicator_type. A future version could differentiate
# this based on additional raw_log fields.
INDICATOR_TYPE = "INTERNAL_NETWORK_EVENT"


def _classify_attack_type(attack_type_raw: str) -> str:
    """Deterministically map free-text attack_type input to one of the
    eight known canonical attack categories, or DEFAULT_THREAT_TYPE if
    no known keyword matches."""
    normalized = attack_type_raw.strip().lower()

    for canonical in BASE_IMPACT:
        if normalized == canonical.lower():
            return canonical

    for keyword, canonical in _KEYWORD_MAP:
        if keyword in normalized:
            return canonical

    return DEFAULT_THREAT_TYPE


def _impact_modifier(failed_attempts: int) -> int:
    """Deterministic impact modifier based on the failed_attempts bucket."""
    if failed_attempts >= 500:
        return 20
    if failed_attempts >= 100:
        return 15
    if failed_attempts >= 50:
        return 10
    if failed_attempts >= 10:
        return 5
    return 0


def _confidence_modifier(failed_attempts: int) -> float:
    """Deterministic confidence modifier, using the same buckets as impact."""
    if failed_attempts >= 500:
        return 0.20
    if failed_attempts >= 100:
        return 0.15
    if failed_attempts >= 50:
        return 0.10
    if failed_attempts >= 10:
        return 0.05
    return 0.00


def _severity_from_impact(impact_percentage: int) -> str:
    """Deterministic severity bucket derived from the final impact percentage."""
    if impact_percentage >= 90:
        return "CRITICAL"
    if impact_percentage >= 70:
        return "HIGH"
    if impact_percentage >= 40:
        return "MEDIUM"
    return "LOW"


def analyze_threat(raw_log: RawLog) -> ThreatAnalysis:
    """
    Run the deterministic mock AI threat analysis.

    Reads only raw_log.attack_type and raw_log.failed_attempts. Does
    NOT read (or need) company_name or internal_ip, and does not
    transmit anything to an external service - the whole computation is
    local, offline, and deterministic.
    """
    canonical_type = _classify_attack_type(raw_log.attack_type)

    base_impact = BASE_IMPACT.get(canonical_type, DEFAULT_BASE_IMPACT)
    base_confidence = BASE_CONFIDENCE.get(canonical_type, DEFAULT_BASE_CONFIDENCE)

    impact = min(100, base_impact + _impact_modifier(raw_log.failed_attempts))
    confidence = min(1.0, round(base_confidence + _confidence_modifier(raw_log.failed_attempts), 2))
    severity = _severity_from_impact(impact)

    attack_pattern = ATTACK_PATTERNS.get(canonical_type, DEFAULT_ATTACK_PATTERN)
    mitigation = MITIGATIONS.get(canonical_type, DEFAULT_MITIGATION)

    return ThreatAnalysis(
        threat_type=canonical_type,
        severity=severity,
        impact_percentage=impact,
        confidence=confidence,
        attack_pattern=attack_pattern,
        mitigation=mitigation,
    )
