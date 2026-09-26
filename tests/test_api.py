"""
Integration tests for the FastAPI application (spec tests 10-17), using
the fixtures defined in tests/conftest.py.
"""

from __future__ import annotations

SAMPLE_EVENT = {
    "company_name": "Alpha Cyber Systems",
    "internal_ip": "10.0.0.25",
    "attack_type": "Brute Force",
    "failed_attempts": 150,
    "target_service": "SSH",
    "timestamp": "2026-09-25T10:30:00+05:30",
}


def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


# TEST 10: POST /api/ingest-log returns HTTP 201.
def test_ingest_log_returns_201(client, client_a_headers):
    response = client.post("/api/ingest-log", json=SAMPLE_EVENT, headers=client_a_headers)
    assert response.status_code == 201


# TEST 11 & 12: Response does not contain company name / internal IP.
def test_ingest_log_response_excludes_sensitive_fields(client, client_a_headers):
    response = client.post("/api/ingest-log", json=SAMPLE_EVENT, headers=client_a_headers)
    body = response.json()
    body_text = str(body)

    assert "Alpha Cyber Systems" not in body_text
    assert "10.0.0.25" not in body_text
    assert "company_name" not in body
    assert "internal_ip" not in body
    assert "organization_token" not in body
    assert "indicator_token" not in body

    assert body["threat_type"] == "Brute Force"
    assert body["severity"] == "HIGH"
    assert body["impact_percentage"] == 75
    assert body["confidence"] == 0.95
    assert body["indicator_type"] == "INTERNAL_NETWORK_EVENT"
    assert body["target_service"] == "SSH"


def test_ingest_log_without_api_key_is_rejected(client):
    response = client.post("/api/ingest-log", json=SAMPLE_EVENT)
    assert response.status_code == 401


def test_ingest_log_with_invalid_api_key_is_rejected(client):
    response = client.post("/api/ingest-log", json=SAMPLE_EVENT, headers={"X-API-Key": "wrong-key"})
    assert response.status_code == 401


def test_ingest_log_rejects_invalid_ip(client, client_a_headers):
    bad_event = dict(SAMPLE_EVENT, internal_ip="not-an-ip")
    response = client.post("/api/ingest-log", json=bad_event, headers=client_a_headers)
    assert response.status_code == 422


def test_ingest_log_rejects_negative_failed_attempts(client, client_a_headers):
    bad_event = dict(SAMPLE_EVENT, failed_attempts=-5)
    response = client.post("/api/ingest-log", json=bad_event, headers=client_a_headers)
    assert response.status_code == 422


# TEST 13: Unauthenticated feed request returns HTTP 401.
def test_threat_feed_without_api_key_is_rejected(client):
    response = client.get("/api/threat-feed")
    assert response.status_code == 401


# TEST 14: Invalid API key returns HTTP 401.
def test_threat_feed_with_invalid_api_key_is_rejected(client):
    response = client.get("/api/threat-feed", headers={"X-API-Key": "not-a-real-key"})
    assert response.status_code == 401


# TEST 15: Valid client receives feed.
def test_valid_clients_receive_feed(client, client_a_headers, client_b_headers, client_c_headers):
    client.post("/api/ingest-log", json=SAMPLE_EVENT, headers=client_a_headers)

    for headers in (client_a_headers, client_b_headers, client_c_headers):
        response = client.get("/api/threat-feed", headers=headers)
        assert response.status_code == 200
        payload = response.json()
        assert payload["count"] >= 1
        assert len(payload["reports"]) >= 1


# TEST 16 & 17: Feed does not contain raw company name / internal IP.
def test_feed_excludes_raw_sensitive_data(client, client_a_headers):
    client.post("/api/ingest-log", json=SAMPLE_EVENT, headers=client_a_headers)

    response = client.get("/api/threat-feed", headers=client_a_headers)
    feed_text = response.text

    assert "Alpha Cyber Systems" not in feed_text
    assert "10.0.0.25" not in feed_text


def test_threat_feed_limit_validation(client, client_a_headers):
    response = client.get("/api/threat-feed", headers=client_a_headers, params={"limit": 0})
    assert response.status_code == 422

    response = client.get("/api/threat-feed", headers=client_a_headers, params={"limit": 101})
    assert response.status_code == 422


def test_threat_feed_default_and_max_limit(client, client_a_headers):
    response = client.get("/api/threat-feed", headers=client_a_headers)
    assert response.status_code == 200

    response = client.get("/api/threat-feed", headers=client_a_headers, params={"limit": 100})
    assert response.status_code == 200


def test_stats_endpoint_returns_safe_aggregates(client, client_a_headers):
    client.post("/api/ingest-log", json=SAMPLE_EVENT, headers=client_a_headers)
    response = client.get("/api/stats")
    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {
        "total_reports",
        "critical_reports",
        "high_reports",
        "medium_reports",
        "low_reports",
    }
    assert body["total_reports"] >= 1
    assert body["high_reports"] >= 1


def test_no_raw_data_endpoints_exist(client, client_a_headers):
    for path in ("/raw-logs", "/organizations", "/internal-network", "/company-details"):
        response = client.get(path, headers=client_a_headers)
        assert response.status_code == 404
