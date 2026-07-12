"""API-level ingest/query smoke tests with fakes."""

from __future__ import annotations

import json


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"


def test_ingest_and_list(client, sample_scan):
    r = client.post("/ingest", json={"scan": sample_scan})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["findings_ingested"] == 15
    assert body["scan_id"] == sample_scan["scan_id"]

    r2 = client.get(f"/scans/{sample_scan['scan_id']}/findings")
    assert r2.status_code == 200
    assert len(r2.json()) == 15


def test_ingest_validation_error(client):
    r = client.post("/ingest", json={"scan": {"scan_id": "x"}})
    assert r.status_code == 422


def test_query_after_ingest(client, sample_scan, fake_llm):
    client.post("/ingest", json={"scan": sample_scan})
    fake_llm.responses = [
        json.dumps(
            {
                "intent": "severity",
                "severity": "CRITICAL",
                "cwe_id": None,
                "owasp": None,
                "endpoint": None,
                "finding_id": None,
                "keywords": [],
            }
        ),
        json.dumps(
            {
                "answer": "Critical findings are FINDING-001 and FINDING-004.",
                "findings_referenced": ["FINDING-001", "FINDING-004"],
                "reference_ids": ["CWE-89"],
                "abstained": False,
            }
        ),
    ]
    r = client.post(
        "/query",
        json={"question": "What are all the critical severity findings?"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["grounded"] is True
    assert "FINDING-001" in body["findings_referenced"]
    assert body["latency_ms"] >= 0
