"""Default LLM call-budget integration tests with the deterministic fake model."""

from __future__ import annotations

import json


def _enable_default_llm_path(client) -> None:
    settings = client.app.state.settings
    settings.use_llm_scope_gate = False
    settings.use_semantic_planner = True
    settings.use_dynamic_synthesis = True
    settings.use_tool_agent = False


def test_clear_remediation_uses_generator_without_planner(client, sample_scan, fake_llm):
    """Explicit SQLi remediation is retrieval + one grounded generator call."""
    _enable_default_llm_path(client)
    client.post("/ingest", json={"scan": sample_scan})
    fake_llm.responses = [
        json.dumps(
            {
                "answer": "Use parameterized queries for the transaction search.",
                "findings_referenced": ["FINDING-001"],
                "reference_ids": ["CWE-89"],
                "abstained": False,
            }
        )
    ]

    response = client.post(
        "/query",
        json={"question": "How do I fix the SQL injection in transaction search?"},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["answer_source"] == "llm"
    assert body["findings_referenced"] == ["FINDING-001"]
    assert len(fake_llm.calls) == 1
    assert "query planner" not in fake_llm.calls[0]["system"].lower()


def test_ambiguous_question_uses_planner_then_generator(client, sample_scan, fake_llm):
    """Ambiguous soft language takes the bounded two-call planner/generator path."""
    _enable_default_llm_path(client)
    client.post("/ingest", json={"scan": sample_scan})
    fake_llm.responses = [
        json.dumps(
            {
                "intent": "explain",
                "answer_mode": "explain",
                "include_topics": ["authorization"],
                "include_phrases": ["other users data"],
                "in_scope": True,
                "execution": "hybrid",
                "confidence": 0.9,
                "rationale": "soft cross-user access question",
            }
        ),
        json.dumps(
            {
                "answer": "The account-details finding allows access to another user's account data.",
                "findings_referenced": ["FINDING-002"],
                "reference_ids": ["CWE-639"],
                "abstained": False,
            }
        ),
    ]

    response = client.post(
        "/query",
        json={"question": "Could one customer access another customer's account information?"},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["abstained"] is False
    assert "FINDING-002" in body["findings_referenced"]
    assert len(fake_llm.calls) == 2
    assert "query planner" in fake_llm.calls[0]["system"].lower()
    assert "application security engineer" in fake_llm.calls[1]["system"].lower()
