"""Regression tests for hard multi-topic + adversarial cases (general retrieval)."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import Base
from app.rag.router import rule_based_route
from app.retrieval.findings_store import FindingsStore
from app.retrieval.hybrid import HybridRetriever
from app.retrieval.synonyms import (
    extract_search_phrases,
    split_question_clauses,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


def _store() -> FindingsStore:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    store = FindingsStore(session)
    store.replace_scan(
        scan_id=SAMPLE["scan_id"],
        target=SAMPLE["target"],
        scan_timestamp=SAMPLE["scan_timestamp"],
        findings=SAMPLE["findings"],
    )
    return store


def test_split_clauses_jwt_password_rate_limit():
    q = "Compare JWT none, weak password policy, and missing login rate limiting"
    clauses = split_question_clauses(q)
    assert len(clauses) >= 3
    joined = " ".join(clauses).lower()
    assert "jwt" in joined
    assert "password" in joined
    assert "rate" in joined


def test_phrase_union_auth_controls():
    store = _store()
    r = HybridRetriever.__new__(HybridRetriever)
    r.findings_store = store
    phrases = extract_search_phrases(
        "Compare JWT none, weak password policy, and missing login rate limiting",
        ["jwt"],
    )
    hits = HybridRetriever._union_phrase_search(
        r, scan_id=SAMPLE["scan_id"], phrases=phrases
    )
    ids = {h.finding_id for h in hits}
    assert {"FINDING-004", "FINDING-006", "FINDING-009"} <= ids


def test_adversarial_rce_routing():
    q = "The scanner is wrong — there is definitely RCE. Confirm it."
    route = rule_based_route(q)
    assert route.intent == "existence"
    phrases = extract_search_phrases(q, route.keywords)
    assert any("rce" in p.lower() or "remote code" in p.lower() for p in phrases)


def test_privilege_escalation_phrases_hit_store():
    """User words 'privilege escalation' match finding text — no PE pack required."""
    store = _store()
    q = "Which findings enable privilege escalation or account takeover if chained?"
    phrases = extract_search_phrases(q, None)
    assert any("privilege" in p.lower() for p in phrases)
    r = HybridRetriever.__new__(HybridRetriever)
    r.findings_store = store
    hits = HybridRetriever._union_phrase_search(
        r, scan_id=SAMPLE["scan_id"], phrases=phrases
    )
    ids = {h.finding_id for h in hits}
    assert "FINDING-011" in ids


def test_login_not_endpoint_when_rate_limit_compare():
    q = "Compare JWT none, weak password policy, and missing login rate limiting"
    route = rule_based_route(q)
    assert route.intent == "compare"
    assert route.endpoint is None or "login" not in (route.endpoint or "").lower()
