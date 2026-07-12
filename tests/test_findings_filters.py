"""Structured findings store filter tests (no LLM)."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import Base
from app.retrieval.findings_store import FindingsStore

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


def _store_with_sample() -> FindingsStore:
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


def test_critical_severity_only():
    store = _store_with_sample()
    rows = store.search(severity="CRITICAL")
    ids = {r.finding_id for r in rows}
    assert ids == {"FINDING-001", "FINDING-004"}


def test_owasp_a01():
    store = _store_with_sample()
    rows = store.search(owasp="A01")
    ids = {r.finding_id for r in rows}
    assert ids == {"FINDING-002", "FINDING-008"}


def test_endpoint_accounts():
    store = _store_with_sample()
    rows = store.search(endpoint="accounts")
    assert any(r.finding_id == "FINDING-002" for r in rows)


def test_no_rce_keyword_match():
    store = _store_with_sample()
    rows = store.search(keywords=["remote code execution"])
    assert rows == []


def test_ingest_idempotent_count():
    store = _store_with_sample()
    assert store.count() == 15
    store.replace_scan(
        scan_id=SAMPLE["scan_id"],
        target=SAMPLE["target"],
        scan_timestamp=SAMPLE["scan_timestamp"],
        findings=SAMPLE["findings"],
    )
    assert store.count() == 15


def test_severity_sort_order():
    store = _store_with_sample()
    rows = store.list_all()
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    ranks = [order.index(r.severity) for r in rows]
    assert ranks == sorted(ranks)
