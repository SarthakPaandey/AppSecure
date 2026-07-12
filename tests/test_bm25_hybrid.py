"""BM25 + RRF fusion tests (production hybrid IR path)."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import Base
from app.retrieval.bm25_index import (
    BM25Index,
    FindingsBM25Index,
    reciprocal_rank_fusion,
    tokenize,
)
from app.retrieval.findings_store import FindingsStore
from app.retrieval.hybrid import HybridRetriever
from app.clients.embeddings import FakeEmbeddings
from app.retrieval.vector_store import VectorStore
from app.config import Settings
from app.rag.router import rule_based_route

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


def test_tokenize_keeps_technical_tokens():
    toks = tokenize("SQL injection CWE-89 on /api/v1/transactions/search")
    assert "sql" in toks or "injection" in toks
    assert any(t.startswith("cwe") for t in toks)
    assert "the" not in toks


def test_bm25_ranks_sqli_above_unrelated():
    idx = BM25Index()
    idx.build(
        [
            ("a", "SQL Injection in Transaction Search account_id parameter", "s1"),
            ("b", "Missing Security Headers on static assets", "s1"),
            ("c", "Weak Password Policy registration", "s1"),
        ]
    )
    hits = idx.search("SQL injection transaction search", top_k=3)
    assert hits
    assert hits[0].doc_id == "a"


def test_rrf_prefers_consensus():
    fused = reciprocal_rank_fusion(
        [
            ["a", "b", "c"],
            ["b", "a", "d"],
            ["a", "e"],
        ]
    )
    ids = [x[0] for x in fused]
    assert ids[0] == "a"


def test_findings_bm25_and_hybrid_free_text(tmp_path: Path):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    store = FindingsStore(session)
    store.replace_scan(
        scan_id=SAMPLE["scan_id"],
        target=SAMPLE["target"],
        scan_timestamp=SAMPLE["scan_timestamp"],
        findings=SAMPLE["findings"],
    )
    bm25 = FindingsBM25Index()
    n = bm25.rebuild_from_records(store.list_all())
    assert n == 15

    hits = bm25.search("SQL injection transaction", top_k=5, scan_id=SAMPLE["scan_id"])
    assert hits
    assert hits[0].doc_id == "FINDING-001"

    settings = Settings(
        modelscope_api_key="x",
        groq_api_key="x",
        data_dir=tmp_path,
        sqlite_path=tmp_path / "t.db",
        chroma_path=tmp_path / "chroma",
        knowledge_dir=ROOT / "data" / "knowledge",
    )
    vs = VectorStore(chroma_path=settings.chroma_path, embeddings=FakeEmbeddings(32))
    # seed finding vectors
    from app.ingestion.finding_documents import findings_to_vector_payloads

    ids, texts, metas = findings_to_vector_payloads(store.list_all())
    vs.upsert_documents(ids=ids, texts=texts, metadatas=metas)

    hr = HybridRetriever(
        findings_store=store,
        vector_store=vs,
        settings=settings,
        bm25_index=bm25,
    )
    route = rule_based_route("How do I fix the SQL injection in transaction search?")
    res = hr.retrieve(
        question="How do I fix the SQL injection in transaction search?",
        route=route,
        scan_id=SAMPLE["scan_id"],
    )
    assert res.findings
    assert res.findings[0].finding_id == "FINDING-001"
    assert res.used_bm25 is True

    # Multi-topic still works via fusion + clauses
    route2 = rule_based_route(
        "Compare JWT none, weak password policy, and missing login rate limiting"
    )
    res2 = hr.retrieve(
        question=(
            "Compare JWT none, weak password policy, and missing login rate limiting"
        ),
        route=route2,
        scan_id=SAMPLE["scan_id"],
    )
    ids2 = {f.finding_id for f in res2.findings}
    assert {"FINDING-004", "FINDING-006", "FINDING-009"} <= ids2
