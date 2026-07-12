"""Soft-path fail-soft: LLM/embed failures degrade to grounded templates/BM25."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.schemas import IngestRequest, QueryRequest, ScanIn
from app.clients.embeddings import FakeEmbeddings
from app.clients.llm import FakeLLM
from app.config import Settings
from app.db.models import Base
from app.ingestion.pipeline import IngestionPipeline
from app.rag.generator import AnswerGenerator
from app.retrieval.findings_store import FindingsStore
from app.retrieval.vector_store import VectorStore
from app.services.query_service import QueryService

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


class BoomLLM(FakeLLM):
    """Always fails like a timed-out provider."""

    def complete(self, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(kwargs)
        raise TimeoutError("LLM request timed out")


class BoomEmbeddings(FakeEmbeddings):
    def embed(self, texts: list[str]) -> list[list[float]]:
        raise RuntimeError("embedding provider down")


def _svc(tmp_path: Path, *, llm=None, embeddings=None) -> QueryService:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    settings = Settings(
        modelscope_api_key="x",
        groq_api_key="x",
        data_dir=tmp_path,
        sqlite_path=tmp_path / "t.db",
        chroma_path=tmp_path / "chroma",
        knowledge_dir=ROOT / "data" / "knowledge",
        rerank_mode="light",
        cross_encoder_enabled=False,
        use_tool_agent=False,
        use_semantic_planner=False,
        use_dynamic_synthesis=True,
        use_llm_scope_gate=False,
        llm_timeout_s=2.0,
        embed_timeout_s=2.0,
    )
    emb = embeddings or FakeEmbeddings(32)
    vs = VectorStore(chroma_path=settings.chroma_path, embeddings=emb)
    # Ingest with healthy embeds so store has rows; boom only at query time if needed
    healthy_vs = VectorStore(
        chroma_path=tmp_path / "chroma_ingest", embeddings=FakeEmbeddings(32)
    )
    IngestionPipeline(
        session=session, vector_store=healthy_vs, settings=settings
    ).ingest(IngestRequest(scan=ScanIn.model_validate(SAMPLE), reference_documents=[]))
    # Point query service at maybe-broken embed client for retrieval
    vs_query = VectorStore(chroma_path=settings.chroma_path, embeddings=emb)
    return QueryService(
        session=session,
        vector_store=vs_query,
        llm=llm or FakeLLM(),
        settings=settings,
    )


def test_generator_template_on_llm_timeout():
    store = FindingsStore.__new__(FindingsStore)  # unused
    _ = store
    # Build two real findings via temp DB
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    fs = FindingsStore(session)
    fs.replace_scan(
        scan_id=SAMPLE["scan_id"],
        target=SAMPLE["target"],
        scan_timestamp=SAMPLE["scan_timestamp"],
        findings=SAMPLE["findings"],
    )
    findings = fs.search(scan_id=SAMPLE["scan_id"], severity="CRITICAL")[:2]
    gen = AnswerGenerator(BoomLLM())
    out = gen.generate(
        question="How do I fix the SQL injection in transaction search?",
        intent="remediation",
        findings=findings,
        knowledge_hits=[],
        use_dynamic_synthesis=True,
    )
    assert out.abstained is False
    assert out.raw.get("source") == "template"
    assert out.raw.get("fallback_reason") == "llm_fail_soft"
    assert out.findings_referenced
    assert findings[0].finding_id in out.findings_referenced or any(
        f.finding_id in (out.answer or "") for f in findings
    )


def test_generator_compare_template_on_llm_timeout():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    fs = FindingsStore(session)
    fs.replace_scan(
        scan_id=SAMPLE["scan_id"],
        target=SAMPLE["target"],
        scan_timestamp=SAMPLE["scan_timestamp"],
        findings=SAMPLE["findings"],
    )
    findings = [
        f
        for f in fs.list_all(SAMPLE["scan_id"])
        if f.finding_id in {"FINDING-002", "FINDING-008"}
    ]
    gen = AnswerGenerator(BoomLLM())
    out = gen.generate(
        question="Compare the two IDOR findings",
        intent="compare",
        findings=findings,
        knowledge_hits=[],
        use_dynamic_synthesis=True,
    )
    assert out.raw.get("source") == "template"
    assert set(out.findings_referenced) >= {"FINDING-002", "FINDING-008"} or len(
        out.findings_referenced
    ) >= 2


def test_vector_query_embed_failure_returns_empty(tmp_path: Path):
    vs = VectorStore(chroma_path=tmp_path / "c", embeddings=BoomEmbeddings(8))
    # Seed requires working embeds — use healthy then swap
    healthy = VectorStore(chroma_path=tmp_path / "c", embeddings=FakeEmbeddings(8))
    healthy.upsert_documents(
        ids=["f1"],
        texts=["SQL injection"],
        metadatas=[{"scan_id": "s1", "doc_type": "finding"}],
    )
    vs._collection = healthy._collection  # type: ignore[attr-defined]
    vs._embeddings = BoomEmbeddings(8)  # type: ignore[method-assign]
    hits = vs.query(text="SQL", top_k=3, where={"scan_id": "s1"})
    assert hits == []


def test_service_explain_survives_llm_timeout(tmp_path: Path):
    """End-to-end: timed-out LLM still returns grounded non-empty answer."""
    svc = _svc(tmp_path, llm=BoomLLM(), embeddings=FakeEmbeddings(32))
    # Re-ingest into the service's chroma so hybrid works
    IngestionPipeline(
        session=svc.session,
        vector_store=svc.vector_store,
        settings=svc.settings,
    ).ingest(IngestRequest(scan=ScanIn.model_validate(SAMPLE), reference_documents=[]))
    svc.retriever.rebuild_bm25()

    r = svc.query(
        QueryRequest(
            question="How do I fix the SQL injection in transaction search?",
            scan_id=SAMPLE["scan_id"],
        )
    )
    assert r.abstained is False
    assert r.answer_source in {"template", "structured", "llm"}
    assert "FINDING-001" in r.findings_referenced or "sql" in r.answer.lower()
    assert len(r.answer) > 20


def test_service_survives_dead_embeddings(tmp_path: Path):
    """Dead dense path: BM25/SQL still answers inventory; soft may still template."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    settings = Settings(
        modelscope_api_key="x",
        groq_api_key="x",
        data_dir=tmp_path,
        sqlite_path=tmp_path / "t.db",
        chroma_path=tmp_path / "chroma",
        knowledge_dir=ROOT / "data" / "knowledge",
        rerank_mode="light",
        cross_encoder_enabled=False,
        use_tool_agent=False,
        use_semantic_planner=False,
        use_dynamic_synthesis=False,
        use_llm_scope_gate=False,
    )
    # Ingest with healthy embeds into a throwaway store; query uses boom embeds
    healthy = VectorStore(chroma_path=tmp_path / "chroma_ok", embeddings=FakeEmbeddings(32))
    IngestionPipeline(session=session, vector_store=healthy, settings=settings).ingest(
        IngestRequest(scan=ScanIn.model_validate(SAMPLE), reference_documents=[])
    )
    boom_vs = VectorStore(chroma_path=tmp_path / "chroma_ok", embeddings=BoomEmbeddings(32))
    # Share collection data but boom embeds on query
    boom_vs._collection = healthy._collection  # type: ignore[attr-defined]
    svc = QueryService(
        session=session,
        vector_store=boom_vs,
        llm=FakeLLM(),
        settings=settings,
    )
    svc.retriever.rebuild_bm25()

    r = svc.query(
        QueryRequest(
            question="What are all the critical severity findings?",
            scan_id=SAMPLE["scan_id"],
        )
    )
    assert r.abstained is False
    assert {"FINDING-001", "FINDING-004"} <= set(r.findings_referenced)
