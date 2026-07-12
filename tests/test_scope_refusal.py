"""Out-of-scope and empty-context refusal (product boundary)."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.schemas import IngestRequest, QueryRequest, ScanIn
from app.clients.embeddings import FakeEmbeddings
from app.clients.llm import FakeLLM
from app.config import Settings
from app.db.models import Base
from app.ingestion.pipeline import IngestionPipeline
from app.rag.scope import has_scan_scope_signals, is_out_of_scope, scope_refusal_response
from app.rag.router import rule_based_route
from app.retrieval.vector_store import VectorStore
from app.services.query_service import QueryService

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


def test_scope_helpers_unit():
    assert is_out_of_scope("what's the weather today?")
    assert is_out_of_scope("tell me a joke")
    assert is_out_of_scope("hello")
    assert not is_out_of_scope(
        "What are all the critical severity findings?",
        rule_based_route("What are all the critical severity findings?"),
    )
    assert not is_out_of_scope(
        "Is there a remote code execution vulnerability?",
        rule_based_route("Is there a remote code execution vulnerability?"),
    )
    assert has_scan_scope_signals("How do I fix the SQL injection?")
    assert not has_scan_scope_signals("explain why the sky is blue")


def test_scope_refusal_copy():
    r = scope_refusal_response(reason="out_of_scope", has_scan_data=True)
    assert r.abstained
    assert "ingested" in r.answer.lower() or "scan" in r.answer.lower()
    empty = scope_refusal_response(has_scan_data=False)
    assert "ingest" in empty.answer.lower()


def _service(tmp_path: Path) -> QueryService:
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
    )
    vs = VectorStore(chroma_path=settings.chroma_path, embeddings=FakeEmbeddings(32))
    IngestionPipeline(session=session, vector_store=vs, settings=settings).ingest(
        IngestRequest(scan=ScanIn.model_validate(SAMPLE), reference_documents=[])
    )
    return QueryService(
        session=session,
        vector_store=vs,
        llm=FakeLLM(),
        settings=settings,
    )


def test_off_topic_abstains(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(QueryRequest(question="What's the weather in London today?"))
    assert r.abstained is True
    assert r.findings_referenced == []
    assert "scan" in r.answer.lower() or "ingested" in r.answer.lower()
    assert r.answer_source == "abstain"


def test_joke_abstains(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(QueryRequest(question="Tell me a joke about cats"))
    assert r.abstained is True
    assert r.findings_referenced == []


def test_scan_question_still_works(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(QueryRequest(question="What are all the critical severity findings?"))
    assert r.abstained is False
    assert "FINDING-001" in r.findings_referenced or "FINDING-004" in r.findings_referenced
