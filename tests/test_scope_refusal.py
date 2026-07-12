"""Scope gate: structural rules + LLM (FakeLLM / Gemma) relatedness."""

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
from app.rag.router import rule_based_route
from app.rag.scope import (
    classify_scope_with_llm,
    decide_scope,
    has_structural_scan_slots,
    scope_refusal_response,
)
from app.retrieval.vector_store import VectorStore
from app.services.query_service import QueryService

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


def test_structural_slots_skip_llm():
    route = rule_based_route("What are all the critical severity findings?")
    assert has_structural_scan_slots(route)
    d = decide_scope(
        "What are all the critical severity findings?",
        route,
        llm=FakeLLM(),  # would work, but rules_in should win first
        use_llm=True,
    )
    assert d.related is True
    assert d.source == "rules_in"


def test_llm_scope_weather_not_related():
    llm = FakeLLM()
    d = classify_scope_with_llm(llm, "What's the weather in London today?")
    assert d.related is False
    assert d.source == "llm"
    assert llm.calls  # LLM was invoked


def test_llm_scope_soft_appsec_related():
    llm = FakeLLM()
    d = classify_scope_with_llm(
        llm,
        "Could someone access other users' account data through the API?",
    )
    assert d.related is True


def test_obvious_off_topic_no_llm_needed():
    d = decide_scope("tell me a joke about cats", None, llm=FakeLLM(), use_llm=True)
    assert d.related is False
    assert d.source == "rules_out"


def test_scope_refusal_copy():
    r = scope_refusal_response(reason="out_of_scope", has_scan_data=True)
    assert r.abstained
    assert "scan" in r.answer.lower() or "ingested" in r.answer.lower()


def _service(tmp_path: Path, *, use_llm_scope: bool = True) -> QueryService:
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
        use_llm_scope_gate=use_llm_scope,
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


def test_off_topic_abstains_via_service(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(QueryRequest(question="What's the weather in London today?"))
    assert r.abstained is True
    assert r.findings_referenced == []
    assert r.answer_source == "abstain"


def test_joke_abstains(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(QueryRequest(question="Tell me a joke about cats"))
    assert r.abstained is True


def test_scan_question_still_works(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(QueryRequest(question="What are all the critical severity findings?"))
    assert r.abstained is False
    assert "FINDING-001" in r.findings_referenced or "FINDING-004" in r.findings_referenced


def test_soft_security_question_not_refused(tmp_path: Path):
    """Soft AppSec phrasing should pass LLM scope (FakeLLM) and not early-refuse."""
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="Could an attacker access other users' account data through broken access control?"
        )
    )
    # May answer or soft-retrieve; must not be the fixed out-of-scope chit-chat refuse
    if r.abstained:
        assert "weather" not in r.answer.lower()
        assert "joke" not in r.answer.lower()
        # no-match abstain is OK; pure scope refuse mentions "outside that scope"
        # soft security should not hit pure out_of_scope if LLM says related
    assert "only answer questions about" not in r.answer.lower() or r.abstained is False
