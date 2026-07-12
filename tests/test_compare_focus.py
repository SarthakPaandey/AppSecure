"""Class-focused compare/explain pools and tight citations."""

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
from app.rag.generator import AnswerGenerator
from app.retrieval.findings_store import FindingsStore
from app.retrieval.vector_store import VectorStore
from app.services.compare_focus import focus_findings_for_question
from app.services.query_service import QueryService
from app.retrieval.taxonomy import topic_names_for_text

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


def _all_findings():
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
    return store.list_all(SAMPLE["scan_id"])


def test_focus_idor_compare_excludes_sqli():
    findings = _all_findings()
    focused = focus_findings_for_question(
        "Compare the two IDOR findings — are they the same root cause?",
        findings,
        max_n=4,
    )
    ids = {f.finding_id for f in focused}
    assert "FINDING-002" in ids
    assert "FINDING-008" in ids
    assert "FINDING-001" not in ids  # SQLi must not pollute IDOR compare


def test_template_compare_idor_refs_tight():
    findings = _all_findings()
    gen = AnswerGenerator(FakeLLM())
    out = gen._template_compare(
        findings,
        question="Compare the two IDOR findings — same root cause?",
    )
    refs = set(out.findings_referenced)
    assert "FINDING-002" in refs and "FINDING-008" in refs
    assert "FINDING-001" not in refs
    assert len(refs) <= 4


def test_horizontal_privilege_maps_to_authorization_topic():
    names = topic_names_for_text(
        "do any endpoints permit horizontal privilege escalation?"
    )
    assert "authorization" in names
    assert "mass_assignment" not in names  # horizontal ≠ vertical mass-assignment


def test_service_compare_idor_citations(tmp_path: Path):
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
        use_dynamic_synthesis=False,  # force template path
        use_llm_scope_gate=False,
    )
    vs = VectorStore(chroma_path=settings.chroma_path, embeddings=FakeEmbeddings(32))
    IngestionPipeline(session=session, vector_store=vs, settings=settings).ingest(
        IngestRequest(scan=ScanIn.model_validate(SAMPLE), reference_documents=[])
    )
    svc = QueryService(
        session=session, vector_store=vs, llm=FakeLLM(), settings=settings
    )
    r = svc.query(
        QueryRequest(
            question="Compare the two IDOR findings — are they the same root cause?",
            scan_id=SAMPLE["scan_id"],
        )
    )
    assert r.abstained is False
    refs = set(r.findings_referenced)
    assert {"FINDING-002", "FINDING-008"} <= refs
    assert "FINDING-001" not in refs
