"""Specific subtype existence: parent family match is not enough."""

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
from app.retrieval.existence_subtype import (
    detect_existence_subtype,
    filter_for_existence_subtype,
    finding_supports_subtype,
)
from app.retrieval.findings_store import FindingsStore
from app.retrieval.taxonomy import topic_names_for_text
from app.retrieval.vector_store import VectorStore
from app.services.query_service import QueryService

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


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
        use_dynamic_synthesis=False,
        use_llm_scope_gate=False,
    )
    vs = VectorStore(chroma_path=settings.chroma_path, embeddings=FakeEmbeddings(32))
    IngestionPipeline(session=session, vector_store=vs, settings=settings).ingest(
        IngestRequest(scan=ScanIn.model_validate(SAMPLE), reference_documents=[])
    )
    return QueryService(
        session=session, vector_store=vs, llm=FakeLLM(), settings=settings
    )


def test_detect_command_injection_subtype():
    sub = detect_existence_subtype("Are there any command injection findings?")
    assert sub is not None
    assert sub.name == "command_injection"


def test_detect_sql_injection_subtype():
    sub = detect_existence_subtype("Is there SQL injection in this scan?")
    assert sub is not None
    assert sub.name == "sql_injection"


def test_broad_injection_is_not_a_specific_subtype():
    # Family listing — no subtype gate
    assert detect_existence_subtype("Which injection findings were found?") is None
    assert detect_existence_subtype("What injection issues exist?") is None


def test_topic_prefers_command_injection_leaf():
    names = topic_names_for_text("are there any command injection findings?")
    assert "command_injection" in names
    assert "injection" not in names  # parent suppressed by leaf


def test_sqli_finding_does_not_support_command_injection():
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
    all_f = store.list_all(SAMPLE["scan_id"])
    sub = detect_existence_subtype("command injection?")
    assert sub is not None
    sqli = next(f for f in all_f if f.finding_id == "FINDING-001")
    xss = next(f for f in all_f if f.finding_id == "FINDING-003")
    assert finding_supports_subtype(sqli, sub) is False
    assert finding_supports_subtype(xss, sub) is False
    assert filter_for_existence_subtype("Are there command injection findings?", all_f) == []


def test_command_injection_absent_abstains(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="Are there any command injection findings?",
            scan_id=SAMPLE["scan_id"],
        )
    )
    assert r.abstained is True
    assert r.findings_referenced == []
    ans = (r.answer or "").lower()
    # Must not claim command injection was found via SQLi/XSS
    assert "yes" not in ans or "no matching" in ans or "does not contain" in ans
    assert "finding-001" not in ans
    assert "finding-003" not in ans


def test_sql_injection_present(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="Is there a SQL injection vulnerability?",
            scan_id=SAMPLE["scan_id"],
        )
    )
    assert r.abstained is False
    assert "FINDING-001" in r.findings_referenced


def test_generic_injection_list_may_include_family(tmp_path: Path):
    """Broad family listing (not a specific subtype existence) may return SQLi/XSS."""
    route = rule_based_route("Which findings are related to injection?")
    # Prefer list-style; existence of bare "injection" without subtype is family
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="Which injection findings were found?",
            scan_id=SAMPLE["scan_id"],
        )
    )
    # Not forced to abstain: family union is OK for broad listing
    if not r.abstained:
        refs = set(r.findings_referenced)
        assert refs & {"FINDING-001", "FINDING-003", "FINDING-007"}
    _ = route
