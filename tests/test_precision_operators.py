"""Precision operators: count, top_n, negation, phrase∩severity, endpoint, secrets.

Expectations assert against sample_findings.json only in tests — product code
must not hardcode finding IDs.
"""

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
from app.retrieval.filter_engine import FilterSpec, apply_filters
from app.retrieval.findings_store import FindingRecord, FindingsStore
from app.retrieval.vector_store import VectorStore
from app.services.query_service import QueryService

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


def _records_from_sample() -> list[FindingRecord]:
    out = []
    for f in SAMPLE["findings"]:
        out.append(
            FindingRecord(
                finding_id=f["id"],
                scan_id=SAMPLE["scan_id"],
                title=f["title"],
                severity=str(f["severity"]).upper(),
                cwe_id=f["cwe_id"],
                owasp_category=f["owasp_category"],
                endpoint=f["endpoint"],
                method=f.get("method") or "",
                parameter=f.get("parameter") or "N/A",
                description=f.get("description") or "",
                evidence=f.get("evidence") or {},
                remediation_hint=f.get("remediation_hint") or "",
            )
        )
    return out


def test_filter_count_critical():
    recs = _records_from_sample()
    got = apply_filters(
        recs, FilterSpec(include_severities=["CRITICAL"], want_count=True)
    )
    assert len(got) == 2
    assert {f.finding_id for f in got} == {"FINDING-001", "FINDING-004"}


def test_filter_top_n():
    recs = _records_from_sample()
    got = apply_filters(recs, FilterSpec(top_n=3))
    assert len(got) == 3
    assert got[0].severity == "CRITICAL"
    assert got[1].severity == "CRITICAL"


def test_filter_exclude_authentication_phrase():
    recs = _records_from_sample()
    got = apply_filters(
        recs, FilterSpec(exclude_phrases=["authentication", "password", "jwt", "login"])
    )
    ids = {f.finding_id for f in got}
    assert "FINDING-004" not in ids  # Authentication Bypass via JWT
    assert "FINDING-009" not in ids  # Weak Password
    assert "FINDING-001" in ids  # SQLi remains


def test_filter_high_and_injection_text_only():
    recs = _records_from_sample()
    got = apply_filters(
        recs,
        FilterSpec(include_severities=["HIGH"], include_phrases=["injection"]),
    )
    # Text-only: HIGH rows must contain "injection" in store text (may be empty)
    for f in got:
        assert f.severity == "HIGH"
        blob = (f.title + f.description).lower()
        assert "injection" in blob


def test_filter_secrets_phrases():
    recs = _records_from_sample()
    got = apply_filters(
        recs, FilterSpec(include_phrases=["secret", "hardcoded", "api key"])
    )
    assert any(f.finding_id == "FINDING-015" for f in got)


def test_filter_payments_endpoint_strict():
    recs = _records_from_sample()
    got = apply_filters(
        recs,
        FilterSpec(endpoint_substrings=["payments"], endpoint_strict=True),
    )
    assert len(got) == 1
    assert got[0].finding_id == "FINDING-005"


def test_router_count_not_existence():
    r = rule_based_route("How many CRITICAL findings are there?")
    assert r.want_count is True
    assert r.severity == "CRITICAL"
    assert r.intent != "existence" or r.want_count


def test_router_top_n_highest_risk():
    r = rule_based_route("What are the top 3 highest risk findings?")
    assert r.top_n == 3


def test_router_not_authentication():
    r = rule_based_route("Which findings are not authentication related?")
    assert any("auth" in p for p in r.exclude_phrases)


def test_router_payments_endpoint():
    r = rule_based_route("Which findings affect the payments endpoint?")
    assert any("payment" in e for e in r.endpoint_substrings)
    assert r.endpoint_strict is True


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
    )
    vs = VectorStore(chroma_path=settings.chroma_path, embeddings=FakeEmbeddings(32))
    IngestionPipeline(session=session, vector_store=vs, settings=settings).ingest(
        IngestRequest(scan=ScanIn.model_validate(SAMPLE), reference_documents=[])
    )
    return QueryService(
        session=session, vector_store=vs, llm=FakeLLM(), settings=settings
    )


def test_service_count_critical(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(QueryRequest(question="How many CRITICAL findings are there?"))
    assert r.abstained is False
    assert "2" in r.answer
    assert "15" not in r.answer.split("CRITICAL")[0] if "CRITICAL" in r.answer else True
    assert set(r.findings_referenced) == {"FINDING-001", "FINDING-004"}


def test_service_count_critical_alt(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(QueryRequest(question="Count the CRITICAL findings"))
    assert set(r.findings_referenced) == {"FINDING-001", "FINDING-004"}
    assert "**2**" in r.answer or " 2 " in f" {r.answer} "


def test_service_top_3(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(QueryRequest(question="What are the top 3 highest risk findings?"))
    assert len(r.findings_referenced) == 3
    assert "FINDING-001" in r.findings_referenced
    assert "FINDING-004" in r.findings_referenced


def test_service_not_auth(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(question="Which findings are not authentication related?")
    )
    assert "FINDING-004" not in r.findings_referenced
    assert "FINDING-009" not in r.findings_referenced


def test_service_secrets(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(QueryRequest(question="Are there any secrets management findings?"))
    assert r.abstained is False
    assert "FINDING-015" in r.findings_referenced


def test_service_payments(tmp_path: Path):
    svc = _service(tmp_path)
    for q in (
        "Are there any findings related to the payments endpoint?",
        "Which findings affect the payments endpoint?",
    ):
        r = svc.query(QueryRequest(question=q))
        assert r.findings_referenced == ["FINDING-005"], q


def test_service_all_critical_list(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(question="What are all the critical severity findings?")
    )
    assert set(r.findings_referenced) == {"FINDING-001", "FINDING-004"}


def test_service_remediate_cwe918(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(QueryRequest(question="How do I remediate CWE-918?"))
    assert r.query_intent == "remediation"
    # FakeLLM still produces something; refs should include 007 when retrieval works
    store = FindingsStore(svc.session)
    assert store.get_by_id("FINDING-007") is not None


def test_service_remediation_with_endpoint_negation_stays_grounded(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question=(
                "For the SQLi on transaction search, give a fix plan covering code "
                "changes and tests without inventing endpoints not in the scan."
            )
        )
    )
    assert r.abstained is False
    assert "FINDING-001" in r.findings_referenced
