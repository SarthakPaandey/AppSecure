"""Precision + synthesis improvements (router, class filter, templates, cites)."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.schemas import QueryRequest
from app.clients.embeddings import FakeEmbeddings
from app.clients.llm import FakeLLM
from app.config import Settings
from app.db.models import Base
from app.ingestion.pipeline import IngestionPipeline
from app.api.schemas import IngestRequest, ScanIn
from app.rag.citations import filter_citations_to_answer, finding_ids_mentioned_in_answer
from app.rag.generator import AnswerGenerator
from app.rag.router import rule_based_route
from app.retrieval.findings_store import FindingsStore
from app.retrieval.vector_store import VectorStore
from app.services.query_service import QueryService

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


def test_router_cluster_not_summary():
    r = rule_based_route(
        "Group all findings by shared root cause rather than by severity. Which clusters would you create?"
    )
    assert r.intent == "cluster"


def test_router_idor_middleware_is_remediation():
    r = rule_based_route(
        "How would you fix both IDOR findings with one shared authorization middleware design?"
    )
    assert r.intent == "remediation"
    assert any("idor" in c for c in r.class_constraints)


def test_router_high_vs_is_classify_not_compare():
    r = rule_based_route(
        "Which HIGH findings are access-control problems vs injection problems vs authn problems?"
    )
    assert r.intent == "list"
    assert r.classify_problem_buckets is True
    assert r.severity == "HIGH"


def test_router_single_problem_family_is_not_a_bucket_comparison():
    r = rule_based_route("Which HIGH findings are injection problems?")
    assert r.intent == "list"
    assert r.classify_problem_buckets is False


def test_router_go_live_is_remediation_top3():
    r = rule_based_route(
        "From a fintech risk perspective, which three findings would you fix first "
        "before a production go-live and why?"
    )
    assert r.intent == "remediation"
    assert r.top_n == 3


def test_router_pii_is_data_impact_not_idor_only():
    r = rule_based_route(
        "Which findings could leak other customers' PII or financial data if exploited?"
    )
    assert r.data_impact is True
    assert r.class_constraints == []


def test_router_cwe_wants_parameter():
    r = rule_based_route(
        "Is CWE-918 present, and what is the exact endpoint and parameter?"
    )
    assert r.intent == "existence"
    assert r.cwe_id == "CWE-918"
    assert r.want_parameter is True


def test_filter_citations_to_answer():
    ans = "Use FINDING-002 and FINDING-008 for IDOR middleware."
    out = filter_citations_to_answer(
        answer=ans,
        candidate_ids=["FINDING-002", "FINDING-008", "FINDING-010", "FINDING-004"],
        intent="remediation",
    )
    assert set(out) == {"FINDING-002", "FINDING-008"}
    assert finding_ids_mentioned_in_answer(ans) == ["FINDING-002", "FINDING-008"]


def test_template_problem_buckets_uses_store_cwe():
    store_findings = []
    # minimal FindingRecord-like via store after ingest is heavy; use generator on fakes
    from app.retrieval.findings_store import FindingRecord

    findings = [
        FindingRecord(
            finding_id="FINDING-002",
            title="IDOR accounts",
            severity="HIGH",
            cwe_id="CWE-639",
            owasp_category="A01:2021",
            endpoint="/api/v1/accounts/{id}",
            method="GET",
            parameter="id",
            description="Broken object level authorization",
            remediation_hint="ownership checks",
            evidence={},
            scan_id="s",
        ),
        FindingRecord(
            finding_id="FINDING-007",
            title="SSRF import",
            severity="HIGH",
            cwe_id="CWE-918",
            owasp_category="A10:2021",
            endpoint="/api/v1/documents/import",
            method="POST",
            parameter="source_url",
            description="Server-Side Request Forgery fetches user URLs",
            remediation_hint="allowlist",
            evidence={},
            scan_id="s",
        ),
        FindingRecord(
            finding_id="FINDING-006",
            title="Missing Rate Limiting on Login",
            severity="HIGH",
            cwe_id="CWE-307",
            owasp_category="A07:2021",
            endpoint="/api/v1/auth/login",
            method="POST",
            parameter="password",
            description="unlimited authentication attempts",
            remediation_hint="rate limit",
            evidence={},
            scan_id="s",
        ),
        FindingRecord(
            finding_id="FINDING-011",
            title="Mass Assignment",
            severity="HIGH",
            cwe_id="CWE-915",
            owasp_category="A08:2021",
            endpoint="/api/v1/users/profile",
            method="PUT",
            parameter="role",
            description="privilege escalation via role assignment",
            remediation_hint="allowlist fields",
            evidence={},
            scan_id="s",
        ),
    ]
    gen = AnswerGenerator(FakeLLM())
    out = gen.generate(
        question="Which HIGH findings are access-control vs injection vs authn?",
        intent="list",
        findings=findings,
        knowledge_hits=[],
        classify_problem_buckets=True,
    )
    assert "FINDING-007" in out.answer
    assert "CWE-918" in out.answer
    assert "CWE-307" in out.answer  # not invented CWE-613
    assert "CWE-613" not in out.answer
    assert "injection" in out.answer.lower()
    assert "FINDING-006" in out.answer
    assert "FINDING-011" in out.answer


def test_template_priority_top_n_exactly_three():
    from app.retrieval.findings_store import FindingRecord

    findings = [
        FindingRecord(
            finding_id=f"FINDING-00{i}",
            title=t,
            severity=s,
            cwe_id=c,
            owasp_category="A01",
            endpoint="/x",
            method="GET",
            parameter="p",
            description=d,
            remediation_hint="fix",
            evidence={},
            scan_id="s",
        )
        for i, (t, s, c, d) in enumerate(
            [
                ("SQLi", "CRITICAL", "CWE-89", "sql injection"),
                ("JWT none", "CRITICAL", "CWE-287", "jwt none algorithm"),
                ("IDOR", "HIGH", "CWE-639", "idor"),
                ("SSRF", "HIGH", "CWE-918", "ssrf"),
            ],
            start=1,
        )
    ]
    gen = AnswerGenerator(FakeLLM())
    out = gen.generate(
        question="Which three findings would you fix first before production go-live?",
        intent="remediation",
        findings=findings,
        knowledge_hits=[],
        top_n=3,
    )
    assert out.findings_referenced == ["FINDING-001", "FINDING-002", "FINDING-003"]
    assert "Top 3" in out.answer


def test_template_auth_triad_same_broad_family():
    from app.retrieval.findings_store import FindingRecord

    findings = [
        FindingRecord(
            finding_id="FINDING-004",
            title="JWT None",
            severity="CRITICAL",
            cwe_id="CWE-287",
            owasp_category="A07",
            endpoint="/auth/verify",
            method="POST",
            parameter="token",
            description="jwt none algorithm",
            remediation_hint="allowlist",
            evidence={},
            scan_id="s",
        ),
        FindingRecord(
            finding_id="FINDING-009",
            title="Weak Password Policy",
            severity="LOW",
            cwe_id="CWE-521",
            owasp_category="A07",
            endpoint="/auth/register",
            method="POST",
            parameter="password",
            description="weak password",
            remediation_hint="complexity",
            evidence={},
            scan_id="s",
        ),
        FindingRecord(
            finding_id="FINDING-006",
            title="Missing Rate Limiting",
            severity="HIGH",
            cwe_id="CWE-307",
            owasp_category="A07",
            endpoint="/auth/login",
            method="POST",
            parameter="password",
            description="rate limit missing",
            remediation_hint="throttle",
            evidence={},
            scan_id="s",
        ),
    ]
    gen = AnswerGenerator(FakeLLM())
    out = gen.generate(
        question=(
            "Compare JWT none, weak password policy, and missing login rate limiting "
            "— are they the same control family?"
        ),
        intent="compare",
        findings=findings,
        knowledge_hits=[],
    )
    assert "broad control family" in out.answer.lower() or "same broad" in out.answer.lower()
    assert "different" in out.answer.lower()
    assert {"FINDING-004", "FINDING-009", "FINDING-006"} <= set(out.findings_referenced)


def test_cluster_template_groups_families():
    store_engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(bind=store_engine)
    session = sessionmaker(bind=store_engine)()
    store = FindingsStore(session)
    store.replace_scan(
        scan_id=SAMPLE["scan_id"],
        target=SAMPLE["target"],
        scan_timestamp=SAMPLE["scan_timestamp"],
        findings=SAMPLE["findings"],
    )
    findings = store.list_all()
    gen = AnswerGenerator(FakeLLM())
    out = gen.generate(
        question="Group by root cause",
        intent="cluster",
        findings=findings,
        knowledge_hits=[],
    )
    assert "control family" in out.answer.lower() or "root" in out.answer.lower()
    assert "FINDING-002" in out.answer or "IDOR" in out.answer
    assert len(out.findings_referenced) == 15


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
        session=session,
        vector_store=vs,
        llm=FakeLLM(),
        settings=settings,
    )


def test_idor_middleware_retrieval_precision(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question=(
                "How would you fix both IDOR findings with one shared "
                "authorization middleware design?"
            )
        )
    )
    ids = set(r.findings_referenced)
    assert {"FINDING-002", "FINDING-008"} <= ids
    # Should not drag in unrelated JWT/headers when class-constrained
    assert "FINDING-010" not in ids
    assert "FINDING-004" not in ids or len(ids) <= 3


def test_cwe918_includes_parameter(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="Is CWE-918 present, and what is the exact endpoint and parameter?"
        )
    )
    assert "FINDING-007" in r.findings_referenced
    assert "source_url" in r.answer.lower() or "parameter" in r.answer.lower()


def test_cluster_intent_service(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question=(
                "Group all findings by shared root cause rather than by severity. "
                "Which clusters would you create?"
            )
        )
    )
    assert r.query_intent == "cluster"
    assert r.abstained is False
    assert len(r.findings_referenced) >= 10
    assert "###" in r.answer or "family" in r.answer.lower()
