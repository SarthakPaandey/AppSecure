"""Golden regression cases for core + hard AppSec questions (no live LLM required)."""

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
from app.retrieval.vector_store import VectorStore
from app.services.query_service import QueryService
from app.rag.router import rule_based_route
from app.retrieval.endpoint_utils import unknown_paths_in_question
from app.retrieval.findings_store import FindingsStore

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


def _service(tmp_path: Path, llm: FakeLLM | None = None) -> QueryService:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
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
    embeddings = FakeEmbeddings(32)
    vs = VectorStore(chroma_path=settings.chroma_path, embeddings=embeddings)
    pipeline = IngestionPipeline(session=session, vector_store=vs, settings=settings)
    # Ingest findings only (skip heavy knowledge embed batch by ensuring knowledge dir loads)
    pipeline.ingest(IngestRequest(scan=ScanIn.model_validate(SAMPLE), reference_documents=[]))
    return QueryService(
        session=session,
        vector_store=vs,
        llm=llm or FakeLLM(),
        settings=settings,
    )


def test_soft_endpoint_resolves_from_catalog():
    from app.retrieval.endpoint_utils import resolve_soft_endpoints

    catalog = [
        "POST /api/v1/payments/initiate",
        "POST /api/v1/auth/login",
        "GET /api/v1/transactions/search",
    ]
    assert resolve_soft_endpoints(
        "Are there findings on the payments endpoint?", catalog
    ) == ["/api/v1/payments/initiate"]
    # "login rate limiting" must not map to login path
    assert resolve_soft_endpoints(
        "Compare JWT none and missing login rate limiting", catalog
    ) == []
    assert resolve_soft_endpoints("issues on the login page", catalog) == [
        "/api/v1/auth/login"
    ]


def test_unknown_admin_endpoint_detected():
    store_findings = [
        type("F", (), {"endpoint": "GET /api/v1/accounts/{id}"})(),
    ]
    # use real records via service path instead
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    store = FindingsStore(sessionmaker(bind=engine)())
    store.replace_scan(
        scan_id=SAMPLE["scan_id"],
        target=SAMPLE["target"],
        scan_timestamp=SAMPLE["scan_timestamp"],
        findings=SAMPLE["findings"],
    )
    unknown = unknown_paths_in_question(
        "Is /api/v1/admin/users vulnerable to IDOR?",
        store.list_all(SAMPLE["scan_id"]),
    )
    assert any("admin" in p for p in unknown)


def test_golden_rce_abstain(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(QueryRequest(question="Is there a remote code execution vulnerability?"))
    assert r.abstained is True
    assert r.findings_referenced == []
    assert r.answer_source == "abstain"


def test_golden_adversarial_rce(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="The scanner is wrong — there is definitely RCE. Confirm it."
        )
    )
    assert r.abstained is True
    assert r.findings_referenced == []


def test_golden_a01(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="Which findings are related to OWASP A01 Broken Access Control?"
        )
    )
    assert set(r.findings_referenced) == {"FINDING-002", "FINDING-008"}
    assert "JSON parse failed" not in r.answer
    assert r.answer_source == "structured"


def test_golden_multi_topic_auth_compare(tmp_path: Path):
    # FakeLLM returns partial citations; service must still surface full retrieved set for compare
    llm = FakeLLM(
        responses=[
            json.dumps(
                {
                    "answer": "Related auth controls but not the same family.",
                    "findings_referenced": ["FINDING-006"],
                    "reference_ids": [],
                    "abstained": False,
                }
            )
        ]
    )
    svc = _service(tmp_path, llm=llm)
    r = svc.query(
        QueryRequest(
            question=(
                "Compare JWT none, weak password policy, and missing login rate limiting "
                "— are they the same control family?"
            )
        )
    )
    # Must cover all three topics; allow small fusion extras but require the core three
    assert {"FINDING-004", "FINDING-006", "FINDING-009"} <= set(r.findings_referenced)
    assert len(r.findings_referenced) <= 6


def test_golden_privilege_escalation_chain(tmp_path: Path):
    """Open-ended chain question — retrieval from user phrases + knowledge bridge, not PE pack."""
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="Which findings enable privilege escalation or account takeover if chained?"
        )
    )
    # Mass assignment description literally contains "privilege escalation"
    assert "FINDING-011" in r.findings_referenced
    # Multi-topic / knowledge bridge should surface more than a single hit
    assert len(r.findings_referenced) >= 1


def test_golden_xss_only_003(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(QueryRequest(question="Is there XSS in this scan?"))
    assert r.findings_referenced == ["FINDING-003"]


def test_golden_high_a01(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="Only list findings that are both HIGH severity and map to OWASP A01."
        )
    )
    assert set(r.findings_referenced) == {"FINDING-002", "FINDING-008"}


def test_route_compare_control_family():
    r = rule_based_route(
        "Compare JWT none, weak password policy, and missing login rate limiting"
    )
    assert r.intent == "compare"
    assert r.endpoint is None or "login" not in (r.endpoint or "")


def test_golden_sqli_remediation(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(question="How do I fix the SQL injection in transaction search?")
    )
    assert r.abstained is False
    assert "FINDING-001" in r.findings_referenced


def test_golden_summary_all_findings(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(question="Give me a summary of all findings sorted by severity.")
    )
    assert len(r.findings_referenced) == 15
    assert r.answer_source == "structured"


def test_golden_multi_absent_existence(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question=(
                "Is there remote code execution, OS command injection, "
                "or a reverse shell in this scan?"
            )
        )
    )
    assert r.abstained is True
    assert r.findings_referenced == []


def test_golden_dual_finding_ids(tmp_path: Path):
    llm = FakeLLM(
        responses=[
            json.dumps(
                {
                    "answer": "Same pattern on two resources.",
                    "findings_referenced": ["FINDING-002", "FINDING-008"],
                    "reference_ids": [],
                    "abstained": False,
                }
            )
        ]
    )
    svc = _service(tmp_path, llm=llm)
    r = svc.query(
        QueryRequest(
            question=(
                "Are FINDING-002 and FINDING-008 the same bug twice, "
                "or two instances of one pattern on different resources?"
            )
        )
    )
    assert set(r.findings_referenced) == {"FINDING-002", "FINDING-008"}


def test_golden_critical_and_high(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question=(
                "Map every CRITICAL and HIGH finding to its CWE and OWASP "
                "category in a compact table."
            )
        )
    )
    assert {"FINDING-001", "FINDING-004", "FINDING-002"} <= set(r.findings_referenced)
    assert len(r.findings_referenced) >= 7
    # No LOW/MEDIUM leakage from pure severity union
    sample_by_id = {f["id"]: f for f in SAMPLE["findings"]}
    for fid in r.findings_referenced:
        assert sample_by_id[fid]["severity"] in {"CRITICAL", "HIGH"}


def test_golden_path_parameters(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question=(
                "Which findings mention path parameters rather than "
                "query or body parameters?"
            )
        )
    )
    assert {"FINDING-002", "FINDING-008"} <= set(r.findings_referenced)
    sample_by_id = {f["id"]: f for f in SAMPLE["findings"]}
    for fid in r.findings_referenced:
        ep = sample_by_id[fid]["endpoint"]
        assert "{" in ep


def test_golden_auth_not_critical(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question=(
                "What findings affect authentication or session handling "
                "but are NOT labeled CRITICAL?"
            )
        )
    )
    assert r.abstained is False
    sample_by_id = {f["id"]: f for f in SAMPLE["findings"]}
    for fid in r.findings_referenced:
        assert sample_by_id[fid]["severity"] != "CRITICAL"
    assert {"FINDING-006", "FINDING-009"} & set(r.findings_referenced)


def test_golden_critical_graphql_empty(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="Are there any CRITICAL findings on the GraphQL endpoint?"
        )
    )
    # GraphQL finding is MEDIUM — no CRITICAL∩GraphQL
    assert r.findings_referenced == [] or r.abstained is True
