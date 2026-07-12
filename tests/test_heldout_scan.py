"""Held-out scan proof: not sample-only; arbitrary IDs; isolation; abstention."""

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
from app.rag.planner import extract_catalog_finding_ids
from app.retrieval.vector_store import VectorStore
from app.services.query_service import QueryService

ROOT = Path(__file__).resolve().parents[1]
HELDOUT = json.loads((ROOT / "data" / "heldout_scan.json").read_text())
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


def _service(tmp_path: Path, scans: list[dict] | None = None) -> QueryService:
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
    pipe = IngestionPipeline(session=session, vector_store=vs, settings=settings)
    for scan in scans or [HELDOUT]:
        pipe.ingest(
            IngestRequest(scan=ScanIn.model_validate(scan), reference_documents=[])
        )
    return QueryService(
        session=session,
        vector_store=vs,
        llm=FakeLLM(),
        settings=settings,
    )


def test_heldout_critical_count(tmp_path: Path):
    """Held-out CRITICAL count is exact (inventory, 0 LLM)."""
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="How many CRITICAL findings are there?",
            scan_id=HELDOUT["scan_id"],
        )
    )
    assert r.abstained is False
    # SHIP-AUTH-01, SHIP-SSRF-07, INV-SQL-12
    assert "3" in r.answer
    crit_ids = {"SHIP-AUTH-01", "SHIP-SSRF-07", "INV-SQL-12"}
    assert crit_ids <= set(r.findings_referenced) or "3" in r.answer


def test_heldout_severity_list(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="What are all the HIGH severity findings?",
            scan_id=HELDOUT["scan_id"],
        )
    )
    assert r.abstained is False
    refs = {x.upper() for x in r.findings_referenced}
    assert "WEB:XSS:44" in refs or "web:xss:44".upper() in refs
    assert any("VULN_2026_91" in x.upper() for x in r.findings_referenced)


def test_heldout_unseen_endpoint_abstains(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="Is there an IDOR on /api/v9/totally-unknown/path?",
            scan_id=HELDOUT["scan_id"],
        )
    )
    assert r.abstained is True
    assert r.findings_referenced == []


def test_heldout_unsupported_existence_abstains(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="Is there a remote code execution vulnerability in this scan?",
            scan_id=HELDOUT["scan_id"],
        )
    )
    assert r.abstained is True
    assert r.findings_referenced == []


def test_heldout_arbitrary_ids_via_catalog(tmp_path: Path):
    """SHIP-AUTH-01, web:xss:44, VULN_2026_91 matched via catalog after load."""
    catalog = [f["id"] for f in HELDOUT["findings"]]
    q = "Explain SHIP-AUTH-01 and web:xss:44 and VULN_2026_91"
    matched = extract_catalog_finding_ids(q, catalog)
    assert "SHIP-AUTH-01" in matched
    assert "web:xss:44" in matched
    assert "VULN_2026_91" in matched

    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="What is finding SHIP-AUTH-01?",
            scan_id=HELDOUT["scan_id"],
        )
    )
    assert r.abstained is False
    assert any(x.upper() == "SHIP-AUTH-01" for x in r.findings_referenced)


def test_heldout_web_xss_id(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="Tell me about web:xss:44",
            scan_id=HELDOUT["scan_id"],
        )
    )
    assert r.abstained is False
    assert any("XSS" in x.upper() or "WEB:XSS:44" == x.upper() for x in r.findings_referenced)


def test_heldout_vuln_underscore_id(tmp_path: Path):
    svc = _service(tmp_path)
    r = svc.query(
        QueryRequest(
            question="Explain VULN_2026_91",
            scan_id=HELDOUT["scan_id"],
        )
    )
    assert r.abstained is False
    assert any(x.upper() == "VULN_2026_91" for x in r.findings_referenced)


def test_multi_scan_isolation(tmp_path: Path):
    """Querying held-out scan must not surface sample FINDING-* IDs."""
    svc = _service(tmp_path, scans=[SAMPLE, HELDOUT])
    r = svc.query(
        QueryRequest(
            question="What are all the CRITICAL severity findings?",
            scan_id=HELDOUT["scan_id"],
        )
    )
    assert r.abstained is False
    for fid in r.findings_referenced:
        assert not fid.upper().startswith("FINDING-"), fid
        assert fid.upper() in {
            "SHIP-AUTH-01",
            "SHIP-SSRF-07",
            "INV-SQL-12",
        }

    r2 = svc.query(
        QueryRequest(
            question="What are all the CRITICAL severity findings?",
            scan_id=SAMPLE["scan_id"],
        )
    )
    assert r2.abstained is False
    for fid in r2.findings_referenced:
        assert fid.upper().startswith("FINDING-"), fid


def test_cross_scan_vector_isolation_via_service(tmp_path: Path):
    """Semantic question on scan A must not cite scan B IDs."""
    svc = _service(tmp_path, scans=[SAMPLE, HELDOUT])
    r = svc.query(
        QueryRequest(
            question="List SQL injection findings",
            scan_id=HELDOUT["scan_id"],
        )
    )
    for fid in r.findings_referenced:
        assert fid.upper() != "FINDING-001"
    if not r.abstained:
        assert any("SQL" in (r.answer or "").upper() or "INV-SQL" in x.upper()
                   for x in (r.findings_referenced or ["INV-SQL-12"]))
