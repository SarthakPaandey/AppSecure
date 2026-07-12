"""Hallucination prevention and citation hygiene."""

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
from app.rag.citations import validate_finding_ids
from app.retrieval.findings_store import FindingRecord, FindingsStore
from app.retrieval.vector_store import VectorStore
from app.services.query_service import QueryService

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


def _make_service(tmp_path: Path, llm: FakeLLM) -> QueryService:
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
    )
    embeddings = FakeEmbeddings(32)
    vs = VectorStore(chroma_path=settings.chroma_path, embeddings=embeddings)
    pipeline = IngestionPipeline(session=session, vector_store=vs, settings=settings)
    pipeline.ingest(
        IngestRequest(scan=ScanIn.model_validate(SAMPLE), reference_documents=[])
    )
    return QueryService(session=session, vector_store=vs, llm=llm, settings=settings)


def test_validate_finding_ids_strips_unknown():
    retrieved = [
        FindingRecord(
            finding_id="FINDING-001",
            scan_id="s",
            title="t",
            severity="CRITICAL",
            cwe_id="CWE-89",
            owasp_category="A03",
            endpoint="/x",
            method="GET",
            parameter="p",
            description="d",
            evidence={},
            remediation_hint="r",
        )
    ]
    assert validate_finding_ids(["FINDING-001", "FINDING-999"], retrieved) == [
        "FINDING-001"
    ]


def test_rce_existence_abstains(tmp_path: Path):
    # Router: existence. Generator should not be needed if empty retrieval short-circuits.
    llm = FakeLLM(
        responses=[
            json.dumps(
                {
                    "intent": "existence",
                    "severity": None,
                    "cwe_id": None,
                    "owasp": None,
                    "endpoint": None,
                    "finding_id": None,
                    "keywords": ["remote code execution"],
                }
            )
        ]
    )
    service = _make_service(tmp_path, llm)
    result = service.query(
        QueryRequest(question="Is there a remote code execution vulnerability?")
    )
    assert result.abstained is True
    assert result.findings_referenced == []
    assert "FINDING-" not in result.answer or "no matching" in result.answer.lower() or "not" in result.answer.lower()


def test_model_cannot_inject_fake_finding_id(tmp_path: Path):
    llm = FakeLLM(
        responses=[
            json.dumps(
                {
                    "intent": "list",
                    "severity": "CRITICAL",
                    "cwe_id": None,
                    "owasp": None,
                    "endpoint": None,
                    "finding_id": None,
                    "keywords": [],
                }
            ),
            json.dumps(
                {
                    "answer": "There is also FINDING-999 RCE.",
                    "findings_referenced": ["FINDING-001", "FINDING-999"],
                    "reference_ids": [],
                    "abstained": False,
                }
            ),
        ]
    )
    service = _make_service(tmp_path, llm)
    result = service.query(QueryRequest(question="What are all the critical severity findings?"))
    assert "FINDING-999" not in result.findings_referenced
    assert set(result.findings_referenced).issubset({"FINDING-001", "FINDING-004"})
