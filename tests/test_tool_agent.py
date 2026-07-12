"""Tool-calling agent unit tests (FakeLLM scripts tools)."""

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
from app.rag.tool_agent import FindingsToolAgent
from app.rag.tools import FindingsToolExecutor
from app.retrieval.findings_store import FindingsStore
from app.retrieval.hybrid import HybridRetriever
from app.retrieval.vector_store import VectorStore
from app.services.query_service import QueryService

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


def test_tool_executor_list_and_get():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
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
    settings = Settings(
        modelscope_api_key="x",
        groq_api_key="x",
        data_dir=ROOT / "data",
        use_tool_agent=True,
    )
    vs = VectorStore(
        chroma_path=Path("/tmp/chroma-tool-test"),  # may not exist; not used for list
        embeddings=FakeEmbeddings(8),
    )
    # minimal retriever for search tool
    hr = HybridRetriever(findings_store=store, vector_store=vs, settings=settings)
    hr.rebuild_bm25()
    ex = FindingsToolExecutor(
        findings_store=store, retriever=hr, scan_id=SAMPLE["scan_id"]
    )
    out = json.loads(ex.execute("list_findings", {"severity": "CRITICAL"}))
    assert out["count"] == 2
    ids = {f["id"] for f in out["findings"]}
    assert ids == {"FINDING-001", "FINDING-004"}
    one = json.loads(ex.execute("get_finding", {"finding_id": "FINDING-007"}))
    assert one["finding"]["id"] == "FINDING-007"
    assert "source_url" in one["finding"]["parameter"].lower() or one["finding"][
        "cwe_id"
    ] == "CWE-918"


def test_tool_agent_scripted_flow(tmp_path: Path):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
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
        use_tool_agent=True,
        rerank_mode="light",
        cross_encoder_enabled=False,
    )
    vs = VectorStore(chroma_path=settings.chroma_path, embeddings=FakeEmbeddings(32))
    IngestionPipeline(session=session, vector_store=vs, settings=settings).ingest(
        IngestRequest(scan=ScanIn.model_validate(SAMPLE), reference_documents=[])
    )
    store = FindingsStore(session)
    hr = HybridRetriever(findings_store=store, vector_store=vs, settings=settings)
    hr.rebuild_bm25()
    llm = FakeLLM(
        tool_script=[
            [
                ("get_finding", {"finding_id": "FINDING-002"}),
                ("get_finding", {"finding_id": "FINDING-008"}),
            ],
            json.dumps(
                {
                    "answer": "Shared ownership middleware fixes FINDING-002 and FINDING-008.",
                    "findings_referenced": ["FINDING-002", "FINDING-008"],
                    "reference_ids": [],
                    "abstained": False,
                }
            ),
        ]
    )
    agent = FindingsToolAgent(
        llm=llm,
        executor=FindingsToolExecutor(
            findings_store=store, retriever=hr, scan_id=SAMPLE["scan_id"]
        ),
    )
    result = agent.run(
        question="How would you fix both IDOR findings with shared middleware?",
        intent="remediation",
        class_constraints=["idor", "bola", "cwe-639"],
    )
    assert result.generation.abstained is False
    assert {"FINDING-002", "FINDING-008"} <= set(result.generation.findings_referenced)
    assert result.rounds >= 1


def test_query_service_tool_agent_path(tmp_path: Path):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
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
        use_tool_agent=True,
        rerank_mode="light",
        cross_encoder_enabled=False,
    )
    vs = VectorStore(chroma_path=settings.chroma_path, embeddings=FakeEmbeddings(32))
    IngestionPipeline(session=session, vector_store=vs, settings=settings).ingest(
        IngestRequest(scan=ScanIn.model_validate(SAMPLE), reference_documents=[])
    )
    llm = FakeLLM(
        tool_script=[
            [("get_finding", {"finding_id": "FINDING-001"})],
            json.dumps(
                {
                    "answer": "Fix SQLi on transaction search with parameterized queries (FINDING-001).",
                    "findings_referenced": ["FINDING-001"],
                    "reference_ids": [],
                    "abstained": False,
                }
            ),
        ]
    )
    svc = QueryService(
        session=session, vector_store=vs, llm=llm, settings=settings
    )
    r = svc.query(
        QueryRequest(question="How do I fix the SQL injection in transaction search?")
    )
    assert r.abstained is False
    assert "FINDING-001" in r.findings_referenced
    assert r.answer_source in {"llm", "template"}
