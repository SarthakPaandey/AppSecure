"""HTTP routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.schemas import (
    FindingOut,
    HealthResponse,
    IngestRequest,
    IngestResponse,
    QueryRequest,
    QueryResponse,
)
from app.db.session import get_session
from app.ingestion.pipeline import IngestionPipeline
from app.retrieval.findings_store import FindingsStore
from app.services.query_service import QueryService

router = APIRouter()


def _app_state(request: Request):
    return request.app.state


@router.get("/health", response_model=HealthResponse)
def health(request: Request, session: Session = Depends(get_session)) -> HealthResponse:
    state = _app_state(request)
    settings = state.settings
    vector_store = state.vector_store
    store = FindingsStore(session)
    bm25 = getattr(state, "bm25_index", None)
    bm25_n = len(bm25.index) if bm25 is not None else 0
    return HealthResponse(
        status="ok",
        findings_count=store.count(),
        knowledge_chunk_count=vector_store.count,
        embedding_model=settings.embedding_model,
        llm_model=settings.llm_model,
        llm_fallback_models=settings.llm_model_chain()[1:],
        llm_reasoning_effort=settings.llm_reasoning_effort or "none",
        bm25_docs=bm25_n,
        rerank_mode=getattr(settings, "rerank_mode", "auto"),
        cross_encoder_model=getattr(settings, "cross_encoder_model", None)
        if getattr(settings, "cross_encoder_enabled", True)
        else None,
        retrieval_stack="sql+bm25+dense+rrf+ce",
    )


@router.post("/ingest", response_model=IngestResponse)
def ingest(
    body: IngestRequest,
    request: Request,
    session: Session = Depends(get_session),
) -> IngestResponse:
    state = _app_state(request)
    bm25 = getattr(state, "bm25_index", None)
    pipeline = IngestionPipeline(
        session=session,
        vector_store=state.vector_store,
        settings=state.settings,
        bm25_index=bm25,
    )
    try:
        return pipeline.ingest(body)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Ingest failed: {exc}") from exc


@router.post("/query", response_model=QueryResponse)
def query(
    body: QueryRequest,
    request: Request,
    session: Session = Depends(get_session),
) -> QueryResponse:
    state = _app_state(request)
    service = QueryService(
        session=session,
        vector_store=state.vector_store,
        llm=state.llm,
        settings=state.settings,
        bm25_index=getattr(state, "bm25_index", None),
    )
    try:
        return service.query(body)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Query failed: {exc}") from exc


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def list_findings(scan_id: str, session: Session = Depends(get_session)) -> list[FindingOut]:
    store = FindingsStore(session)
    records = store.list_all(scan_id=scan_id)
    if not records:
        # Distinguish unknown scan vs empty
        if store.count(scan_id=scan_id) == 0 and store.latest_scan_id() != scan_id:
            # still return empty list for simplicity
            return []
    return [
        FindingOut(
            id=r.finding_id,
            title=r.title,
            severity=r.severity,
            cwe_id=r.cwe_id,
            owasp_category=r.owasp_category,
            endpoint=r.endpoint,
            method=r.method,
            parameter=r.parameter,
            description=r.description,
            remediation_hint=r.remediation_hint,
        )
        for r in records
    ]
