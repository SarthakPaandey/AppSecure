"""API request/response schemas."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class EvidenceModel(BaseModel):
    request: str = ""
    response_snippet: str = ""


class FindingIn(BaseModel):
    id: str
    title: str
    severity: str
    cwe_id: str
    owasp_category: str
    endpoint: str
    method: str = ""
    parameter: str = "N/A"
    description: str = ""
    evidence: EvidenceModel | dict[str, Any] = Field(default_factory=dict)
    remediation_hint: str = ""


class ScanIn(BaseModel):
    scan_id: str
    target: str
    scan_timestamp: str
    findings: list[FindingIn]


class ReferenceDocumentIn(BaseModel):
    id: str | None = None
    title: str
    text: str
    source_url: str | None = None


class IngestRequest(BaseModel):
    scan: ScanIn
    reference_documents: list[ReferenceDocumentIn] = Field(default_factory=list)


class IngestResponse(BaseModel):
    scan_id: str
    findings_ingested: int
    knowledge_chunks: int
    status: str = "ok"
    latency_ms: int


class QueryRequest(BaseModel):
    question: str = Field(..., min_length=1)
    scan_id: str | None = None
    top_k_knowledge: int | None = Field(default=None, ge=1, le=20)


class Citation(BaseModel):
    type: Literal["finding", "reference"]
    id: str
    title: str | None = None
    severity: str | None = None
    url: str | None = None
    snippet: str | None = None


class QueryResponse(BaseModel):
    answer: str
    citations: list[Citation]
    findings_referenced: list[str]
    query_intent: str
    grounded: bool = True
    abstained: bool = False
    latency_ms: int
    scan_id: str | None = None
    # Explainability: how the answer was produced
    answer_source: Literal["structured", "llm", "template", "abstain"] = "structured"
    model_used: str | None = None


class FindingOut(BaseModel):
    id: str
    title: str
    severity: str
    cwe_id: str
    owasp_category: str
    endpoint: str
    method: str
    parameter: str
    description: str
    remediation_hint: str


class HealthResponse(BaseModel):
    status: str
    findings_count: int
    knowledge_chunk_count: int
    embedding_model: str
    llm_model: str
    llm_fallback_models: list[str] = []
    llm_reasoning_effort: str = "none"
    # Retrieval observability (production hybrid IR)
    bm25_docs: int = 0
    rerank_mode: str = "auto"
    cross_encoder_model: str | None = None
    retrieval_stack: str = "sql+bm25+dense+rrf+ce"
