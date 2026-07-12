"""Shared helpers for the query orchestrator (no product policy here)."""

from __future__ import annotations

import time
from typing import Any, Literal

from app.api.schemas import Citation, QueryResponse
from app.rag.generator import GenerationResult

AnswerSource = Literal["structured", "llm", "template", "abstain"]

# Multi-topic compare / coverage cues (store-agnostic tokens)
MULTI_TOPIC_TOKENS = (
    "jwt",
    "password",
    "rate limit",
    "idor",
    "ssrf",
    "xss",
    "sql",
)

PRIORITY_CUES = (
    "fix first",
    "go-live",
    "go live",
    "priorit",
    "before a production",
    "would you fix first",
)


def count_named_topics(question: str, tokens: tuple[str, ...] = MULTI_TOPIC_TOKENS) -> int:
    ql = (question or "").lower()
    return sum(1 for t in tokens if t in ql)


def is_priority_question(question: str) -> bool:
    ql = (question or "").lower()
    return any(x in ql for x in PRIORITY_CUES)


def normalize_answer_source(raw: str | None) -> AnswerSource:
    if raw in {"structured", "llm", "template", "abstain"}:
        return raw  # type: ignore[return-value]
    return "llm"


def latency_since(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def make_response(
    *,
    answer: str,
    citations: list[Citation] | None = None,
    findings_referenced: list[str] | None = None,
    query_intent: str,
    abstained: bool,
    started: float,
    scan_id: str | None,
    answer_source: AnswerSource,
    model_used: str | None = None,
    grounded: bool = True,
) -> QueryResponse:
    return QueryResponse(
        answer=answer,
        citations=citations or [],
        findings_referenced=findings_referenced or [],
        query_intent=query_intent,
        grounded=grounded,
        abstained=abstained,
        latency_ms=latency_since(started),
        scan_id=scan_id,
        answer_source=answer_source,
        model_used=model_used,
    )


def abstain_response(
    *,
    gen: GenerationResult | Any,
    started: float,
    scan_id: str | None,
    route_intent: str = "general",
    model_used: str | None = None,
) -> QueryResponse:
    return make_response(
        answer=gen.answer,
        query_intent=route_intent,
        abstained=True,
        started=started,
        scan_id=scan_id,
        answer_source="abstain",
        model_used=model_used,
    )
