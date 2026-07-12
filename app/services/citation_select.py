"""Citation ID selection after generation (server-side, store-bound)."""

from __future__ import annotations

from app.rag.citations import filter_citations_to_answer, validate_finding_ids
from app.rag.generator import GenerationResult
from app.rag.router import RouteResult
from app.retrieval.findings_store import FindingRecord
from app.retrieval.hybrid import HybridRetrievalResult
from app.services.pipeline_common import count_named_topics


def select_citation_ids(
    *,
    question: str,
    route: RouteResult,
    gen: GenerationResult,
    retrieval: HybridRetrievalResult,
    gen_findings: list[FindingRecord],
) -> tuple[list[str], GenerationResult]:
    """Return (safe_finding_ids, possibly-updated gen for existence abstain)."""
    safe = validate_finding_ids(gen.findings_referenced, retrieval.findings)

    if (
        route.top_n
        or route.classify_problem_buckets
        or route.data_impact
        or (gen.raw or {}).get("source") == "structured"
    ) and gen.findings_referenced:
        safe = validate_finding_ids(
            gen.findings_referenced, retrieval.findings or gen_findings
        ) or list(gen.findings_referenced)
    elif route.intent in {
        "list",
        "summary",
        "severity",
        "cross_ref",
        "cluster",
    } and retrieval.findings:
        safe = [f.finding_id for f in retrieval.findings]
    elif route.intent == "compare" and retrieval.findings:
        safe = [f.finding_id for f in retrieval.findings[:6]]
    elif route.intent == "existence":
        if gen.abstained or not retrieval.findings:
            safe = []
        elif not safe:
            safe = [f.finding_id for f in retrieval.findings[:3]]
        else:
            safe = safe[:3]
    elif route.intent in {"explain", "remediation"}:
        if route.class_constraints or route.finding_ids:
            safe = [
                f.finding_id
                for f in retrieval.findings[
                    : max(2, len(route.finding_ids or []) or 2)
                ]
            ]
            if gen.findings_referenced:
                validated = validate_finding_ids(
                    gen.findings_referenced, retrieval.findings
                )
                if validated:
                    safe = validated
        elif safe:
            primary = {f.finding_id for f in retrieval.findings[:3]}
            tight = [fid for fid in safe if fid in primary]
            safe = (tight or safe)[:2]
        elif retrieval.findings:
            safe = [f.finding_id for f in retrieval.findings[:2]]
    elif not safe and retrieval.findings:
        safe = [f.finding_id for f in retrieval.findings[:4]]
    elif safe:
        safe = safe[:6]

    safe = filter_citations_to_answer(
        answer=gen.answer,
        candidate_ids=safe,
        intent=route.intent,
    )

    # Multi-topic compare: keep retrieval union if the model under-cites
    if route.intent == "compare" and retrieval.findings:
        if count_named_topics(question) >= 2:
            pool_ids = [f.finding_id for f in retrieval.findings[:6]]
            if len(pool_ids) > len(safe):
                safe = pool_ids

    if route.intent == "existence" and (gen.abstained or not retrieval.findings):
        safe = []
        retrieval.findings = []
        if not gen.abstained:
            from app.rag.generator import abstention_response

            gen = abstention_response(question, route.intent)

    if gen.findings_referenced and not safe and not retrieval.findings:
        from app.rag.generator import abstention_response

        gen = abstention_response(question, route.intent)
        safe = []

    return safe, gen
