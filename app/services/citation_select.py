"""Citation ID selection after generation (server-side, store-bound)."""

from __future__ import annotations

from app.rag.citations import (
    filter_citations_to_answer,
    finding_ids_mentioned_in_answer,
    validate_finding_ids,
)
from app.rag.generator import GenerationResult
from app.rag.router import RouteResult
from app.retrieval.findings_store import FindingRecord
from app.retrieval.hybrid import HybridRetrievalResult
from app.services.compare_focus import focus_findings_for_question


def select_citation_ids(
    *,
    question: str,
    route: RouteResult,
    gen: GenerationResult,
    retrieval: HybridRetrievalResult,
    gen_findings: list[FindingRecord],
) -> tuple[list[str], GenerationResult]:
    """Return (safe_finding_ids, possibly-updated gen for existence abstain)."""
    pool = list(retrieval.findings or gen_findings)
    source = str((gen.raw or {}).get("source") or "")
    is_template = source in {"template", "structured"}

    safe = validate_finding_ids(gen.findings_referenced, pool)

    if (
        route.top_n
        or route.classify_problem_buckets
        or route.data_impact
        or source == "structured"
    ) and gen.findings_referenced:
        safe = validate_finding_ids(
            gen.findings_referenced, pool or gen_findings
        ) or list(gen.findings_referenced)
    elif route.intent in {
        "list",
        "summary",
        "severity",
        "cross_ref",
        "cluster",
    } and pool:
        safe = [f.finding_id for f in pool]
    elif route.intent == "compare":
        focused = focus_findings_for_question(
            question, gen_findings or pool, max_n=4
        )
        focus_ids = [f.finding_id for f in focused]
        focus_set = {x.upper() for x in focus_ids}
        # Prefer model refs that fall inside the class-focused set
        if safe:
            tight = [fid for fid in safe if fid.upper() in focus_set]
            safe = tight or focus_ids[:3]
        else:
            safe = focus_ids[:3]
        # Cap compare citations tightly (templates especially)
        safe = safe[:4 if not is_template else 3]
    elif route.intent == "existence":
        if gen.abstained or not pool:
            safe = []
        elif not safe:
            safe = [f.finding_id for f in pool[:3]]
        else:
            safe = safe[:3]
    elif route.intent in {"explain", "remediation"}:
        focused = focus_findings_for_question(
            question, gen_findings or pool, max_n=3
        )
        focus_ids = [f.finding_id for f in focused]
        focus_set = {x.upper() for x in focus_ids}
        if route.class_constraints or route.finding_ids:
            if gen.findings_referenced:
                validated = validate_finding_ids(gen.findings_referenced, pool)
                if validated:
                    safe = validated
            if not safe:
                safe = focus_ids[: max(2, len(route.finding_ids or []) or 2)]
        elif safe:
            # Prefer intersection with focused class + primary hits
            primary = {f.finding_id.upper() for f in pool[:3]} | focus_set
            tight = [fid for fid in safe if fid.upper() in primary]
            safe = (tight or safe)[:2]
        elif focus_ids:
            safe = focus_ids[:2]
        elif pool:
            safe = [f.finding_id for f in pool[:2]]
        if is_template:
            safe = safe[:2]
    elif not safe and pool:
        safe = [f.finding_id for f in pool[:4]]
    elif safe:
        safe = safe[:6]

    # Prefer IDs actually mentioned in the answer when present
    mentioned = finding_ids_mentioned_in_answer(
        gen.answer, catalog_ids=[f.finding_id for f in pool]
    )
    if mentioned and route.intent in {"compare", "explain", "remediation"}:
        allowed = {c.upper(): c for c in safe} if safe else {
            f.finding_id.upper(): f.finding_id for f in pool
        }
        named = [allowed[m.upper()] for m in mentioned if m.upper() in allowed]
        if named:
            safe = named

    safe = filter_citations_to_answer(
        answer=gen.answer,
        candidate_ids=safe,
        intent=route.intent,
    )

    # Multi-topic compare: only fill *missing* class hits — never dump full pool
    if route.intent == "compare" and pool:
        focused = focus_findings_for_question(question, pool, max_n=4)
        focus_ids = [f.finding_id for f in focused]
        if focus_ids and not safe:
            safe = focus_ids[:3]
        elif focus_ids and len(safe) < 2:
            # Under-cited: add focused IDs not already present
            have = {x.upper() for x in safe}
            for fid in focus_ids:
                if fid.upper() not in have:
                    safe.append(fid)
                    have.add(fid.upper())
                if len(safe) >= 3:
                    break

    if route.intent == "existence" and (gen.abstained or not pool):
        safe = []
        retrieval.findings = []
        if not gen.abstained:
            from app.rag.generator import abstention_response

            gen = abstention_response(question, route.intent)

    if gen.findings_referenced and not safe and not pool:
        from app.rag.generator import abstention_response

        gen = abstention_response(question, route.intent)
        safe = []

    return safe, gen
