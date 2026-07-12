"""Optional multi-round tool agent (default off). Isolated from main query path."""

from __future__ import annotations

import logging
from typing import Any

from app.api.schemas import QueryRequest, QueryResponse
from app.clients.llm import LLMClient
from app.config import Settings
from app.rag.citations import (
    build_citations,
    filter_citations_to_answer,
    gate_citations,
)
from app.rag.router import RouteResult
from app.retrieval.findings_store import FindingsStore
from app.retrieval.hybrid import HybridRetriever
from app.services.pipeline_common import (
    count_named_topics,
    is_priority_question,
    make_response,
    normalize_answer_source,
)

logger = logging.getLogger(__name__)

STRUCTURED_INTENTS = frozenset(
    {"list", "summary", "severity", "cross_ref", "existence", "cluster"}
)
SYNTHESIS_INTENTS = frozenset({"explain", "remediation", "compare", "general"})


def try_tool_agent(
    *,
    request: QueryRequest,
    route: RouteResult,
    scan_id: str | None,
    started: float,
    settings: Settings,
    llm: LLMClient,
    findings_store: FindingsStore,
    retriever: HybridRetriever,
) -> QueryResponse | None:
    """Run tool agent when enabled. Returns None to fall through to hybrid."""
    if not bool(getattr(settings, "use_tool_agent", False)):
        return None
    if route.intent not in SYNTHESIS_INTENTS:
        return None
    skip = bool(
        route.classify_problem_buckets
        or route.top_n
        or route.data_impact
        or route.want_count
        or route.intent in STRUCTURED_INTENTS
        or bool(getattr(route, "exclude_phrases", None))
    )
    if skip:
        return None

    # Lazy import — keep default path free of agent dependency weight
    from app.rag.tool_agent import FindingsToolAgent
    from app.rag.tools import FindingsToolExecutor

    try:
        executor = FindingsToolExecutor(
            findings_store=findings_store,
            retriever=retriever,
            scan_id=scan_id,
        )
        agent = FindingsToolAgent(
            llm=llm,
            executor=executor,
            max_rounds=int(getattr(settings, "tool_agent_max_rounds", 2)),
        )
        agent_result = agent.run(
            question=request.question,
            intent=route.intent,
            class_constraints=list(route.class_constraints or []),
        )
        gen = agent_result.generation
        agent_findings = agent_result.findings
        if not agent_findings and (gen.abstained or not (gen.answer or "").strip()):
            raise RuntimeError("tool agent returned no findings; use hybrid")

        agent_findings, gen = _enrich_priority(
            request.question, agent_findings, gen, findings_store, scan_id
        )
        agent_findings, gen = _enforce_compare_coverage(
            request.question, route, agent_findings, gen
        )
        agent_findings, gen = _enforce_class_constraints(
            route, agent_findings, gen, retriever
        )
        _reject_off_topic_idor(route, gen)

        knowledge_hits = retriever._retrieve_knowledge(
            question=request.question,
            route=route,
            findings=agent_findings,
            top_k=request.top_k_knowledge
            or max(settings.default_top_k_knowledge, 4),
        )

        allowed = {f.finding_id for f in agent_findings}
        gate = gate_citations(
            answer=gen.answer,
            findings_referenced=gen.findings_referenced,
            allowed_ids=allowed,
            fill_refs_if_empty=bool(agent_findings) and not gen.abstained,
            fill_from=[f.finding_id for f in agent_findings[:6]],
        )
        safe_ids = filter_citations_to_answer(
            answer=gate.answer,
            candidate_ids=gate.findings_referenced,
            intent=route.intent,
        )
        if gen.abstained and not safe_ids:
            if not agent_findings:
                raise RuntimeError("tool agent abstain empty; use hybrid")
            if route.class_constraints:
                raise RuntimeError(
                    "tool agent abstained with class findings; use hybrid"
                )

        citations = build_citations(
            findings=agent_findings,
            finding_ids=safe_ids,
            knowledge_hits=knowledge_hits if safe_ids else [],
            reference_ids=gen.reference_ids if not gen.abstained else [],
        )
        raw_source = "llm"
        if gen.abstained and not safe_ids:
            raw_source = "abstain"
        elif (gen.raw or {}).get("source") == "tool_agent_fallback":
            raw_source = "template"
        source = normalize_answer_source(raw_source)
        model_used = agent_result.tool_model or getattr(
            llm, "last_tool_model_used", None
        )
        return make_response(
            answer=gate.answer,
            citations=citations,
            findings_referenced=safe_ids,
            query_intent=route.intent,
            abstained=bool(gen.abstained and not safe_ids),
            started=started,
            scan_id=scan_id,
            answer_source=source,
            model_used=model_used if source == "llm" else None,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Tool agent failed; falling back to hybrid path",
            extra={
                "question": request.question,
                "intent": route.intent,
                "fallback_reason": str(exc),
            },
        )
        return None


def _enrich_priority(
    question: str,
    agent_findings: list[Any],
    gen: Any,
    findings_store: FindingsStore,
    scan_id: str | None,
) -> tuple[list[Any], Any]:
    if not is_priority_question(question):
        return agent_findings, gen
    crits = findings_store.search(scan_id=scan_id, severity="CRITICAL")
    crit_ids = {f.finding_id for f in crits}
    seen_ids = {f.finding_id for f in agent_findings} | set(
        gen.findings_referenced or []
    )
    if crit_ids and not crit_ids.issubset(seen_ids):
        by_id = {f.finding_id: f for f in agent_findings}
        for c in crits:
            by_id[c.finding_id] = c
        agent_findings = list(by_id.values())
        for cid in sorted(crit_ids):
            if cid not in (gen.findings_referenced or []):
                gen.findings_referenced = [cid, *(gen.findings_referenced or [])]
        ans = gen.answer or ""
        if crit_ids and not any(cid in ans for cid in crit_ids):
            raise RuntimeError(
                "tool agent priority answer omitted CRITICAL; use hybrid"
            )
    return agent_findings, gen


def _enforce_compare_coverage(
    question: str,
    route: RouteResult,
    agent_findings: list[Any],
    gen: Any,
) -> tuple[list[Any], Any]:
    if route.intent != "compare":
        return agent_findings, gen
    named = count_named_topics(question)
    if named >= 2 and len(agent_findings) < 2:
        raise RuntimeError("tool agent under-cited multi-topic compare; use hybrid")
    if named >= 2 and len(agent_findings) >= 2:
        gen.findings_referenced = [f.finding_id for f in agent_findings[:8]]
    return agent_findings, gen


def _enforce_class_constraints(
    route: RouteResult,
    agent_findings: list[Any],
    gen: Any,
    retriever: HybridRetriever,
) -> tuple[list[Any], Any]:
    if not route.class_constraints:
        return agent_findings, gen
    if not agent_findings:
        raise RuntimeError("tool agent empty under class constraints; use hybrid")
    class_hits = retriever._filter_by_class_constraints(
        agent_findings, list(route.class_constraints)
    )
    if not class_hits:
        raise RuntimeError("tool agent findings miss class constraints; use hybrid")
    agent_findings = class_hits
    allowed = {f.finding_id for f in agent_findings}
    gen.findings_referenced = [
        r for r in gen.findings_referenced if r in allowed
    ] or [f.finding_id for f in agent_findings[:6]]
    return agent_findings, gen


def _reject_off_topic_idor(route: RouteResult, gen: Any) -> None:
    if not route.class_constraints or not (gen.answer or "").strip():
        return
    ans_l = gen.answer.lower()
    wants_idor = any(
        "idor" in c or "bola" in c or "cwe-639" in c for c in route.class_constraints
    )
    if wants_idor and (
        "sql injection" in ans_l or "parameterized quer" in ans_l
    ) and "idor" not in ans_l and "cwe-639" not in ans_l:
        raise RuntimeError("tool agent off-topic for IDOR class; use hybrid")
