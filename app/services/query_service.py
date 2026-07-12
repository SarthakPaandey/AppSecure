"""Query orchestration: route → retrieve → ground → cite."""

from __future__ import annotations

import time

from sqlalchemy.orm import Session

from app.api.schemas import QueryRequest, QueryResponse
from app.clients.llm import LLMClient
from app.config import Settings
from app.rag.citations import (
    build_citations,
    filter_citations_to_answer,
    gate_citations,
    validate_finding_ids,
)
from app.rag.generator import AnswerGenerator, abstention_response
from app.rag.planner import (
    SemanticPlanner,
    merge_plan_into_route,
    resolve_endpoints_against_catalog,
)
from app.rag.router import QueryRouter, rule_based_route
from app.rag.scope import is_out_of_scope, scope_refusal_response
from app.rag.tool_agent import FindingsToolAgent
from app.rag.tools import FindingsToolExecutor
from app.retrieval.endpoint_utils import resolve_soft_endpoints, unknown_paths_in_question
from app.retrieval.bm25_index import FindingsBM25Index
from app.retrieval.filter_engine import apply_filters, route_to_filter_spec
from app.retrieval.findings_store import FindingsStore
from app.retrieval.hybrid import HybridRetriever
from app.retrieval.taxonomy import TOPICS
from app.retrieval.vector_store import VectorStore

import logging

logger = logging.getLogger(__name__)

# Intents answered via SQL / structured templates (no tool agent required)
STRUCTURED_INTENTS = frozenset(
    {"list", "summary", "severity", "cross_ref", "existence", "cluster"}
)
# Synthesis intents prefer tool-calling agent when enabled
# (cluster stays structured: needs full inventory + control-family template)
SYNTHESIS_INTENTS = frozenset(
    {"explain", "remediation", "compare", "general"}
)


class QueryService:
    def __init__(
        self,
        *,
        session: Session,
        vector_store: VectorStore,
        llm: LLMClient,
        settings: Settings,
        bm25_index: FindingsBM25Index | None = None,
    ) -> None:
        self.session = session
        self.vector_store = vector_store
        self.llm = llm
        self.settings = settings
        self.findings_store = FindingsStore(session)
        self.router = QueryRouter(llm)
        self.generator = AnswerGenerator(llm)
        self.planner = SemanticPlanner(
            llm,
            enabled=bool(getattr(settings, "use_semantic_planner", True)),
        )
        self.bm25_index = bm25_index or FindingsBM25Index()
        self.retriever = HybridRetriever(
            findings_store=self.findings_store,
            vector_store=vector_store,
            settings=settings,
            bm25_index=self.bm25_index,
        )
        if len(self.bm25_index.index) == 0:
            self.retriever.rebuild_bm25()

    def query(self, request: QueryRequest) -> QueryResponse:
        started = time.perf_counter()
        scan_id = request.scan_id or self.findings_store.latest_scan_id()
        all_findings = self.findings_store.list_all(scan_id=scan_id)

        # Empty store: clear product boundary (no waffle)
        if not all_findings:
            gen = scope_refusal_response(reason="out_of_scope", has_scan_data=False)
            latency_ms = int((time.perf_counter() - started) * 1000)
            return QueryResponse(
                answer=gen.answer,
                citations=[],
                findings_referenced=[],
                query_intent="general",
                grounded=True,
                abstained=True,
                latency_ms=latency_ms,
                scan_id=scan_id,
                answer_source="abstain",
                model_used=None,
            )

        # Stage A: rules always; optional semantic planner for soft NL only
        route = rule_based_route(request.question)
        # Map soft NL endpoint cues ("X endpoint" / "Y page") → live catalog paths
        catalog = self.findings_store.distinct_endpoints(scan_id)
        soft_eps = resolve_soft_endpoints(request.question, catalog)
        if soft_eps:
            route.endpoint_substrings = list(
                dict.fromkeys([*route.endpoint_substrings, *soft_eps])
            )
            # Prefer catalog path as primary endpoint filter when unambiguous
            if not route.endpoint and len(soft_eps) == 1 and soft_eps[0].startswith("/"):
                route.endpoint = soft_eps[0]
                route.endpoint_strict = True
            elif soft_eps and not route.endpoint_strict:
                # Token matched a catalog path → allow strict substring filter
                if any(e.startswith("/") for e in soft_eps):
                    route.endpoint_strict = True

        # Off-topic / non-scan questions: refuse before planner/LLM
        if is_out_of_scope(request.question, route):
            gen = scope_refusal_response(reason="out_of_scope", has_scan_data=True)
            latency_ms = int((time.perf_counter() - started) * 1000)
            return QueryResponse(
                answer=gen.answer,
                citations=[],
                findings_referenced=[],
                query_intent=route.intent or "general",
                grounded=True,
                abstained=True,
                latency_ms=latency_ms,
                scan_id=scan_id,
                answer_source="abstain",
                model_used=None,
            )

        rules_confident = bool(
            route.want_count
            or route.answer_mode in {"count", "top_n"}
            or route.cwe_id
            or route.finding_ids
            or route.classify_problem_buckets
            or getattr(route, "path_param_only", False)
            or (
                # Multi-topic chain questions: taxonomy is enough; skip slow planner
                len(getattr(route, "topics", None) or []) >= 2
                and any(
                    t in (route.topics or [])
                    for t in ("authentication", "mass_assignment", "authorization")
                )
            )
            or (
                route.intent == "existence"
                and any(
                    x in request.question.lower()
                    for x in ("rce", "remote code", "xxe", "reverse shell")
                )
            )
        )
        if getattr(self.settings, "use_semantic_planner", True) and not rules_confident:
            plan = self.planner.plan(
                request.question,
                endpoints=catalog,
                topic_names=list(TOPICS.keys()),
            )
            if plan is not None:
                if plan.endpoint_substrings:
                    plan.endpoint_substrings = resolve_endpoints_against_catalog(
                        plan.endpoint_substrings, catalog
                    )
                route = merge_plan_into_route(route, plan)
                logger.info(
                    "Semantic plan intent=%s mode=%s conf=%.2f topics=%s",
                    plan.intent,
                    plan.answer_mode,
                    plan.confidence,
                    plan.include_topics,
                )

        # Normalize rule operators after merge
        if route.want_count:
            route.intent = "list"
            route.answer_mode = "count"
        if route.classify_problem_buckets:
            route.intent = "list"
            route.severity = "HIGH"
            route.severities = ["HIGH"]
            route.class_constraints = []
            route.include_phrases = []
        if route.data_impact:
            route.class_constraints = []
            if route.intent in {"explain", "general", "compare"}:
                route.intent = "list"
        if route.top_n and route.answer_mode == "top_n":
            route.intent = "list"

        # --- Precision path: set algebra on full inventory (no agent, no free-form count) ---
        spec = route_to_filter_spec(route)
        precision_mode = (
            spec.want_count
            or spec.answer_mode in {"count", "top_n"}
            or bool(spec.exclude_phrases)
            or bool(spec.exclude_topics)
            or bool(spec.exclude_severities)
            or bool(getattr(spec, "path_param_only", False))
            or (
                bool(spec.include_phrases)
                and route.intent in {"list", "general"}
            )
            or (
                bool(spec.include_topics)
                and route.intent in {"list", "general"}
            )
            or (bool(spec.endpoint_substrings) and route.endpoint_strict)
            or (
                bool(spec.include_severities)
                and route.intent in {"list", "existence"}
                and not route.classify_problem_buckets
            )
        )
        # Always apply filter for existence with strict structural slots only
        # (severity, CWE, endpoint). Topic/phrase matching uses hybrid
        # existence_search which is phrase-precise and won't false-match.
        if route.intent == "existence" and (
            spec.include_severities
            or spec.cwe_ids
            or spec.endpoint_substrings
        ):
            precision_mode = True
        # Topic-based existence: when the question asks about a specific
        # topic (e.g. "secrets management", "XSS", "IDOR"), use precision
        # filtering. If the question lists multiple absent vulnerability
        # types (e.g. "RCE, command injection, reverse shell"), defer to
        # hybrid existence_search for phrase precision.
        from app.retrieval.synonyms import extract_search_phrases, partition_phrases

        if route.intent == "existence" and spec.include_topics and not route.classify_problem_buckets:
            q_text = request.question or ""
            # Multi-absent detection: comma-separated items with "or"
            # (e.g. "RCE, command injection, or reverse shell")
            comma_count = q_text.count(",")
            has_or = " or " in q_text.lower()
            multi_absent = comma_count >= 2 or (comma_count >= 1 and has_or)
            if not multi_absent:
                precision_mode = True

        if precision_mode and not route.classify_problem_buckets and not route.data_impact:
            filtered = apply_filters(all_findings, spec)
            gen = self.generator.generate(
                question=request.question,
                intent=route.intent if not spec.want_count else "list",
                findings=filtered,
                knowledge_hits=[],
                want_parameter=route.want_parameter,
                want_endpoint=route.want_endpoint,
                top_n=spec.top_n if spec.answer_mode == "top_n" else None,
                want_count=spec.want_count or spec.answer_mode == "count",
                use_dynamic_synthesis=bool(
                    getattr(self.settings, "use_dynamic_synthesis", True)
                ),
            )
            allowed = {f.finding_id for f in filtered}
            gate = gate_citations(
                answer=gen.answer,
                findings_referenced=gen.findings_referenced
                or [f.finding_id for f in filtered],
                allowed_ids=allowed,
                fill_refs_if_empty=bool(filtered) and not gen.abstained,
                fill_from=[f.finding_id for f in filtered],
            )
            safe_ids = gate.findings_referenced
            citations = build_citations(
                findings=filtered,
                finding_ids=safe_ids,
                knowledge_hits=[],
                reference_ids=gen.reference_ids,
            )
            latency_ms = int((time.perf_counter() - started) * 1000)
            abstained = bool(
                gen.abstained or (not filtered and route.intent == "existence")
            )
            return QueryResponse(
                answer=gate.answer,
                citations=citations if not abstained else [],
                findings_referenced=safe_ids if not abstained else [],
                query_intent=route.intent,
                grounded=True,
                abstained=abstained,
                latency_ms=latency_ms,
                scan_id=scan_id,
                answer_source="structured" if not abstained else "abstain",
                model_used=None,
            )

        unknown_paths = unknown_paths_in_question(request.question, all_findings)
        if unknown_paths and any(
            x in request.question.lower()
            for x in ("vulnerable", "idor", "finding", "issue", "broken", "on ")
        ):
            latency_ms = int((time.perf_counter() - started) * 1000)
            paths = ", ".join(f"`{p}`" for p in unknown_paths)
            known = sorted({f.endpoint for f in all_findings if f.endpoint})[:6]
            known_txt = ", ".join(f"`{p}`" for p in known) if known else "(none ingested)"
            return QueryResponse(
                answer=(
                    f"No findings in this scan reference endpoint path(s) {paths}. "
                    "That path does not appear in the ingested findings dataset, so I will not "
                    f"invent vulnerabilities for it. Example endpoints from this scan: {known_txt}."
                ),
                citations=[],
                findings_referenced=[],
                query_intent="existence",
                grounded=True,
                abstained=True,
                latency_ms=latency_ms,
                scan_id=scan_id,
                answer_source="abstain",
                model_used=None,
            )

        # Prefer deterministic store templates (faster + no invented CWE/severity)
        skip_agent = bool(
            route.classify_problem_buckets
            or route.top_n
            or route.data_impact
            or route.want_count
            or route.intent in STRUCTURED_INTENTS
            or bool(getattr(route, "exclude_phrases", None))
        )
        use_agent = (
            bool(getattr(self.settings, "use_tool_agent", True))
            and (route.intent in SYNTHESIS_INTENTS)
            and not skip_agent
        )

        # --- Path A: tool-calling agent for synthesis (separate Groq tool model) ---
        if use_agent:
            try:
                executor = FindingsToolExecutor(
                    findings_store=self.findings_store,
                    retriever=self.retriever,
                    scan_id=scan_id,
                )
                agent = FindingsToolAgent(
                    llm=self.llm,
                    executor=executor,
                    max_rounds=int(getattr(self.settings, "tool_agent_max_rounds", 2)),
                )
                agent_result = agent.run(
                    question=request.question,
                    intent=route.intent,
                    class_constraints=list(route.class_constraints or []),
                )
                gen = agent_result.generation
                agent_findings = agent_result.findings
                # If agent found nothing useful, fall through to hybrid path
                if not agent_findings and (
                    gen.abstained or not (gen.answer or "").strip()
                ):
                    raise RuntimeError("tool agent returned no findings; use hybrid")

                # Go-live / fix-first: agent must surface CRITICAL findings when they exist
                q_l = request.question.lower()
                priority_q = any(
                    x in q_l
                    for x in (
                        "fix first",
                        "go-live",
                        "go live",
                        "priorit",
                        "before a production",
                        "would you fix first",
                    )
                )
                if priority_q:
                    crits = self.findings_store.search(
                        scan_id=scan_id, severity="CRITICAL"
                    )
                    crit_ids = {f.finding_id for f in crits}
                    seen_ids = {f.finding_id for f in agent_findings} | set(
                        gen.findings_referenced or []
                    )
                    if crit_ids and not crit_ids.issubset(seen_ids):
                        # Merge CRITICAL into agent pool; if still missing from answer
                        # refs, fall through so hybrid+priority seeding can rank them.
                        by_id = {f.finding_id: f for f in agent_findings}
                        for c in crits:
                            by_id[c.finding_id] = c
                        agent_findings = list(by_id.values())
                        for cid in sorted(crit_ids):
                            if cid not in (gen.findings_referenced or []):
                                gen.findings_referenced = [
                                    cid,
                                    *(gen.findings_referenced or []),
                                ]
                        # If answer text omits every CRITICAL id, prefer hybrid synthesis
                        ans = gen.answer or ""
                        if crit_ids and not any(cid in ans for cid in crit_ids):
                            raise RuntimeError(
                                "tool agent priority answer omitted CRITICAL; use hybrid"
                            )

                # Multi-topic compare: require coverage of named topics
                if route.intent == "compare":
                    ql_cmp = request.question.lower()
                    named = sum(
                        1
                        for t in (
                            "jwt",
                            "password",
                            "rate limit",
                            "idor",
                            "ssrf",
                            "xss",
                            "sql",
                        )
                        if t in ql_cmp
                    )
                    if named >= 2 and len(agent_findings) < 2:
                        raise RuntimeError(
                            "tool agent under-cited multi-topic compare; use hybrid"
                        )
                    # Expand citations to all tool-loaded findings for multi-topic
                    if named >= 2 and len(agent_findings) >= 2:
                        gen.findings_referenced = [
                            f.finding_id for f in agent_findings[:8]
                        ]

                # Class-constrained Qs (e.g. both IDOR findings): agent must stay on class
                if route.class_constraints and agent_findings:
                    class_hits = self.retriever._filter_by_class_constraints(
                        agent_findings, list(route.class_constraints)
                    )
                    if not class_hits:
                        raise RuntimeError(
                            "tool agent findings miss class constraints; use hybrid"
                        )
                    agent_findings = class_hits
                    # Drop off-class citations the model may have invented
                    allowed_class = {f.finding_id for f in agent_findings}
                    gen.findings_referenced = [
                        r for r in gen.findings_referenced if r in allowed_class
                    ] or [f.finding_id for f in agent_findings[:6]]
                elif route.class_constraints and not agent_findings:
                    raise RuntimeError(
                        "tool agent empty under class constraints; use hybrid"
                    )

                # Off-topic answer text for class-constrained remediation (e.g. SQLi for IDOR)
                if route.class_constraints and (gen.answer or "").strip():
                    ans_l = gen.answer.lower()
                    wants_idor = any(
                        "idor" in c or "bola" in c or "cwe-639" in c
                        for c in route.class_constraints
                    )
                    if wants_idor and (
                        "sql injection" in ans_l or "parameterized quer" in ans_l
                    ) and "idor" not in ans_l and "cwe-639" not in ans_l:
                        raise RuntimeError(
                            "tool agent off-topic for IDOR class; use hybrid"
                        )

                knowledge_hits = self.retriever._retrieve_knowledge(
                    question=request.question,
                    route=route,
                    findings=agent_findings,
                    top_k=request.top_k_knowledge
                    or max(self.settings.default_top_k_knowledge, 4),
                )

                allowed = {f.finding_id for f in agent_findings}
                gate = gate_citations(
                    answer=gen.answer,
                    findings_referenced=gen.findings_referenced,
                    allowed_ids=allowed,
                    fill_refs_if_empty=bool(agent_findings) and not gen.abstained,
                    fill_from=[f.finding_id for f in agent_findings[:6]],
                )
                safe_finding_ids = gate.findings_referenced
                safe_finding_ids = filter_citations_to_answer(
                    answer=gate.answer,
                    candidate_ids=safe_finding_ids,
                    intent=route.intent,
                )
                if gen.abstained and not safe_finding_ids:
                    if not agent_findings:
                        raise RuntimeError("tool agent abstain empty; use hybrid")
                    if route.class_constraints:
                        raise RuntimeError(
                            "tool agent abstained with class findings; use hybrid"
                        )

                citations = build_citations(
                    findings=agent_findings,
                    finding_ids=safe_finding_ids,
                    knowledge_hits=knowledge_hits if safe_finding_ids else [],
                    reference_ids=gen.reference_ids if not gen.abstained else [],
                )
                answer_source = "llm"
                if gen.abstained and not safe_finding_ids:
                    answer_source = "abstain"
                elif (gen.raw or {}).get("source") == "tool_agent_fallback":
                    answer_source = "template"
                model_used = agent_result.tool_model or getattr(
                    self.llm, "last_tool_model_used", None
                )
                latency_ms = int((time.perf_counter() - started) * 1000)
                return QueryResponse(
                    answer=gate.answer,
                    citations=citations,
                    findings_referenced=safe_finding_ids,
                    query_intent=route.intent,
                    grounded=True,
                    abstained=bool(gen.abstained and not safe_finding_ids),
                    latency_ms=latency_ms,
                    scan_id=scan_id,
                    answer_source=answer_source  # type: ignore[arg-type]
                    if answer_source in {"structured", "llm", "template", "abstain"}
                    else "llm",
                    model_used=model_used if answer_source == "llm" else None,
                )
            except Exception as exc:  # noqa: BLE001
                # Fall through to hybrid retrieve + generator path
                fallback_reason = str(exc)
                logger.warning(
                    "Tool agent failed; falling back to hybrid path",
                    extra={
                        "question": request.question,
                        "intent": route.intent,
                        "fallback_reason": fallback_reason,
                    },
                )

        # --- Path B: hybrid retrieve + structured/LLM generator (reliable fallback) ---
        # Fast path: inventory/template Qs only need SQL + light knowledge (avoid multi-second embed)
        from app.retrieval.hybrid import HybridRetrievalResult
        from app.retrieval.findings_store import sort_by_severity as _sort_sev

        if route.classify_problem_buckets:
            retrieval = HybridRetrievalResult(
                findings=_sort_sev(
                    self.findings_store.search(scan_id=scan_id, severity="HIGH")
                ),
                knowledge_hits=[],
            )
        elif route.top_n:
            pool = self.findings_store.search(scan_id=scan_id, severity="CRITICAL")
            pool = _sort_sev(
                pool
                + [
                    f
                    for f in self.findings_store.search(scan_id=scan_id, severity="HIGH")
                    if f.finding_id not in {x.finding_id for x in pool}
                ]
            )
            retrieval = HybridRetrievalResult(findings=pool, knowledge_hits=[])
        elif route.data_impact:
            retrieval = HybridRetrievalResult(
                findings=_sort_sev(self.findings_store.list_all(scan_id=scan_id)),
                knowledge_hits=[],
            )
        else:
            retrieval = self.retriever.retrieve(
                question=request.question,
                route=route,
                scan_id=scan_id,
                top_k_knowledge=request.top_k_knowledge,
            )

        should_abstain = not retrieval.findings and route.intent in {
            "existence",
            "explain",
            "remediation",
            "compare",
            "list",
            "cross_ref",
            "general",
            "cluster",
        }

        if not retrieval.findings and route.intent in {
            "summary",
            "severity",
            "cluster",
            "general",
        }:
            if self.findings_store.count(scan_id=scan_id) == 0:
                should_abstain = True
            elif route.intent in {"summary", "severity", "cluster"}:
                retrieval.findings = self.findings_store.list_all(scan_id=scan_id)

        if should_abstain and not retrieval.findings:
            gen = abstention_response(request.question, route.intent)
            latency_ms = int((time.perf_counter() - started) * 1000)
            return QueryResponse(
                answer=gen.answer,
                citations=[],
                findings_referenced=[],
                query_intent=route.intent,
                grounded=True,
                abstained=True,
                latency_ms=latency_ms,
                scan_id=scan_id,
                answer_source="abstain",
                model_used=None,
            )

        gen_findings = retrieval.findings
        from app.retrieval.findings_store import sort_by_severity

        q_l = request.question.lower()

        # Classification: full HIGH inventory from store (CWE/severity truth)
        if route.classify_problem_buckets:
            gen_findings = sort_by_severity(
                self.findings_store.search(scan_id=scan_id, severity="HIGH")
            )
            retrieval.findings = gen_findings

        # Priority / go-live: CRITICAL + HIGH pool; template enforces top_n
        if route.top_n:
            by_id = {f.finding_id: f for f in gen_findings}
            for c in self.findings_store.search(scan_id=scan_id, severity="CRITICAL"):
                by_id[c.finding_id] = c
            for h in self.findings_store.search(scan_id=scan_id, severity="HIGH"):
                by_id.setdefault(h.finding_id, h)
            gen_findings = sort_by_severity(list(by_id.values()))
            retrieval.findings = gen_findings

        # PII / financial cross-customer: broad inventory, then impact filter in generator
        if route.data_impact:
            by_id = {f.finding_id: f for f in gen_findings}
            for f in self.findings_store.list_all(scan_id=scan_id):
                by_id.setdefault(f.finding_id, f)
            gen_findings = sort_by_severity(list(by_id.values()))
            retrieval.findings = gen_findings

        if route.data_impact or route.classify_problem_buckets:
            gen_findings = gen_findings[:50]
        elif route.intent in {"explain"} and len(gen_findings) > 3 and not route.top_n:
            gen_findings = gen_findings[:3]
        elif route.intent == "remediation" and route.class_constraints:
            gen_findings = gen_findings[:6]
        elif route.intent == "remediation" and route.top_n:
            # Keep full pool; template picks top_n
            gen_findings = gen_findings[:12]
        elif route.intent == "remediation" and len(gen_findings) > 4:
            gen_findings = gen_findings[:4]
        elif route.intent == "cluster":
            gen_findings = gen_findings[:50]

        gen = self.generator.generate(
            question=request.question,
            intent=route.intent,
            findings=gen_findings,
            knowledge_hits=retrieval.knowledge_hits,
            want_parameter=route.want_parameter,
            want_endpoint=route.want_endpoint,
            top_n=route.top_n,
            classify_problem_buckets=route.classify_problem_buckets,
            data_impact=route.data_impact,
            use_dynamic_synthesis=bool(
                getattr(self.settings, "use_dynamic_synthesis", True)
            ),
        )

        safe_finding_ids = validate_finding_ids(
            gen.findings_referenced, retrieval.findings
        )

        # Template-shaped answers: trust generator's explicit refs (top_n / buckets / PII)
        if (
            route.top_n
            or route.classify_problem_buckets
            or route.data_impact
            or (gen.raw or {}).get("source") == "structured"
        ) and gen.findings_referenced:
            safe_finding_ids = validate_finding_ids(
                gen.findings_referenced, retrieval.findings or gen_findings
            ) or list(gen.findings_referenced)
        elif route.intent in {
            "list",
            "summary",
            "severity",
            "cross_ref",
            "cluster",
        } and retrieval.findings:
            safe_finding_ids = [f.finding_id for f in retrieval.findings]
        elif route.intent == "compare" and retrieval.findings:
            safe_finding_ids = [f.finding_id for f in retrieval.findings[:6]]
        elif route.intent == "existence":
            if gen.abstained or not retrieval.findings:
                safe_finding_ids = []
            elif not safe_finding_ids:
                safe_finding_ids = [f.finding_id for f in retrieval.findings[:3]]
            else:
                safe_finding_ids = safe_finding_ids[:3]
        elif route.intent in {"explain", "remediation"}:
            if route.class_constraints or route.finding_ids:
                safe_finding_ids = [
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
                        safe_finding_ids = validated
            elif safe_finding_ids:
                primary = {f.finding_id for f in retrieval.findings[:3]}
                tight = [fid for fid in safe_finding_ids if fid in primary]
                safe_finding_ids = (tight or safe_finding_ids)[:2]
            elif retrieval.findings:
                safe_finding_ids = [f.finding_id for f in retrieval.findings[:2]]
        elif not safe_finding_ids and retrieval.findings:
            safe_finding_ids = [f.finding_id for f in retrieval.findings[:4]]
        elif safe_finding_ids:
            safe_finding_ids = safe_finding_ids[:6]

        safe_finding_ids = filter_citations_to_answer(
            answer=gen.answer,
            candidate_ids=safe_finding_ids,
            intent=route.intent,
        )

        if route.intent == "existence" and (gen.abstained or not retrieval.findings):
            safe_finding_ids = []
            retrieval.findings = []
            if not gen.abstained:
                gen = abstention_response(request.question, route.intent)

        if gen.findings_referenced and not safe_finding_ids and not retrieval.findings:
            gen = abstention_response(request.question, route.intent)
            safe_finding_ids = []

        # Stage E: dual-stage citation gate
        pool = retrieval.findings or gen_findings
        allowed = {f.finding_id for f in pool}
        gate = gate_citations(
            answer=gen.answer,
            findings_referenced=safe_finding_ids or gen.findings_referenced,
            allowed_ids=allowed,
            fill_refs_if_empty=bool(pool) and not gen.abstained,
            fill_from=safe_finding_ids or [f.finding_id for f in pool[:6]],
        )
        safe_finding_ids = gate.findings_referenced
        final_answer = gate.answer

        citations = build_citations(
            findings=pool,
            finding_ids=safe_finding_ids,
            knowledge_hits=retrieval.knowledge_hits
            if safe_finding_ids or not gen.abstained
            else [],
            reference_ids=gen.reference_ids if not gen.abstained else [],
        )

        answer_source = str(gen.raw.get("source") or "llm") if gen.raw else "llm"
        if gen.abstained and not safe_finding_ids:
            answer_source = "abstain"
        model_used = None
        if answer_source == "llm":
            model_used = getattr(self.llm, "last_model_used", None)

        latency_ms = int((time.perf_counter() - started) * 1000)
        return QueryResponse(
            answer=final_answer,
            citations=citations,
            findings_referenced=safe_finding_ids,
            query_intent=route.intent,
            grounded=True,
            abstained=bool(gen.abstained and not safe_finding_ids),
            latency_ms=latency_ms,
            scan_id=scan_id,
            answer_source=answer_source  # type: ignore[arg-type]
            if answer_source in {"structured", "llm", "template", "abstain"}
            else "llm",
            model_used=model_used,
        )
