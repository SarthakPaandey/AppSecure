"""Query orchestration: essay-aligned pipeline (helpers, not a rewrite).

Flow:
  load scan + catalog
  → parse structure → exact path if confident
  → optional plan → validate/merge → filter or retrieve
  → abstain if unsupported → template or generate → citation gate
"""

from __future__ import annotations

import logging
import time
from typing import Any, Literal, cast

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
    apply_catalog_finding_ids,
    decide_planner_scope,
    extract_catalog_finding_ids,
    merge_plan_into_route,
    resolve_endpoints_against_catalog,
    validate_plan_against_catalog,
)
from app.rag.router import QueryRouter, RouteResult, rule_based_route
from app.rag.scope import decide_scope, scope_refusal_response
from app.rag.tool_agent import FindingsToolAgent
from app.rag.tools import FindingsToolExecutor
from app.retrieval.bm25_index import FindingsBM25Index
from app.retrieval.endpoint_utils import resolve_soft_endpoints, unknown_paths_in_question
from app.retrieval.filter_engine import apply_filters, route_to_filter_spec
from app.retrieval.findings_store import FindingsStore, FindingRecord, sort_by_severity
from app.retrieval.hybrid import HybridRetrievalResult, HybridRetriever
from app.retrieval.taxonomy import TOPICS
from app.retrieval.vector_store import VectorStore

logger = logging.getLogger(__name__)

# Intents answered via SQL / structured templates (no tool agent required)
STRUCTURED_INTENTS = frozenset(
    {"list", "summary", "severity", "cross_ref", "existence", "cluster"}
)
# Synthesis intents prefer tool-calling agent when enabled
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
        catalog_endpoints = self.findings_store.distinct_endpoints(scan_id)
        catalog_ids = [f.finding_id for f in all_findings]

        if not all_findings:
            return self._build_safe_response(
                started=started,
                scan_id=scan_id,
                gen=scope_refusal_response(reason="out_of_scope", has_scan_data=False),
                route_intent="general",
                model_used=None,
            )

        route, plan_meta = self._build_route_and_plan(
            question=request.question,
            scan_id=scan_id,
            catalog_endpoints=catalog_endpoints,
            catalog_ids=catalog_ids,
        )

        # Deterministic refuse (obvious junk or high-conf planner out-of-scope)
        if plan_meta.get("refuse"):
            return self._build_safe_response(
                started=started,
                scan_id=scan_id,
                gen=scope_refusal_response(reason="out_of_scope", has_scan_data=True),
                route_intent=route.intent or "general",
                model_used=plan_meta.get("model_used"),
            )

        # --- Exact structured path (0 LLM for inventory) ---
        structured = self._execute_structured_query(
            request=request,
            route=route,
            all_findings=all_findings,
            started=started,
            scan_id=scan_id,
        )
        if structured is not None:
            return structured

        # Unknown path existence → grounded abstain
        unknown = self._unknown_path_abstain(
            request=request,
            all_findings=all_findings,
            started=started,
            scan_id=scan_id,
        )
        if unknown is not None:
            return unknown

        # Optional tool agent (default off) → hybrid fallback
        agent_resp = self._try_tool_agent(
            request=request,
            route=route,
            scan_id=scan_id,
            started=started,
        )
        if agent_resp is not None:
            return agent_resp

        # --- Soft / semantic path ---
        retrieval = self._execute_semantic_query(
            request=request,
            route=route,
            scan_id=scan_id,
        )
        return self._generate_response(
            request=request,
            route=route,
            retrieval=retrieval,
            scan_id=scan_id,
            started=started,
        )

    # ------------------------------------------------------------------
    # Helpers (visible pipeline stages)
    # ------------------------------------------------------------------

    def _build_route_and_plan(
        self,
        *,
        question: str,
        scan_id: str | None,
        catalog_endpoints: list[str],
        catalog_ids: list[str],
    ) -> tuple[RouteResult, dict[str, Any]]:
        """Parse structure, optional semantic plan, validate/merge (rules win)."""
        meta: dict[str, Any] = {"refuse": False, "model_used": None}

        route = rule_based_route(question)

        # Soft NL endpoint cues → live catalog paths
        soft_eps = resolve_soft_endpoints(question, catalog_endpoints)
        if soft_eps:
            route.endpoint_substrings = list(
                dict.fromkeys([*route.endpoint_substrings, *soft_eps])
            )
            if not route.endpoint and len(soft_eps) == 1 and soft_eps[0].startswith("/"):
                route.endpoint = soft_eps[0]
                route.endpoint_strict = True
            elif soft_eps and not route.endpoint_strict:
                if any(e.startswith("/") for e in soft_eps):
                    route.endpoint_strict = True

        # Catalog-aware finding IDs (SHIP-AUTH-01, web:xss:44, …)
        route = apply_catalog_finding_ids(route, catalog_ids, question)

        # Scope: structural + obvious junk; dedicated scope LLM only if enabled
        scope = decide_scope(
            question,
            route,
            llm=self.llm,
            endpoints=catalog_endpoints,
            use_llm=bool(getattr(self.settings, "use_llm_scope_gate", False)),
        )
        meta["model_used"] = scope.model_used
        if not scope.related:
            meta["refuse"] = True
            meta["refuse_reason"] = scope.reason
            return route, meta

        rules_confident = self._rules_confident_for_planner(route, question)
        if getattr(self.settings, "use_semantic_planner", True) and not rules_confident:
            plan = self.planner.plan(
                question,
                endpoints=catalog_endpoints,
                topic_names=list(TOPICS.keys()),
                finding_ids=catalog_ids,
            )
            decision = decide_planner_scope(plan)
            if decision.refuse:
                meta["refuse"] = True
                meta["refuse_reason"] = decision.reason
                return route, meta
            if plan is not None and not decision.fail_open:
                plan = validate_plan_against_catalog(
                    plan,
                    endpoints=catalog_endpoints,
                    finding_ids=catalog_ids,
                )
                if plan.endpoint_substrings:
                    plan.endpoint_substrings = resolve_endpoints_against_catalog(
                        plan.endpoint_substrings, catalog_endpoints
                    )
                route = merge_plan_into_route(route, plan)
                # Planner must not invent finding IDs the user never typed
                if route.finding_ids:
                    mentioned = extract_catalog_finding_ids(question, catalog_ids)
                    mentioned_u = {m.upper() for m in mentioned}
                    route.finding_ids = [
                        f for f in route.finding_ids if f.upper() in mentioned_u
                    ]
                    route.finding_id = (
                        route.finding_ids[0] if route.finding_ids else None
                    )
                logger.info(
                    "Semantic plan intent=%s mode=%s conf=%.2f in_scope=%s topics=%s",
                    plan.intent,
                    plan.answer_mode,
                    plan.confidence,
                    plan.in_scope,
                    plan.include_topics,
                )
            # fail_open / None plan → continue with rules as-is

        # Normalize operators after merge
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

        return route, meta

    @staticmethod
    def _rules_confident_for_planner(route: RouteResult, question: str) -> bool:
        """True when structural rules are enough — skip semantic planner."""
        if (
            route.want_count
            or route.answer_mode in {"count", "top_n"}
            or route.cwe_id
            or route.finding_ids
            or route.classify_problem_buckets
            or getattr(route, "path_param_only", False)
        ):
            return True
        # A clearly identified finding class, CWE/OWASP, or catalog endpoint is
        # enough for narrative synthesis too: retrieve and call the generator
        # directly rather than spending a planner call reinterpreting it.
        if route.intent in {"explain", "remediation", "compare"} and (
            route.cwe_id
            or route.owasp
            or route.finding_ids
            or route.endpoint_strict
            or bool(getattr(route, "topics", None))
            or bool(getattr(route, "class_constraints", None))
        ):
            return True
        # Multi-topic compare is clause-union retrieval — planner inventing IDs hurts
        if route.intent == "compare":
            ql = (question or "").lower()
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
                if t in ql
            )
            if named >= 2:
                return True
        if route.intent == "existence" and any(
            x in question.lower()
            for x in ("rce", "remote code", "xxe", "reverse shell")
        ):
            return True
        return False

    def _execute_structured_query(
        self,
        *,
        request: QueryRequest,
        route: RouteResult,
        all_findings: list[FindingRecord],
        started: float,
        scan_id: str | None,
    ) -> QueryResponse | None:
        """SQLite FilterEngine path for exact inventory operators. Returns None if soft."""
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
            or bool(spec.finding_ids)
        )
        if route.intent == "existence" and (
            spec.include_severities
            or spec.cwe_ids
            or spec.endpoint_substrings
            or spec.finding_ids
        ):
            precision_mode = True

        if route.intent == "existence" and spec.include_topics and not route.classify_problem_buckets:
            q_text = request.question or ""
            comma_count = q_text.count(",")
            has_or = " or " in q_text.lower()
            multi_absent = comma_count >= 2 or (comma_count >= 1 and has_or)
            if not multi_absent:
                precision_mode = True

        if not precision_mode or route.classify_problem_buckets or route.data_impact:
            return None

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

    def _unknown_path_abstain(
        self,
        *,
        request: QueryRequest,
        all_findings: list[FindingRecord],
        started: float,
        scan_id: str | None,
    ) -> QueryResponse | None:
        unknown_paths = unknown_paths_in_question(request.question, all_findings)
        if not unknown_paths:
            return None
        if not any(
            x in request.question.lower()
            for x in ("vulnerable", "idor", "finding", "issue", "broken", "on ")
        ):
            return None
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

    def _try_tool_agent(
        self,
        *,
        request: QueryRequest,
        route: RouteResult,
        scan_id: str | None,
        started: float,
    ) -> QueryResponse | None:
        """Optional multi-round tool agent (default off). Returns None to use hybrid."""
        skip_agent = bool(
            route.classify_problem_buckets
            or route.top_n
            or route.data_impact
            or route.want_count
            or route.intent in STRUCTURED_INTENTS
            or bool(getattr(route, "exclude_phrases", None))
        )
        use_agent = (
            bool(getattr(self.settings, "use_tool_agent", False))
            and (route.intent in SYNTHESIS_INTENTS)
            and not skip_agent
        )
        if not use_agent:
            return None

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
            if not agent_findings and (
                gen.abstained or not (gen.answer or "").strip()
            ):
                raise RuntimeError("tool agent returned no findings; use hybrid")

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
                    ans = gen.answer or ""
                    if crit_ids and not any(cid in ans for cid in crit_ids):
                        raise RuntimeError(
                            "tool agent priority answer omitted CRITICAL; use hybrid"
                        )

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
                if named >= 2 and len(agent_findings) >= 2:
                    gen.findings_referenced = [
                        f.finding_id for f in agent_findings[:8]
                    ]

            if route.class_constraints and agent_findings:
                class_hits = self.retriever._filter_by_class_constraints(
                    agent_findings, list(route.class_constraints)
                )
                if not class_hits:
                    raise RuntimeError(
                        "tool agent findings miss class constraints; use hybrid"
                    )
                agent_findings = class_hits
                allowed_class = {f.finding_id for f in agent_findings}
                gen.findings_referenced = [
                    r for r in gen.findings_referenced if r in allowed_class
                ] or [f.finding_id for f in agent_findings[:6]]
            elif route.class_constraints and not agent_findings:
                raise RuntimeError(
                    "tool agent empty under class constraints; use hybrid"
                )

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
            logger.warning(
                "Tool agent failed; falling back to hybrid path",
                extra={
                    "question": request.question,
                    "intent": route.intent,
                    "fallback_reason": str(exc),
                },
            )
            return None

    def _execute_semantic_query(
        self,
        *,
        request: QueryRequest,
        route: RouteResult,
        scan_id: str | None,
    ) -> HybridRetrievalResult:
        """BM25 ∪ dense → RRF (CE off by default); scan membership via store filters."""
        if route.classify_problem_buckets:
            return HybridRetrievalResult(
                findings=sort_by_severity(
                    self.findings_store.search(scan_id=scan_id, severity="HIGH")
                ),
                knowledge_hits=[],
            )
        if route.top_n:
            pool = self.findings_store.search(scan_id=scan_id, severity="CRITICAL")
            pool = sort_by_severity(
                pool
                + [
                    f
                    for f in self.findings_store.search(
                        scan_id=scan_id, severity="HIGH"
                    )
                    if f.finding_id not in {x.finding_id for x in pool}
                ]
            )
            return HybridRetrievalResult(findings=pool, knowledge_hits=[])
        if route.data_impact:
            return HybridRetrievalResult(
                findings=sort_by_severity(
                    self.findings_store.list_all(scan_id=scan_id)
                ),
                knowledge_hits=[],
            )
        return self.retriever.retrieve(
            question=request.question,
            route=route,
            scan_id=scan_id,
            top_k_knowledge=request.top_k_knowledge,
        )

    def _generate_response(
        self,
        *,
        request: QueryRequest,
        route: RouteResult,
        retrieval: HybridRetrievalResult,
        scan_id: str | None,
        started: float,
    ) -> QueryResponse:
        """Inventory template or grounded generator + citation gate."""
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
            return self._build_safe_response(
                started=started,
                scan_id=scan_id,
                gen=gen,
                route_intent=route.intent,
            )

        gen_findings = retrieval.findings

        if route.classify_problem_buckets:
            gen_findings = sort_by_severity(
                self.findings_store.search(scan_id=scan_id, severity="HIGH")
            )
            retrieval.findings = gen_findings

        if route.top_n:
            by_id = {f.finding_id: f for f in gen_findings}
            for c in self.findings_store.search(scan_id=scan_id, severity="CRITICAL"):
                by_id[c.finding_id] = c
            for h in self.findings_store.search(scan_id=scan_id, severity="HIGH"):
                by_id.setdefault(h.finding_id, h)
            gen_findings = sort_by_severity(list(by_id.values()))
            retrieval.findings = gen_findings

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

        # Multi-topic compare: keep the retrieval union even if the LLM under-cites
        if route.intent == "compare" and retrieval.findings:
            ql = request.question.lower()
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
                if t in ql
            )
            if named >= 2:
                pool_ids = [f.finding_id for f in retrieval.findings[:6]]
                if len(pool_ids) > len(safe_finding_ids):
                    safe_finding_ids = pool_ids

        if route.intent == "existence" and (gen.abstained or not retrieval.findings):
            safe_finding_ids = []
            retrieval.findings = []
            if not gen.abstained:
                gen = abstention_response(request.question, route.intent)

        if gen.findings_referenced and not safe_finding_ids and not retrieval.findings:
            gen = abstention_response(request.question, route.intent)
            safe_finding_ids = []

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

        raw_answer_source = str(gen.raw.get("source") or "llm") if gen.raw else "llm"
        if gen.abstained and not safe_finding_ids:
            raw_answer_source = "abstain"
        answer_source = cast(
            Literal["structured", "llm", "template", "abstain"],
            raw_answer_source
            if raw_answer_source in {"structured", "llm", "template", "abstain"}
            else "llm",
        )
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
            answer_source=answer_source,
            model_used=model_used,
        )

    def _build_safe_response(
        self,
        *,
        started: float,
        scan_id: str | None,
        gen: Any,
        route_intent: str = "general",
        model_used: str | None = None,
    ) -> QueryResponse:
        """Fixed refusal / empty-store / abstain envelope."""
        latency_ms = int((time.perf_counter() - started) * 1000)
        return QueryResponse(
            answer=gen.answer,
            citations=[],
            findings_referenced=[],
            query_intent=route_intent,
            grounded=True,
            abstained=True,
            latency_ms=latency_ms,
            scan_id=scan_id,
            answer_source="abstain",
            model_used=model_used,
        )
