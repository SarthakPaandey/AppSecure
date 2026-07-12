"""Query orchestration: essay-aligned pipeline.

Flow:
  load scan + catalog
  → parse structure → exact path if confident
  → optional plan → validate/merge → filter or retrieve
  → abstain if unsupported → template or generate → citation gate

Heavy optional paths (tool agent) live in sibling modules so the default
story stays readable.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from sqlalchemy.orm import Session

from app.api.schemas import QueryRequest, QueryResponse
from app.clients.llm import LLMClient
from app.config import Settings
from app.rag.citations import build_citations, gate_citations
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
from app.retrieval.bm25_index import FindingsBM25Index
from app.retrieval.endpoint_utils import resolve_soft_endpoints, unknown_paths_in_question
from app.retrieval.existence_subtype import filter_for_existence_subtype
from app.retrieval.filter_engine import apply_filters, route_to_filter_spec
from app.retrieval.findings_store import FindingsStore, FindingRecord, sort_by_severity
from app.retrieval.hybrid import HybridRetrievalResult, HybridRetriever
from app.retrieval.taxonomy import TOPICS
from app.retrieval.vector_store import VectorStore
from app.services.citation_select import select_citation_ids
from app.services.generation_pool import prepare_generation_pool
from app.services.pipeline_common import (
    abstain_response,
    count_named_topics,
    make_response,
    normalize_answer_source,
)
from app.services.tool_agent_path import try_tool_agent

logger = logging.getLogger(__name__)


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

    # ------------------------------------------------------------------
    # Public entry — essay pipeline (keep short)
    # ------------------------------------------------------------------

    def query(self, request: QueryRequest) -> QueryResponse:
        started = time.perf_counter()
        scan_id = request.scan_id or self.findings_store.latest_scan_id()
        all_findings = self.findings_store.list_all(scan_id=scan_id)
        catalog_endpoints = self.findings_store.distinct_endpoints(scan_id)
        catalog_ids = [f.finding_id for f in all_findings]

        if not all_findings:
            return abstain_response(
                gen=scope_refusal_response(reason="out_of_scope", has_scan_data=False),
                started=started,
                scan_id=scan_id,
                route_intent="general",
            )

        route, plan_meta = self._build_route_and_plan(
            question=request.question,
            catalog_endpoints=catalog_endpoints,
            catalog_ids=catalog_ids,
        )
        if plan_meta.get("refuse"):
            return abstain_response(
                gen=scope_refusal_response(reason="out_of_scope", has_scan_data=True),
                started=started,
                scan_id=scan_id,
                route_intent=route.intent or "general",
                model_used=plan_meta.get("model_used"),
            )

        # Exact structured inventory (0 LLM)
        structured = self._execute_structured_query(
            request=request,
            route=route,
            all_findings=all_findings,
            started=started,
            scan_id=scan_id,
        )
        if structured is not None:
            return structured

        unknown = self._unknown_path_abstain(
            request=request,
            all_findings=all_findings,
            started=started,
            scan_id=scan_id,
        )
        if unknown is not None:
            return unknown

        # Optional tool agent (default off) — isolated module
        agent_resp = try_tool_agent(
            request=request,
            route=route,
            scan_id=scan_id,
            started=started,
            settings=self.settings,
            llm=self.llm,
            findings_store=self.findings_store,
            retriever=self.retriever,
        )
        if agent_resp is not None:
            return agent_resp

        # Soft / semantic → generate + citation gate
        retrieval = self._execute_semantic_query(
            request=request, route=route, scan_id=scan_id
        )
        return self._generate_response(
            request=request,
            route=route,
            retrieval=retrieval,
            scan_id=scan_id,
            started=started,
        )

    # ------------------------------------------------------------------
    # Stage: route + plan
    # ------------------------------------------------------------------

    def _build_route_and_plan(
        self,
        *,
        question: str,
        catalog_endpoints: list[str],
        catalog_ids: list[str],
    ) -> tuple[RouteResult, dict[str, Any]]:
        meta: dict[str, Any] = {"refuse": False, "model_used": None}
        route = rule_based_route(question)

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

        route = apply_catalog_finding_ids(route, catalog_ids, question)

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

        if getattr(self.settings, "use_semantic_planner", True) and not self._rules_confident_for_planner(
            route, question
        ):
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

        route = self._normalize_route_operators(route)
        return route, meta

    @staticmethod
    def _normalize_route_operators(route: RouteResult) -> RouteResult:
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
        return route

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
        if route.intent in {"explain", "remediation", "compare"} and (
            route.cwe_id
            or route.owasp
            or route.finding_ids
            or route.endpoint_strict
            or bool(getattr(route, "topics", None))
            or bool(getattr(route, "class_constraints", None))
        ):
            return True
        if route.intent == "compare" and count_named_topics(question) >= 2:
            return True
        if route.intent == "existence" and any(
            x in question.lower()
            for x in ("rce", "remote code", "xxe", "reverse shell")
        ):
            return True
        return False

    # ------------------------------------------------------------------
    # Stage: structured FilterEngine
    # ------------------------------------------------------------------

    def _execute_structured_query(
        self,
        *,
        request: QueryRequest,
        route: RouteResult,
        all_findings: list[FindingRecord],
        started: float,
        scan_id: str | None,
    ) -> QueryResponse | None:
        """SQLite FilterEngine path. Returns None when soft retrieval is needed."""
        spec = route_to_filter_spec(route)
        precision = self._is_precision_mode(request, route, spec)
        if not precision or route.classify_problem_buckets or route.data_impact:
            return None

        filtered = apply_filters(all_findings, spec)
        # Existence: specific subtype (e.g. command injection) needs direct support
        if route.intent == "existence":
            filtered = filter_for_existence_subtype(request.question, filtered)
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
        abstained = bool(
            gen.abstained or (not filtered and route.intent == "existence")
        )
        return make_response(
            answer=gate.answer,
            citations=citations if not abstained else [],
            findings_referenced=safe_ids if not abstained else [],
            query_intent=route.intent,
            abstained=abstained,
            started=started,
            scan_id=scan_id,
            answer_source="structured" if not abstained else "abstain",
        )

    @staticmethod
    def _is_precision_mode(request: QueryRequest, route: RouteResult, spec: Any) -> bool:
        precision = (
            spec.want_count
            or spec.answer_mode in {"count", "top_n"}
            or bool(spec.exclude_phrases)
            or bool(spec.exclude_topics)
            or bool(spec.exclude_severities)
            or bool(getattr(spec, "path_param_only", False))
            or (bool(spec.include_phrases) and route.intent in {"list", "general"})
            or (bool(spec.include_topics) and route.intent in {"list", "general"})
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
            precision = True
        if (
            route.intent == "existence"
            and spec.include_topics
            and not route.classify_problem_buckets
        ):
            q_text = request.question or ""
            comma_count = q_text.count(",")
            has_or = " or " in q_text.lower()
            multi_absent = comma_count >= 2 or (comma_count >= 1 and has_or)
            if not multi_absent:
                precision = True
        return precision

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
        paths = ", ".join(f"`{p}`" for p in unknown_paths)
        known = sorted({f.endpoint for f in all_findings if f.endpoint})[:6]
        known_txt = ", ".join(f"`{p}`" for p in known) if known else "(none ingested)"
        return make_response(
            answer=(
                f"No findings in this scan reference endpoint path(s) {paths}. "
                "That path does not appear in the ingested findings dataset, so I will not "
                f"invent vulnerabilities for it. Example endpoints from this scan: {known_txt}."
            ),
            query_intent="existence",
            abstained=True,
            started=started,
            scan_id=scan_id,
            answer_source="abstain",
        )

    # ------------------------------------------------------------------
    # Stage: hybrid retrieval
    # ------------------------------------------------------------------

    def _execute_semantic_query(
        self,
        *,
        request: QueryRequest,
        route: RouteResult,
        scan_id: str | None,
    ) -> HybridRetrievalResult:
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

    # ------------------------------------------------------------------
    # Stage: generate + citation gate
    # ------------------------------------------------------------------

    def _generate_response(
        self,
        *,
        request: QueryRequest,
        route: RouteResult,
        retrieval: HybridRetrievalResult,
        scan_id: str | None,
        started: float,
    ) -> QueryResponse:
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
            return abstain_response(
                gen=abstention_response(request.question, route.intent),
                started=started,
                scan_id=scan_id,
                route_intent=route.intent,
            )

        gen_findings = prepare_generation_pool(
            route=route,
            retrieval=retrieval,
            findings_store=self.findings_store,
            scan_id=scan_id,
        )

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

        safe_ids, gen = select_citation_ids(
            question=request.question,
            route=route,
            gen=gen,
            retrieval=retrieval,
            gen_findings=gen_findings,
        )

        pool = retrieval.findings or gen_findings
        allowed = {f.finding_id for f in pool}
        gate = gate_citations(
            answer=gen.answer,
            findings_referenced=safe_ids or gen.findings_referenced,
            allowed_ids=allowed,
            fill_refs_if_empty=bool(pool) and not gen.abstained,
            fill_from=safe_ids or [f.finding_id for f in pool[:6]],
        )
        safe_ids = gate.findings_referenced

        citations = build_citations(
            findings=pool,
            finding_ids=safe_ids,
            knowledge_hits=retrieval.knowledge_hits
            if safe_ids or not gen.abstained
            else [],
            reference_ids=gen.reference_ids if not gen.abstained else [],
        )

        raw_source = str(gen.raw.get("source") or "llm") if gen.raw else "llm"
        if gen.abstained and not safe_ids:
            raw_source = "abstain"
        answer_source = normalize_answer_source(raw_source)
        model_used = (
            getattr(self.llm, "last_model_used", None)
            if answer_source == "llm"
            else None
        )

        return make_response(
            answer=gate.answer,
            citations=citations,
            findings_referenced=safe_ids,
            query_intent=route.intent,
            abstained=bool(gen.abstained and not safe_ids),
            started=started,
            scan_id=scan_id,
            answer_source=answer_source,
            model_used=model_used,
        )

    # Back-compat name used by older tests / callers
    def _build_safe_response(
        self,
        *,
        started: float,
        scan_id: str | None,
        gen: Any,
        route_intent: str = "general",
        model_used: str | None = None,
    ) -> QueryResponse:
        return abstain_response(
            gen=gen,
            started=started,
            scan_id=scan_id,
            route_intent=route_intent,
            model_used=model_used,
        )
