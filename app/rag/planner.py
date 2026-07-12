"""Semantic planner: LLM → QueryPlan JSON (rules remain fallback).

Planner runs only for ambiguous questions. It interprets filters/concepts —
it never answers. Explicit structural rule slots always win on merge.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from app.clients.llm import LLMClient, parse_json_response
from app.rag.plan_schema import QueryPlan
from app.rag.prompts import PLANNER_SYSTEM, build_planner_user_prompt

logger = logging.getLogger(__name__)

# High confidence for planner in_scope=false → refuse (conservative)
_IN_SCOPE_REFUSE_CONF = 0.75


@dataclass
class PlanValidationResult:
    """Validated plan ready for merge / orchestrator decisions."""

    plan: QueryPlan | None
    refuse: bool = False  # high-conf out of scope
    fail_open: bool = False  # malformed / low-conf out / error → retrieve
    reason: str = ""


class SemanticPlanner:
    def __init__(
        self,
        llm: LLMClient,
        *,
        confidence_floor: float = 0.35,
        enabled: bool = True,
    ) -> None:
        self.llm = llm
        self.confidence_floor = confidence_floor
        self.enabled = enabled

    def plan(
        self,
        question: str,
        *,
        endpoints: list[str] | None = None,
        topic_names: list[str] | None = None,
        finding_ids: list[str] | None = None,
    ) -> QueryPlan | None:
        if not self.enabled or not hasattr(self.llm, "complete"):
            return None
        user = build_planner_user_prompt(
            question=question,
            endpoints=endpoints or [],
            topic_names=topic_names or [],
            finding_ids=finding_ids or [],
        )
        try:
            raw = self.llm.complete(
                system=PLANNER_SYSTEM,
                user=user,
                temperature=0.0,
                response_json=True,
                max_tokens=800,
            )
            data = parse_json_response(raw)
            if not isinstance(data, dict):
                logger.warning("Planner returned non-object JSON; fail open")
                return None
            plan = QueryPlan.model_validate(data)
            if plan.confidence < self.confidence_floor and not _has_structure(plan):
                logger.info(
                    "Planner low confidence %.2f without structure; fallback",
                    plan.confidence,
                )
                return None
            # Ignore empty soft-only plans that only flip intent to general
            if (
                not _has_structure(plan)
                and plan.intent in {"general", "summary"}
                and not plan.want_count
                and plan.in_scope is True
            ):
                return None
            return plan
        except Exception as exc:  # noqa: BLE001
            logger.warning("Semantic planner failed: %s", exc)
            return None


def decide_planner_scope(plan: QueryPlan | None) -> PlanValidationResult:
    """Apply conservative in_scope policy.

    | Situation                         | Behavior              |
    |-----------------------------------|-----------------------|
    | plan is None (malformed/timeout)  | fail open → retrieve  |
    | in_scope=false, high confidence   | refuse                |
    | in_scope=false, low confidence    | fail open → retrieve  |
    | in_scope=true                     | continue              |
    """
    if plan is None:
        return PlanValidationResult(
            plan=None, fail_open=True, reason="planner_unavailable"
        )
    if plan.in_scope is False:
        if plan.confidence >= _IN_SCOPE_REFUSE_CONF:
            return PlanValidationResult(
                plan=plan, refuse=True, reason="planner_high_conf_out_of_scope"
            )
        return PlanValidationResult(
            plan=plan, fail_open=True, reason="planner_low_conf_out_of_scope"
        )
    return PlanValidationResult(plan=plan, reason="in_scope")


def validate_plan_against_catalog(
    plan: QueryPlan,
    *,
    endpoints: list[str] | None = None,
    finding_ids: list[str] | None = None,
    severities: list[str] | None = None,
) -> QueryPlan:
    """Drop planner slots that cannot exist in the scan catalog.

    Explicit rules still override later on merge; this only sanitizes the plan.
    Fake endpoints/IDs are removed so the planner cannot invent store rows.
    """
    catalog_eps = list(endpoints or [])
    catalog_fids = {f.upper(): f for f in (finding_ids or [])}
    allowed_sevs = {
        s.upper()
        for s in (severities or ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    }

    # Finding IDs: keep only those in catalog (case-insensitive)
    if plan.finding_ids:
        kept: list[str] = []
        for fid in plan.finding_ids:
            key = fid.upper()
            if key in catalog_fids:
                kept.append(catalog_fids[key])
            elif catalog_fids:
                logger.info("Dropping planner finding_id not in catalog: %s", fid)
            else:
                # No catalog loaded — keep as-is (caller should pass catalog)
                kept.append(fid)
        plan.finding_ids = kept

    # Endpoints: resolve against catalog; drop pure inventions when catalog known
    if plan.endpoint_substrings and catalog_eps:
        resolved = resolve_endpoints_against_catalog(
            plan.endpoint_substrings, catalog_eps
        )
        # If a substring matches nothing in catalog (no path hit), drop it
        cat_blob = " ".join(catalog_eps).lower()
        cleaned: list[str] = []
        for sub in resolved:
            s = (sub or "").lower()
            if not s:
                continue
            if s in cat_blob or any(
                s in c.lower() or all(t in c.lower() for t in s.split() if len(t) > 2)
                for c in catalog_eps
            ):
                cleaned.append(sub)
            else:
                logger.info("Dropping planner endpoint not in catalog: %s", sub)
        plan.endpoint_substrings = cleaned

    if plan.include_severities:
        plan.include_severities = [
            s for s in plan.include_severities if s.upper() in allowed_sevs
        ]
    if plan.exclude_severities:
        plan.exclude_severities = [
            s for s in plan.exclude_severities if s.upper() in allowed_sevs
        ]

    return plan


def _has_structure(plan: QueryPlan) -> bool:
    return bool(
        plan.include_severities
        or plan.cwe_ids
        or plan.endpoint_substrings
        or plan.include_topics
        or plan.exclude_topics
        or plan.finding_ids
        or plan.want_count
        or plan.top_n
        or plan.include_phrases
        or plan.exclude_phrases
        or plan.in_scope is False  # out-of-scope signal is structural for policy
    )


def merge_plan_into_route(rules: Any, plan: QueryPlan | None) -> Any:
    """Merge LLM plan into rule-based RouteResult (rules win on hard structure).

    Mutates and returns ``rules`` RouteResult for convenience.
    """
    if plan is None:
        return rules

    q_struct = bool(
        rules.cwe_id
        or rules.finding_ids
        or rules.endpoint
        or (rules.severities and rules.want_count)
    )

    # Intent: prefer LLM for soft; keep rules for count/top_n/cluster/classify
    if rules.want_count or rules.answer_mode in {"count", "top_n"}:
        pass  # keep rule intent
    elif rules.classify_problem_buckets or rules.intent == "cluster":
        pass
    elif plan.intent:
        # Only override general/list when LLM is more specific
        if rules.intent in {"general", "list"} or plan.intent in {
            "explain",
            "remediation",
            "compare",
            "existence",
            "summary",
        }:
            rules.intent = plan.intent

    if plan.answer_mode and not rules.answer_mode:
        rules.answer_mode = plan.answer_mode
    if plan.want_count:
        rules.want_count = True
        rules.answer_mode = "count"
    if plan.top_n:
        rules.top_n = plan.top_n if not rules.top_n else max(rules.top_n, plan.top_n)
        if not rules.answer_mode:
            rules.answer_mode = "top_n"

    # Severities: rules win if already set from explicit words; else take LLM
    if not rules.severities and plan.include_severities:
        rules.severities = list(plan.include_severities)
        rules.severity = rules.severities[0]
    if plan.exclude_severities:
        rules.exclude_severities = list(
            dict.fromkeys([*rules.exclude_severities, *plan.exclude_severities])
        )

    # CWE: explicit rule CWE wins
    if not rules.cwe_id and plan.cwe_ids:
        rules.cwe_id = plan.cwe_ids[0]
    if not rules.owasp and plan.owasp:
        rules.owasp = plan.owasp

    # Endpoints: union + catalog phrases
    if plan.endpoint_substrings:
        rules.endpoint_substrings = list(
            dict.fromkeys([*rules.endpoint_substrings, *plan.endpoint_substrings])
        )
        if plan.endpoint_strict or not rules.endpoint:
            # soft endpoint from LLM
            if not rules.endpoint and plan.endpoint_substrings:
                rules.endpoint = plan.endpoint_substrings[0]
        rules.endpoint_strict = rules.endpoint_strict or plan.endpoint_strict

    # Topics / phrases
    if plan.include_topics:
        rules.topics = list(dict.fromkeys([*getattr(rules, "topics", []), *plan.include_topics]))
    if plan.exclude_topics:
        rules.exclude_topics = list(
            dict.fromkeys(
                [*getattr(rules, "exclude_topics", []), *plan.exclude_topics]
            )
        )
    if plan.include_phrases:
        rules.include_phrases = list(
            dict.fromkeys([*rules.include_phrases, *plan.include_phrases])
        )
    if plan.exclude_phrases:
        rules.exclude_phrases = list(
            dict.fromkeys([*rules.exclude_phrases, *plan.exclude_phrases])
        )

    if plan.finding_ids and not rules.finding_ids:
        rules.finding_ids = list(plan.finding_ids)
        rules.finding_id = rules.finding_ids[0]

    rules.want_parameter = rules.want_parameter or plan.want_parameter
    rules.want_endpoint = rules.want_endpoint or plan.want_endpoint

    # Soft confidence: if LLM very low and no structure, leave rules as-is
    _ = q_struct
    return rules


def resolve_endpoints_against_catalog(
    substrings: list[str],
    catalog: list[str],
) -> list[str]:
    """Map loose endpoint phrases to scan catalog paths (no hardcoded sample paths)."""
    if not substrings or not catalog:
        return list(substrings)
    resolved: list[str] = []
    cat_l = [(c, c.lower()) for c in catalog]
    for sub in substrings:
        s = (sub or "").lower().strip()
        if not s:
            continue
        # Already a path fragment
        hits = [c for c, cl in cat_l if s in cl or all(t in cl for t in s.split() if len(t) > 2)]
        if len(hits) == 1:
            # use path only
            path = hits[0].split()[-1] if " " in hits[0] else hits[0]
            resolved.append(path)
        elif hits:
            # multiple: keep original soft phrase
            resolved.append(sub)
        else:
            resolved.append(sub)
    return list(dict.fromkeys(resolved))


def extract_catalog_finding_ids(
    question: str,
    catalog_ids: list[str],
) -> list[str]:
    """Match finding IDs mentioned in the question against the loaded scan catalog.

    Supports arbitrary catalog IDs (``FINDING-001``, ``SHIP-AUTH-01``,
    ``web:xss:44``, ``VULN_2026_91``) — not only ``FINDING-\\d+``.
    Longer IDs are preferred to avoid partial collisions.
    """
    if not question or not catalog_ids:
        return []
    q = question
    # Prefer longer IDs first so SHIP-AUTH-01 beats AUTH-01 if both existed
    ordered = sorted(set(catalog_ids), key=lambda x: (-len(x), x.upper()))
    found: list[str] = []
    found_upper: set[str] = set()
    for fid in ordered:
        if not fid:
            continue
        # Word-boundary-ish match; allow : _ - inside IDs
        pattern = re.compile(
            r"(?<![A-Za-z0-9])" + re.escape(fid) + r"(?![A-Za-z0-9])",
            flags=re.I,
        )
        if pattern.search(q) and fid.upper() not in found_upper:
            found.append(fid)
            found_upper.add(fid.upper())
    # Also catch classic FINDING-N even if not yet in catalog (unknown → empty filter later)
    for m in re.finditer(r"FINDING-\d+", question, flags=re.I):
        token = m.group(0).upper()
        if token not in found_upper:
            # Prefer catalog casing when present
            canon = next((c for c in catalog_ids if c.upper() == token), token)
            found.append(canon)
            found_upper.add(token)
    return found


def apply_catalog_finding_ids(route: Any, catalog_ids: list[str], question: str) -> Any:
    """Attach catalog-matched finding IDs onto a RouteResult (rules path)."""
    matched = extract_catalog_finding_ids(question, catalog_ids)
    if not matched:
        return route
    existing = list(getattr(route, "finding_ids", None) or [])
    existing_u = {x.upper() for x in existing}
    for fid in matched:
        if fid.upper() not in existing_u:
            existing.append(fid)
            existing_u.add(fid.upper())
    route.finding_ids = existing
    if not getattr(route, "finding_id", None) and existing:
        route.finding_id = existing[0]
    return route
