"""Scan-scope policy: is this question about the ingested findings?

Primary decision uses the chat LLM (e.g. Cerebras Gemma 4) so soft phrasing
is not limited to a keyword list. Cheap rule short-circuits avoid an extra
LLM call when the question is obviously structural (CWE, severity, FINDING-id)
or when the store is empty.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from app.clients.llm import LLMClient, parse_json_response
from app.rag.generator import GenerationResult

logger = logging.getLogger(__name__)

SCOPE_SYSTEM = """You are a scope gate for a PTaaS security-scan Q&A assistant.
Decide if the user question is ABOUT the application's security scan findings
(vulnerabilities, severities, endpoints, CWEs, remediations, comparisons of findings)
or is OFF-TOPIC (weather, jokes, general knowledge, pure business/legal chat with no scan link).

Return ONLY JSON:
{"related": true|false, "confidence": 0.0-1.0, "reason": "short"}

related=true examples:
- list/filter findings by severity or class
- explain/fix a vuln, IDOR, SQLi, SSRF, JWT, auth issues
- existence of a vulnerability type in the scan
- questions about endpoints/parameters from an API security scan
- soft AppSec phrasing about the scan ("other users' data", "can someone take over accounts")

related=false examples:
- weather, sports, recipes, jokes, poems
- "who is the president", stock prices
- pure compliance essays with no link to scan findings (e.g. only "are we SOC2 certified?" with no finding context)
- empty/random chit-chat

When unsure but the question could be about security findings in a scan, prefer related=true.
Only output valid JSON."""


@dataclass
class ScopeDecision:
    related: bool
    source: str  # rules_in | rules_out | llm | fallback
    confidence: float = 1.0
    reason: str = ""
    model_used: str | None = None


# Obvious chat junk — skip LLM (latency). Soft AppSec never relies on this alone.
_OBVIOUS_OFF_TOPIC = re.compile(
    r"\b("
    r"weather|temperature|forecast|joke|poem|lyrics|recipe|"
    r"president of|capital of|horoscope|netflix|bitcoin price"
    r")\b",
    flags=re.I,
)


def has_structural_scan_slots(route: object | None) -> bool:
    """Hard operators that only make sense for scan Q&A — no LLM needed."""
    if route is None:
        return False
    if getattr(route, "finding_ids", None) or getattr(route, "finding_id", None):
        return True
    if getattr(route, "cwe_id", None) or getattr(route, "owasp", None):
        return True
    if getattr(route, "severities", None) or getattr(route, "severity", None):
        return True
    if getattr(route, "want_count", False) or getattr(route, "top_n", None):
        return True
    if getattr(route, "path_param_only", False):
        return True
    if getattr(route, "classify_problem_buckets", False):
        return True
    if getattr(route, "endpoint", None):
        return True
    eps = list(getattr(route, "endpoint_substrings", None) or [])
    if any(str(e).startswith("/") for e in eps):
        return True
    return False


def _obvious_off_topic(question: str) -> bool:
    q = (question or "").strip()
    if len(q) < 2:
        return True
    return bool(_OBVIOUS_OFF_TOPIC.search(q))


def classify_scope_with_llm(
    llm: LLMClient,
    question: str,
    *,
    endpoints: list[str] | None = None,
) -> ScopeDecision:
    """Ask the chat model (Gemma 4 etc.) if the question is scan-related."""
    ep = "\n".join(f"- {e}" for e in (endpoints or [])[:25]) or "(none loaded)"
    user = f"""Question:
{question}

Sample endpoints currently in the scan catalog (context only):
{ep}

Is this question related to answering over this security scan? JSON only."""
    try:
        raw = llm.complete(
            system=SCOPE_SYSTEM,
            user=user,
            temperature=0.0,
            response_json=True,
            max_tokens=80,
        )
        data = parse_json_response(raw) or {}
        related = bool(data.get("related", False))
        conf = float(data.get("confidence") or 0.5)
        reason = str(data.get("reason") or "")[:200]
        model = getattr(llm, "last_model_used", None)
        logger.info(
            "LLM scope gate related=%s conf=%.2f model=%s reason=%s",
            related,
            conf,
            model,
            reason,
        )
        return ScopeDecision(
            related=related,
            source="llm",
            confidence=conf,
            reason=reason,
            model_used=str(model) if model else None,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM scope gate failed: %s", exc)
        return ScopeDecision(
            related=True,  # fail open for scan product — better weak answer than false refuse
            source="fallback",
            confidence=0.0,
            reason=f"llm_error:{type(exc).__name__}",
        )


def decide_scope(
    question: str,
    route: object | None = None,
    *,
    llm: LLMClient | None = None,
    endpoints: list[str] | None = None,
    use_llm: bool = True,
) -> ScopeDecision:
    """Decide if the question is in product scope.

    Order:
    1. Structural route slots → related (no LLM)
    2. Obvious off-topic regex → not related (no LLM)
    3. Gemma/LLM JSON related yes/no when enabled
    4. Fail-open related=true if LLM disabled/unavailable after soft path
    """
    q = (question or "").strip()
    if len(q) < 2:
        return ScopeDecision(
            related=False, source="rules_out", reason="empty_question"
        )

    if has_structural_scan_slots(route):
        return ScopeDecision(
            related=True,
            source="rules_in",
            reason="structural_slots",
        )

    if _obvious_off_topic(q):
        return ScopeDecision(
            related=False,
            source="rules_out",
            reason="obvious_off_topic",
        )

    if use_llm and llm is not None:
        return classify_scope_with_llm(llm, q, endpoints=endpoints)

    # LLM gate off (default): only structural + obvious-junk rules apply.
    # Fail open so soft AppSec questions reach planner/retrieval; unsupported
    # claims abstain later. Planner high-conf in_scope=false can still refuse.
    if _legacy_keyword_related(q, route):
        return ScopeDecision(
            related=True,
            source="fallback",
            reason="llm_gate_disabled_keyword",
        )
    return ScopeDecision(
        related=True,
        source="fallback",
        reason="llm_gate_disabled_fail_open",
    )


def _legacy_keyword_related(question: str, route: object | None) -> bool:
    """Used only when USE_LLM_SCOPE_GATE=false."""
    if re.search(
        r"\b(finding|vulnerabilit|cwe|owasp|severity|critical|endpoint|"
        r"idor|ssrf|xss|sqli|jwt|rce|remediat|exploit)\b|/api/|FINDING-\d+",
        question or "",
        flags=re.I,
    ):
        return True
    if route is not None and (
        getattr(route, "topics", None)
        or getattr(route, "class_constraints", None)
        or getattr(route, "include_phrases", None)
    ):
        return bool(
            list(getattr(route, "topics", None) or [])
            or list(getattr(route, "class_constraints", None) or [])
            or list(getattr(route, "include_phrases", None) or [])
        )
    return False


# --- Back-compat helpers used by tests / abstention ---


def has_scan_scope_signals(question: str, route: object | None = None) -> bool:
    return decide_scope(question, route, llm=None, use_llm=False).related


def is_out_of_scope(question: str, route: object | None = None) -> bool:
    """Keyword-only (no LLM). Prefer decide_scope(..., llm=...) in production path."""
    return not decide_scope(question, route, llm=None, use_llm=False).related


def scope_refusal_response(
    *,
    reason: str = "out_of_scope",
    has_scan_data: bool = True,
) -> GenerationResult:
    """Fixed refusal — clear product boundary, no invented findings."""
    if not has_scan_data:
        answer = (
            "No scan findings are currently ingested. "
            "Call **POST /ingest** with a scan payload first, then ask about "
            "that scan (list, explain, remediate, or existence questions)."
        )
    elif reason == "no_match":
        answer = (
            "No matching findings were found in the ingested scan for this question. "
            "I only answer from **ingested scan findings** (and related AppSec knowledge). "
            "I will not invent vulnerabilities, endpoints, or finding IDs. "
            "Try a more specific question about severity, CWE, endpoint, or a finding ID."
        )
    else:
        answer = (
            "I only answer questions about the **ingested security scan findings** "
            "(list/filter, explain, remediate, compare, or existence checks). "
            "This question is outside that scope, so I will not invent an answer. "
            "Ask about findings in this scan — for example severity, a vulnerability class "
            "(IDOR, SSRF, SQLi), an endpoint, or how to fix a specific finding."
        )
    return GenerationResult(
        answer=answer,
        findings_referenced=[],
        reference_ids=[],
        abstained=True,
        raw={"source": "abstain", "scope_reason": reason},
    )
