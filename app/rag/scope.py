"""Scan-scope policy: refuse off-topic / empty-context questions cleanly.

This is not full NLU — a lightweight gate so the assistant does not waffle
on weather, jokes, or compliance essays when nothing in the scan applies.
"""

from __future__ import annotations

import re

from app.rag.generator import GenerationResult

# Strong off-topic (chat / world knowledge / non-scan product)
_OFF_TOPIC = re.compile(
    r"\b("
    r"weather|temperature|forecast|"
    r"joke|poem|story|lyrics|recipe|cook|"
    r"president|capital of|who won|sports score|"
    r"stock price|bitcoin|crypto price|"
    r"translate this|write (me )?code for|"
    r"what is love|horoscope|"
    r"movie recommendation|netflix"
    r")\b",
    flags=re.I,
)

# Question is about the scan / AppSec findings (allow through even if soft)
_SCAN_SCOPE = re.compile(
    r"\b("
    r"finding|findings|scan|scanner|vulnerabilit(?:y|ies)|vuln|"
    r"cwe|owasp|severity|critical|high|medium|low|"
    r"endpoint|parameter|remediat|fix|patch|"
    r"idor|bola|ssrf|xss|sqli|sql injection|jwt|rce|xxe|"
    r"authentication|authorization|access control|"
    r"injection|mass assignment|rate limit|password|"
    r"exploit|attacker|risk of|how do i fix|"
    r"compare|summary|inventory|ingest"
    r")\b"
    r"|FINDING-\d+"
    r"|/api/"
    r"|CWE-\d+",
    flags=re.I,
)


def has_scan_scope_signals(question: str, route: object | None = None) -> bool:
    """True if the question looks like scan/AppSec Q&A (or route already structured)."""
    q = question or ""
    if _SCAN_SCOPE.search(q):
        return True
    if route is None:
        return False
    if getattr(route, "finding_ids", None) or getattr(route, "finding_id", None):
        return True
    if getattr(route, "cwe_id", None) or getattr(route, "owasp", None):
        return True
    if getattr(route, "severities", None) or getattr(route, "severity", None):
        return True
    if getattr(route, "endpoint", None) or getattr(route, "endpoint_substrings", None):
        if getattr(route, "endpoint", None) or list(
            getattr(route, "endpoint_substrings", None) or []
        ):
            return True
    if getattr(route, "topics", None):
        return True
    if getattr(route, "want_count", False) or getattr(route, "top_n", None):
        return True
    if getattr(route, "path_param_only", False):
        return True
    if getattr(route, "classify_problem_buckets", False) or getattr(
        route, "data_impact", False
    ):
        return True
    if getattr(route, "class_constraints", None) or getattr(
        route, "include_phrases", None
    ):
        if list(getattr(route, "class_constraints", None) or []) or list(
            getattr(route, "include_phrases", None) or []
        ):
            return True
    # Do NOT treat intent alone as in-scope ("explain the sky" must not pass)
    return False


def is_out_of_scope(question: str, route: object | None = None) -> bool:
    """Refuse chatty / world questions that are not about this scan."""
    q = (question or "").strip()
    if len(q) < 2:
        return True
    if has_scan_scope_signals(q, route):
        return False
    if _OFF_TOPIC.search(q):
        return True
    # No scan vocabulary / structured slots → out of product scope
    return True


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
