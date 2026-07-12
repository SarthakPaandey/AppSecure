"""Tighten compare/explain pools to class-relevant findings only."""

from __future__ import annotations

import re

from app.retrieval.findings_store import FindingRecord, sort_by_severity


def _blob(f: FindingRecord) -> str:
    return " ".join(
        [
            f.title or "",
            f.description or "",
            f.cwe_id or "",
            f.owasp_category or "",
            f.endpoint or "",
            f.remediation_hint or "",
        ]
    ).lower()


def _is_idor_like(f: FindingRecord) -> bool:
    b = _blob(f)
    cwe = (f.cwe_id or "").upper()
    return (
        "CWE-639" in cwe
        or "idor" in b
        or "bola" in b
        or "object level" in b
        or "broken object" in b
        or "insecure direct object" in b
    )


def _is_authn_like(f: FindingRecord) -> bool:
    b = _blob(f)
    cwe = (f.cwe_id or "").upper()
    return any(
        x in cwe for x in ("CWE-287", "CWE-307", "CWE-521", "CWE-798")
    ) or any(
        x in b
        for x in (
            "jwt",
            "password",
            "rate limit",
            "authentication",
            "login",
            "session",
            "credential",
            "hardcoded",
        )
    )


def _is_ssrf_like(f: FindingRecord) -> bool:
    b = _blob(f)
    return "CWE-918" in (f.cwe_id or "").upper() or "ssrf" in b


def _is_sqli_like(f: FindingRecord) -> bool:
    b = _blob(f)
    return "CWE-89" in (f.cwe_id or "").upper() or "sql injection" in b or (
        "sql" in b and "injection" in b
    )


def _is_xss_like(f: FindingRecord) -> bool:
    b = _blob(f)
    return "CWE-79" in (f.cwe_id or "").upper() or "xss" in b or "cross-site scripting" in b


def focus_findings_for_question(
    question: str,
    findings: list[FindingRecord],
    *,
    max_n: int = 4,
) -> list[FindingRecord]:
    """Prefer class-relevant rows for compare/explain templates (no sample packs)."""
    if not findings:
        return []
    q = (question or "").lower()
    ordered = sort_by_severity(list(findings))

    # Explicit IDOR / horizontal access / BOLA compare or explain
    if any(
        x in q
        for x in (
            "idor",
            "bola",
            "object level",
            "object-level",
            "broken access",
            "horizontal privilege",
            "horizontal access",
            "cross-tenant",
            "cross tenant",
            "cross-user",
            "cross user",
            "other tenant",
            "other users",
            "ownership",
        )
    ):
        focused = [f for f in ordered if _is_idor_like(f)]
        if focused:
            return focused[:max_n]

    # Multi-topic auth compare (jwt / password / rate limit)
    named = [t for t in ("jwt", "password", "rate limit", "ssrf", "xss", "sql") if t in q]
    if len(named) >= 2:
        picked: list[FindingRecord] = []
        seen: set[str] = set()
        for f in ordered:
            b = _blob(f)
            for t in named:
                hit = False
                if t == "jwt" and ("jwt" in b or "none" in b and "algorithm" in b):
                    hit = True
                elif t == "password" and "password" in b:
                    hit = True
                elif t == "rate limit" and ("rate" in b or "cwe-307" in b):
                    hit = True
                elif t == "ssrf" and _is_ssrf_like(f):
                    hit = True
                elif t == "xss" and _is_xss_like(f):
                    hit = True
                elif t == "sql" and _is_sqli_like(f):
                    hit = True
                if hit and f.finding_id not in seen:
                    seen.add(f.finding_id)
                    picked.append(f)
                    break
        if len(picked) >= 2:
            return picked[:max_n]

    if "ssrf" in q:
        focused = [f for f in ordered if _is_ssrf_like(f)]
        if focused:
            return focused[: max(1, min(max_n, 2))]

    if "sql injection" in q or re.search(r"\bsqli\b", q):
        focused = [f for f in ordered if _is_sqli_like(f)]
        if focused:
            return focused[: max(1, min(max_n, 2))]

    if "xss" in q or "cross-site scripting" in q:
        focused = [f for f in ordered if _is_xss_like(f)]
        if focused:
            return focused[: max(1, min(max_n, 2))]

    if any(x in q for x in ("authn", "authentication", "login", "jwt", "password", "session")):
        focused = [f for f in ordered if _is_authn_like(f)]
        if focused:
            return focused[:max_n]

    # Default: keep shortlist only
    return ordered[:max_n]
