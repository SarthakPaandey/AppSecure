"""Endpoint extraction and scan membership checks."""

from __future__ import annotations

import re

from app.retrieval.findings_store import FindingRecord

# Explicit API/static/graphql path fragments in free text
_PATH_RE = re.compile(r"(/(?:api|static|graphql)[a-zA-Z0-9_/{}.-]*)")

# Soft NL cues that often refer to a resource surface (not vulnerability jargon)
_SOFT_ENDPOINT_CUES = re.compile(
    r"\b([a-z][a-z0-9_-]{2,})\s+endpoint\b|"
    r"\bendpoints?\s+(?:related\s+to\s+|on\s+|for\s+)?([a-z][a-z0-9_/-]{2,})\b|"
    r"\bon\s+the\s+([a-z][a-z0-9_-]{2,})\s+(?:endpoint|page|api|route)\b|"
    r"\b(?:the\s+)?([a-z][a-z0-9_-]{2,})\s+(?:page|api|route)\b|"
    r"\brelated\s+to\s+(?:the\s+)?([a-z][a-z0-9_-]{2,})\s+endpoint\b",
    flags=re.I,
)

_SOFT_STOP = frozenset(
    {
        "the",
        "any",
        "this",
        "that",
        "which",
        "what",
        "exact",
        "full",
        "api",
        "all",
        "each",
        "every",
        "same",
        "other",
        "related",
        "affected",
        "vulnerable",
        "finding",
        "findings",
        "not",
        "auth",
        "security",
        "issue",
        "issues",
        "problem",
        "problems",
        "scan",
        "user",
        "users",
        # vuln jargon — not path tokens
        "login",  # often "login rate limiting"; require "login endpoint/page" via other groups
        "password",
        "rate",
        "jwt",
        "token",
        "idor",
        "ssrf",
        "sql",
        "xss",
        "permit",
        "permits",
        "allow",
        "allows",
        "have",
        "has",
        "support",
        "expose",
        "exposes",
    }
)

# Soft resource token only when explicitly endpoint-shaped ("X endpoint/page/route")
_ENDPOINT_SHAPED = re.compile(
    r"\b([a-z][a-z0-9_-]{2,})\s+(?:endpoint|page|route|api)\b|"
    r"\b(?:endpoint|page|route)\s+(?:for\s+|on\s+)?([a-z][a-z0-9_-]{2,})\b",
    flags=re.I,
)


def extract_api_paths(text: str) -> list[str]:
    """Return explicit API/static/graphql paths mentioned in the question."""
    return [m.group(1) for m in _PATH_RE.finditer(text or "")]


def extract_soft_endpoint_tokens(question: str) -> list[str]:
    """NL resource tokens likely referring to an API surface (not free vuln words)."""
    q = question or ""
    tokens: list[str] = []
    for m in _SOFT_ENDPOINT_CUES.finditer(q):
        tok = next((g for g in m.groups() if g), "") or ""
        tok = tok.strip("/ ").lower()
        if not tok or tok in _SOFT_STOP:
            continue
        tokens.append(tok)
    # Explicit "X endpoint/page/route" always accepted (any resource token)
    for m in _ENDPOINT_SHAPED.finditer(q):
        tok = next((g for g in m.groups() if g), "") or ""
        tok = tok.strip("/ ").lower()
        if tok and tok not in {
            "the",
            "any",
            "this",
            "that",
            "which",
            "what",
            "exact",
            "full",
            "api",
            "all",
        }:
            tokens.append(tok)
    return list(dict.fromkeys(tokens))


def normalize_endpoint(ep: str) -> str:
    ep = (ep or "").lower().strip()
    # strip method prefixes if present
    ep = re.sub(r"^(get|post|put|patch|delete|all)\s+", "", ep)
    return ep.rstrip("/") or ep


def catalog_path(entry: str) -> str:
    """Strip HTTP method from 'METHOD /path' catalog labels."""
    e = (entry or "").strip()
    if " " in e and e.split(None, 1)[0].upper() in {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
        "ALL",
    }:
        return e.split(None, 1)[1]
    return e


def match_token_to_catalog(token: str, catalog: list[str]) -> list[str]:
    """Map a soft token to catalog path(s) via substring / last-segment match.

    No Levenshtein: prefers exact segment hits. Returns path strings (no method).
    Empty if ambiguous with 0 hits; multiple if several resources match.
    """
    t = (token or "").lower().strip().strip("/")
    if not t or len(t) < 3:
        return []
    hits: list[str] = []
    for entry in catalog or []:
        path = catalog_path(entry)
        pl = path.lower()
        segs = [s for s in re.split(r"[/{}]+", pl) if s and s not in {"api", "v1", "v2"}]
        if t in pl or any(t == s or s.startswith(t) or t.startswith(s) for s in segs):
            hits.append(path)
    return list(dict.fromkeys(hits))


def resolve_soft_endpoints(
    question: str, catalog: list[str]
) -> list[str]:
    """Resolve NL endpoint cues against the live scan catalog (paths only)."""
    if not catalog:
        return []
    resolved: list[str] = []
    for tok in extract_soft_endpoint_tokens(question):
        hits = match_token_to_catalog(tok, catalog)
        # Prefer single unambiguous mapping; if many, keep the soft token as filter
        if len(hits) == 1:
            resolved.append(hits[0])
        elif len(hits) > 1:
            # Prefer shortest path containing the token as segment
            hits_sorted = sorted(hits, key=lambda p: (len(p), p))
            resolved.append(hits_sorted[0])
        else:
            resolved.append(tok)
    return list(dict.fromkeys(resolved))


def path_in_findings(path: str, findings: list[FindingRecord]) -> bool:
    """True if path appears in any finding endpoint field."""
    p = normalize_endpoint(path)
    if not p or p in {"/api", "/api/v1"}:
        return True  # too generic
    for f in findings:
        fe = normalize_endpoint(f.endpoint)
        if p in fe or fe in p:
            return True
        # path param style: /accounts/{id} vs /accounts/
        p_base = re.sub(r"\{[^}]+\}", "", p)
        fe_base = re.sub(r"\{[^}]+\}", "", fe)
        if p_base and (p_base in fe_base or fe_base in p_base):
            return True
    return False


def unknown_paths_in_question(
    question: str, scan_findings: list[FindingRecord]
) -> list[str]:
    """Explicit paths in the question that do not appear in the scan."""
    unknown: list[str] = []
    for path in extract_api_paths(question):
        if not path_in_findings(path, scan_findings):
            unknown.append(path)
    return unknown
