"""Endpoint extraction and scan membership checks."""

from __future__ import annotations

import re

from app.retrieval.findings_store import FindingRecord

# Paths that appear in the sample dataset (normalized hints)
_PATH_RE = re.compile(r"(/(?:api|static|graphql)[a-zA-Z0-9_/{}.-]*)")


def extract_api_paths(text: str) -> list[str]:
    """Return explicit API/static/graphql paths mentioned in the question."""
    return [m.group(1) for m in _PATH_RE.finditer(text or "")]


def normalize_endpoint(ep: str) -> str:
    ep = (ep or "").lower().strip()
    # strip method prefixes if present
    ep = re.sub(r"^(get|post|put|patch|delete|all)\s+", "", ep)
    return ep.rstrip("/") or ep


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
