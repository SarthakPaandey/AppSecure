"""Prepare the finding pool passed to the generator (inventory seeding + caps)."""

from __future__ import annotations

from app.rag.router import RouteResult
from app.retrieval.findings_store import FindingRecord, FindingsStore, sort_by_severity
from app.retrieval.hybrid import HybridRetrievalResult


def prepare_generation_pool(
    *,
    route: RouteResult,
    retrieval: HybridRetrievalResult,
    findings_store: FindingsStore,
    scan_id: str | None,
) -> list[FindingRecord]:
    """Expand inventory for templates (top_n / buckets / impact) and cap synthesis size."""
    gen_findings = list(retrieval.findings)

    if route.classify_problem_buckets:
        gen_findings = sort_by_severity(
            findings_store.search(scan_id=scan_id, severity="HIGH")
        )
        retrieval.findings = gen_findings

    if route.top_n:
        by_id = {f.finding_id: f for f in gen_findings}
        for c in findings_store.search(scan_id=scan_id, severity="CRITICAL"):
            by_id[c.finding_id] = c
        for h in findings_store.search(scan_id=scan_id, severity="HIGH"):
            by_id.setdefault(h.finding_id, h)
        gen_findings = sort_by_severity(list(by_id.values()))
        retrieval.findings = gen_findings

    if route.data_impact:
        by_id = {f.finding_id: f for f in gen_findings}
        for f in findings_store.list_all(scan_id=scan_id):
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

    return gen_findings
