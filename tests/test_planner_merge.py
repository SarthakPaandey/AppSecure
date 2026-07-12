"""Planner merge + endpoint catalog resolution (no live LLM)."""

from app.rag.plan_schema import QueryPlan
from app.rag.planner import merge_plan_into_route, resolve_endpoints_against_catalog
from app.rag.router import rule_based_route


def test_merge_want_count_from_plan():
    rules = rule_based_route("tell me about critical stuff")
    plan = QueryPlan(intent="list", want_count=True, include_severities=["CRITICAL"], confidence=0.9)
    merged = merge_plan_into_route(rules, plan)
    assert merged.want_count is True
    assert merged.answer_mode == "count"


def test_merge_rules_cwe_wins():
    rules = rule_based_route("How do I remediate CWE-918?")
    plan = QueryPlan(intent="list", cwe_ids=["CWE-89"], confidence=0.9)
    merged = merge_plan_into_route(rules, plan)
    assert merged.cwe_id == "CWE-918"
    assert merged.intent == "remediation"


def test_resolve_endpoints_catalog():
    catalog = [
        "GET /api/v1/transactions/search",
        "POST /api/v1/payments/initiate",
    ]
    got = resolve_endpoints_against_catalog(["transaction search"], catalog)
    assert any("transactions/search" in g for g in got)


def test_query_plan_normalizes_cwe():
    p = QueryPlan(cwe_ids=["89", "cwe-918"])
    assert "CWE-89" in p.cwe_ids
    assert "CWE-918" in p.cwe_ids
