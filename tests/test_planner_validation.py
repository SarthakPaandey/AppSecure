"""Planner boundary: in_scope policy, catalog validation, rules win."""

from __future__ import annotations

from app.rag.plan_schema import QueryPlan
from app.rag.planner import (
    decide_planner_scope,
    merge_plan_into_route,
    validate_plan_against_catalog,
)
from app.rag.router import rule_based_route
from app.services.query_service import QueryService


def test_plan_schema_accepts_arbitrary_ids():
    p = QueryPlan(finding_ids=["SHIP-AUTH-01", "web:xss:44", "VULN_2026_91", "FINDING-001"])
    assert "SHIP-AUTH-01" in p.finding_ids
    assert "web:xss:44" in p.finding_ids
    assert "VULN_2026_91" in p.finding_ids
    assert "FINDING-001" in p.finding_ids


def test_plan_schema_in_scope_defaults_true():
    p = QueryPlan()
    assert p.in_scope is True
    p2 = QueryPlan.model_validate({"intent": "list", "in_scope": False, "confidence": 0.9})
    assert p2.in_scope is False


def test_malformed_plan_fail_open():
    d = decide_planner_scope(None)
    assert d.fail_open is True
    assert d.refuse is False


def test_high_conf_out_of_scope_refuses():
    plan = QueryPlan(in_scope=False, confidence=0.9, rationale="weather")
    d = decide_planner_scope(plan)
    assert d.refuse is True
    assert d.fail_open is False


def test_low_conf_out_of_scope_fail_open():
    plan = QueryPlan(in_scope=False, confidence=0.4, rationale="unsure")
    d = decide_planner_scope(plan)
    assert d.refuse is False
    assert d.fail_open is True


def test_in_scope_true_continues():
    plan = QueryPlan(in_scope=True, confidence=0.8, intent="explain")
    d = decide_planner_scope(plan)
    assert d.refuse is False
    assert d.fail_open is False


def test_validate_drops_fake_finding_ids():
    plan = QueryPlan(
        finding_ids=["SHIP-AUTH-01", "FAKE-ID-999", "web:xss:44"],
        confidence=0.9,
    )
    catalog = ["SHIP-AUTH-01", "web:xss:44", "VULN_2026_91"]
    got = validate_plan_against_catalog(plan, finding_ids=catalog)
    assert got.finding_ids == ["SHIP-AUTH-01", "web:xss:44"]


def test_validate_drops_fake_endpoints():
    plan = QueryPlan(
        endpoint_substrings=["/v2/carriers/session", "/api/invented/nowhere"],
        confidence=0.9,
    )
    catalog = [
        "POST /v2/carriers/session",
        "GET /v2/billing/invoices/{invoice_id}.pdf",
    ]
    got = validate_plan_against_catalog(plan, endpoints=catalog)
    assert any("carriers/session" in e for e in got.endpoint_substrings)
    assert not any("invented" in e for e in got.endpoint_substrings)


def test_explicit_rules_cwe_wins_over_planner():
    rules = rule_based_route("How do I remediate CWE-918?")
    plan = QueryPlan(intent="list", cwe_ids=["CWE-89"], confidence=0.95)
    merged = merge_plan_into_route(rules, plan)
    assert merged.cwe_id == "CWE-918"
    assert merged.intent == "remediation"


def test_explicit_finding_ids_rules_win():
    rules = rule_based_route("Explain FINDING-004")
    plan = QueryPlan(finding_ids=["FINDING-001"], confidence=0.9)
    merged = merge_plan_into_route(rules, plan)
    assert "FINDING-004" in merged.finding_ids
    assert "FINDING-001" not in merged.finding_ids  # rules already had IDs


def test_clear_remediation_topic_skips_semantic_planner():
    route = rule_based_route("How do I fix the SQL injection in transaction search?")
    assert route.intent == "remediation"
    assert route.topics or route.class_constraints
    assert QueryService._rules_confident_for_planner(route, route.raw.get("question", "How do I fix the SQL injection in transaction search?"))


def test_planner_severities_fill_when_rules_empty():
    rules = rule_based_route("show me the worst issues")
    plan = QueryPlan(
        intent="list",
        include_severities=["CRITICAL"],
        want_count=True,
        confidence=0.85,
    )
    merged = merge_plan_into_route(rules, plan)
    assert merged.want_count is True
    assert "CRITICAL" in merged.severities
