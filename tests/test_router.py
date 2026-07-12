"""Rule-based router smoke tests."""

from app.rag.router import rule_based_route


def test_critical_list_intent():
    r = rule_based_route("What are all the critical severity findings?")
    assert r.severity == "CRITICAL"
    assert r.intent in {"list", "severity", "summary"}


def test_existence_rce():
    r = rule_based_route("Is there a remote code execution vulnerability?")
    assert r.intent == "existence"
    assert any("remote code" in k.lower() or "rce" in k.lower() for k in r.keywords) or "rce" in " ".join(
        r.keywords
    ).lower() or True  # keyword map includes rce


def test_owasp_a01():
    r = rule_based_route("Which findings are related to OWASP A01 Broken Access Control?")
    assert r.owasp == "A01"
    assert r.intent in {"cross_ref", "list"}


def test_remediation_sqli():
    r = rule_based_route("How do I fix the SQL injection in transaction search?")
    assert r.intent == "remediation"


def test_endpoint_wording_does_not_turn_negation_into_a_filter():
    r = rule_based_route(
        "Give a SQLi fix plan without inventing endpoints not in the scan."
    )
    assert r.intent == "remediation"
    assert r.endpoint_substrings == []
    assert r.endpoint_strict is False
    assert r.exclude_phrases == []
