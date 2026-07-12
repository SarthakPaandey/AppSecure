"""Dual-stage citation gate unit tests."""

from app.rag.citations import gate_citations


def test_gate_strips_unknown_ids_from_refs_and_text():
    gate = gate_citations(
        answer="See FINDING-001 and FINDING-999 for details.",
        findings_referenced=["FINDING-001", "FINDING-999"],
        allowed_ids={"FINDING-001", "FINDING-002"},
    )
    assert gate.findings_referenced == ["FINDING-001"]
    assert "FINDING-999" in gate.stripped_ids
    assert "FINDING-999" not in gate.answer
    assert "FINDING-001" in gate.answer
    assert gate.ok is False


def test_gate_strips_unknown_catalog_style_ids_from_refs_and_text():
    gate = gate_citations(
        answer="See SHIP-AUTH-01 and SHIP-AUTH-999; CWE-287 remains relevant.",
        findings_referenced=["SHIP-AUTH-01", "SHIP-AUTH-999"],
        allowed_ids={"SHIP-AUTH-01"},
    )
    assert gate.findings_referenced == ["SHIP-AUTH-01"]
    assert "SHIP-AUTH-999" in gate.stripped_ids
    assert "SHIP-AUTH-999" not in gate.answer
    assert "SHIP-AUTH-01" in gate.answer
    assert "CWE-287" in gate.answer


def test_gate_ok_when_all_allowed():
    gate = gate_citations(
        answer="FINDING-001 is critical.",
        findings_referenced=["FINDING-001"],
        allowed_ids={"FINDING-001"},
    )
    assert gate.ok is True
    assert gate.stripped_ids == []
    assert gate.findings_referenced == ["FINDING-001"]


def test_gate_fill_refs_if_empty():
    gate = gate_citations(
        answer="Based on the scan findings.",
        findings_referenced=[],
        allowed_ids={"FINDING-001", "FINDING-004"},
        fill_refs_if_empty=True,
        fill_from=["FINDING-001", "FINDING-004"],
    )
    assert gate.findings_referenced == ["FINDING-001", "FINDING-004"]
