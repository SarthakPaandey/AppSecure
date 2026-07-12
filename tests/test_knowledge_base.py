"""Knowledge corpus shape — assignment sources + AppSec guides."""

from pathlib import Path

from app.ingestion.knowledge_loader import knowledge_inventory, load_knowledge_dir

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "data" / "knowledge"


def test_assignment_owasp_and_cwe_present():
    docs = load_knowledge_dir(KNOWLEDGE)
    types = {d.doc_type for d in docs}
    assert "owasp" in types
    assert "cwe" in types
    assert "guide" in types

    owasp = [d for d in docs if d.doc_type == "owasp"]
    cwe = [d for d in docs if d.doc_type == "cwe"]
    guides = [d for d in docs if d.doc_type == "guide"]

    assert len(owasp) == 10
    assert len(cwe) == 14
    assert len(guides) >= 7


def test_cwes_cover_sample_findings():
    import json

    sample = json.loads((ROOT / "data" / "sample_findings.json").read_text())
    needed = {f["cwe_id"] for f in sample["findings"]}
    docs = load_knowledge_dir(KNOWLEDGE)
    have = {d.cwe_id for d in docs if d.doc_type == "cwe" and d.cwe_id}
    assert needed <= have


def test_guides_have_urls_and_topics():
    docs = load_knowledge_dir(KNOWLEDGE)
    guides = [d for d in docs if d.doc_type == "guide"]
    assert any("idor" in " ".join(g.topics) for g in guides)
    assert any("ssrf" in " ".join(g.topics) or "ssrf" in g.doc_id for g in guides)
    # At least some guides cite external references
    assert any(g.url for g in guides)


def test_inventory_counts():
    inv = knowledge_inventory(KNOWLEDGE)
    assert inv["owasp"] == 10
    assert inv["cwe"] == 14
    assert inv["guide"] >= 7
    assert inv["total"] == inv["owasp"] + inv["cwe"] + inv["guide"]
