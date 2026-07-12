"""Cross-encoder rerank unit tests (no model download required)."""

from __future__ import annotations

from app.retrieval.cross_encoder import CrossEncoderReranker
from app.retrieval.findings_store import FindingRecord
from app.retrieval.rerank import hybrid_rerank_findings


def _rec(fid: str, title: str, desc: str = "") -> FindingRecord:
    return FindingRecord(
        finding_id=fid,
        scan_id="s1",
        title=title,
        severity="HIGH",
        cwe_id="CWE-89",
        owasp_category="A03",
        endpoint="/api/x",
        method="GET",
        parameter="q",
        description=desc or title,
        evidence={},
        remediation_hint="fix",
    )


class _FakeCE:
    def score_pairs(self, pairs: list[tuple[str, str]]) -> list[float]:
        # Prefer docs mentioning SQL injection
        out = []
        for _, doc in pairs:
            out.append(10.0 if "sql injection" in doc.lower() else 1.0)
        return out


def test_hybrid_rerank_uses_cross_encoder_when_available():
    ce = CrossEncoderReranker(enabled=True)
    ce._backend = _FakeCE()  # type: ignore[attr-defined]
    ce._failed = False

    candidates = [
        (_rec("FINDING-B", "Missing headers"), 0.9),
        (_rec("FINDING-A", "SQL Injection in search", "SQL injection details"), 0.5),
    ]
    out, mode = hybrid_rerank_findings(
        query="How do I fix SQL injection?",
        candidates=candidates,
        intent="remediation",
        top_k=2,
        mode="cross_encoder",
        cross_encoder=ce,
    )
    assert mode == "cross_encoder"
    assert out[0].finding_id == "FINDING-A"


def test_hybrid_rerank_falls_back_to_light():
    ce = CrossEncoderReranker(enabled=False)
    candidates = [
        (_rec("FINDING-A", "SQL Injection in search"), 0.2),
        (_rec("FINDING-B", "Weak password"), 0.1),
    ]
    out, mode = hybrid_rerank_findings(
        query="SQL injection",
        candidates=candidates,
        intent="general",
        top_k=2,
        mode="auto",
        cross_encoder=ce,
    )
    assert mode == "light"
    assert out
