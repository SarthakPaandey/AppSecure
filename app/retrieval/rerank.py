"""Reranking: light features and optional local neural cross-encoder.

Pipeline after BM25 ∪ dense RRF:
  1) light feature rerank (always available)
  2) optional MiniLM cross-encoder on the shortlist (production path)

Cross-encoder needs no paid API — local sentence-transformers model.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.retrieval.bm25_index import tokenize
from app.retrieval.findings_store import FindingRecord, SEVERITY_ORDER

if TYPE_CHECKING:
    from app.retrieval.cross_encoder import CrossEncoderReranker

logger = logging.getLogger(__name__)


@dataclass
class RankedFinding:
    record: FindingRecord
    score: float


def _phrase_bonus(query: str, blob: str) -> float:
    q = (query or "").lower()
    b = (blob or "").lower()
    bonus = 0.0
    words = re.findall(r"[a-z0-9]+", q)
    for n in (3, 2):
        for i in range(0, max(0, len(words) - n + 1)):
            phrase = " ".join(words[i : i + n])
            if len(phrase) >= 5 and phrase in b:
                bonus += 1.5 if n >= 3 else 0.8
    for m in re.finditer(r"cwe-?\d+|finding-\d+|a0?\d{1,2}", q, flags=re.I):
        token = m.group(0).lower().replace("cwe", "cwe-").replace("cwe--", "cwe-")
        blob_n = b.replace("cwe", "cwe-").replace("cwe--", "cwe-")
        if token in blob_n:
            bonus += 2.0
    return bonus


def light_rerank_findings(
    *,
    query: str,
    candidates: list[tuple[FindingRecord, float]],
    intent: str = "general",
    top_k: int = 20,
) -> list[FindingRecord]:
    """Feature rerank (overlap + phrases + mild severity prior)."""
    if not candidates:
        return []

    q_toks = set(tokenize(query))
    scored: list[RankedFinding] = []
    for rec, base in candidates:
        blob = " ".join(
            [
                rec.title,
                rec.description,
                rec.endpoint,
                rec.cwe_id,
                rec.owasp_category,
                rec.remediation_hint,
                rec.parameter,
            ]
        )
        d_toks = set(tokenize(blob))
        overlap = len(q_toks & d_toks) / max(1, len(q_toks))
        phrase = _phrase_bonus(query, blob)
        sev_boost = 0.0
        if intent in {"severity", "summary", "list"}:
            order = SEVERITY_ORDER.get(rec.severity.upper(), 9)
            sev_boost = max(0.0, (4 - order) * 0.05)

        score = float(base) + 0.35 * overlap + 0.08 * phrase + sev_boost
        scored.append(RankedFinding(record=rec, score=score))

    scored.sort(
        key=lambda x: (
            -x.score,
            SEVERITY_ORDER.get(x.record.severity.upper(), 99),
            x.record.finding_id,
        )
    )
    out: list[FindingRecord] = []
    seen: set[str] = set()
    for item in scored:
        fid = item.record.finding_id
        if fid in seen:
            continue
        seen.add(fid)
        out.append(item.record)
        if len(out) >= top_k:
            break
    return out


# Back-compat alias
rerank_findings = light_rerank_findings


def hybrid_rerank_findings(
    *,
    query: str,
    candidates: list[tuple[FindingRecord, float]],
    intent: str = "general",
    top_k: int = 20,
    mode: str = "auto",
    cross_encoder: CrossEncoderReranker | None = None,
) -> tuple[list[FindingRecord], str]:
    """Rerank with CE when enabled/available; else light features.

    Returns (findings, mode_used) where mode_used is 'cross_encoder' or 'light'.
    """
    if not candidates:
        return [], "light"

    mode_n = (mode or "auto").strip().lower()
    want_ce = mode_n in {"auto", "cross_encoder", "ce", "neural"}

    if want_ce and cross_encoder is not None and len(candidates) >= 2:
        # Light pass first to order shortlist if CE pool is large
        light_ordered = light_rerank_findings(
            query=query,
            candidates=candidates,
            intent=intent,
            top_k=max(top_k * 2, 24),
        )
        # rebuild base scores from original map
        base_map = {r.finding_id: s for r, s in candidates}
        shortlist = [(r, base_map.get(r.finding_id, 0.0)) for r in light_ordered]
        ce_out = cross_encoder.rerank(
            query=query, candidates=shortlist, top_k=top_k
        )
        if ce_out:
            return ce_out, "cross_encoder"
        if mode_n in {"cross_encoder", "ce", "neural"}:
            logger.info("Forced CE unavailable; falling back to light rerank")

    return (
        light_rerank_findings(
            query=query, candidates=candidates, intent=intent, top_k=top_k
        ),
        "light",
    )
