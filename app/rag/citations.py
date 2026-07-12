"""Citation helpers: validate IDs, build API citations, dual-stage gate."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.api.schemas import Citation
from app.retrieval.findings_store import FindingRecord
from app.retrieval.vector_store import VectorHit


# Classic FINDING-N IDs plus catalog-style IDs with at least two separators.
# This remains deliberately narrower than arbitrary words so CWE-89 and prose
# are not treated as finding citations.
_FINDING_ID_LIKE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:FINDING-\d+|(?:[A-Za-z][A-Za-z0-9]*[-_:]){2,}[A-Za-z0-9][A-Za-z0-9:_-]*)(?![A-Za-z0-9])",
    flags=re.I,
)



def validate_finding_ids(
    claimed: list[str] | None,
    retrieved: list[FindingRecord],
) -> list[str]:
    """Keep only finding IDs that appear in the retrieved set (order preserved)."""
    allowed = {r.finding_id for r in retrieved}
    allowed_upper = {a.upper(): a for a in allowed}
    out: list[str] = []
    seen: set[str] = set()
    for fid in claimed or []:
        fid_norm = str(fid).strip().upper()
        match = allowed_upper.get(fid_norm)
        if match and match not in seen:
            seen.add(match)
            out.append(match)
    return out


def finding_ids_mentioned_in_answer(
    answer: str,
    *,
    catalog_ids: list[str] | None = None,
) -> list[str]:
    """Extract finding IDs from answer text (first-appearance order).

    Always matches classic ``FINDING-\\d+``. When ``catalog_ids`` is provided,
    also matches arbitrary catalog IDs (``SHIP-AUTH-01``, ``web:xss:44``, …).
    """
    out: list[str] = []
    seen: set[str] = set()
    text = answer or ""

    if catalog_ids:
        ordered = sorted(set(catalog_ids), key=lambda x: (-len(x), x.upper()))
        for fid in ordered:
            if not fid:
                continue
            pattern = re.compile(
                r"(?<![A-Za-z0-9])" + re.escape(fid) + r"(?![A-Za-z0-9])",
                flags=re.I,
            )
            if pattern.search(text) and fid.upper() not in seen:
                seen.add(fid.upper())
                out.append(fid)

    for m in re.finditer(r"FINDING-\d+", text, flags=re.I):
        fid = m.group(0).upper()
        if fid not in seen:
            seen.add(fid)
            out.append(fid)
    return out


@dataclass
class GateResult:
    answer: str
    findings_referenced: list[str]
    stripped_ids: list[str] = field(default_factory=list)
    ok: bool = True


def gate_citations(
    *,
    answer: str,
    findings_referenced: list[str] | None,
    allowed_ids: set[str] | list[str],
    strip_unknown_from_answer: bool = True,
    fill_refs_if_empty: bool = False,
    fill_from: list[str] | None = None,
) -> GateResult:
    """Dual-stage citation gate: refs and in-text finding IDs must be allowed."""
    allowed = {str(a).upper() for a in allowed_ids}
    # Preserve catalog casing (FINDING-001, SHIP-AUTH-01, web:xss:44, …)
    canon: dict[str, str] = {str(a).upper(): str(a) for a in allowed_ids}

    stripped: list[str] = []
    safe_refs: list[str] = []
    seen: set[str] = set()
    for fid in findings_referenced or []:
        u = str(fid).strip().upper()
        if u in allowed and u not in seen:
            seen.add(u)
            safe_refs.append(canon.get(u, str(fid).strip()))
        elif u not in allowed:
            stripped.append(u)

    text = answer or ""
    # Detect classic and catalog-style citation-shaped IDs in prose. The latter
    # deliberately requires two separators, avoiding normal security tokens
    # such as CWE-89 while covering SHIP-AUTH-01, web:xss:44, and VULN_2026_91.
    for m in _FINDING_ID_LIKE_TOKEN.finditer(text):
        u = m.group(0).upper()
        if u not in allowed:
            stripped.append(u)

    if strip_unknown_from_answer and stripped:
        def _repl(m: re.Match[str]) -> str:
            u = m.group(0).upper()
            return m.group(0) if u in allowed else ""

        text = _FINDING_ID_LIKE_TOKEN.sub(_repl, text)
        text = re.sub(r"[ \t]{2,}", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text).strip()


    stripped = list(dict.fromkeys(stripped))
    if fill_refs_if_empty and not safe_refs and fill_from:
        for fid in fill_from:
            u = str(fid).upper()
            if u in allowed and u not in seen:
                seen.add(u)
                safe_refs.append(canon.get(u, str(fid)))

    ok = len(stripped) == 0
    return GateResult(
        answer=text,
        findings_referenced=safe_refs,
        stripped_ids=stripped,
        ok=ok,
    )


def filter_citations_to_answer(
    *,
    answer: str,
    candidate_ids: list[str],
    intent: str,
) -> list[str]:
    """Prefer citations that actually appear in the answer text.

    Inventory intents keep the full candidate set. For synthesis intents, if the
    answer names FINDING-ids, cite only those (∩ candidates).
    """
    if intent in {"list", "summary", "severity", "cross_ref", "cluster", "existence"}:
        return candidate_ids

    mentioned = finding_ids_mentioned_in_answer(
        answer, catalog_ids=candidate_ids
    )
    if not mentioned:
        return candidate_ids

    allowed = {c.upper(): c for c in candidate_ids}
    filtered = [allowed[m] for m in mentioned if m in allowed]
    return filtered if filtered else candidate_ids


def build_citations(
    *,
    findings: list[FindingRecord],
    finding_ids: list[str],
    knowledge_hits: list[VectorHit],
    reference_ids: list[str] | None = None,
) -> list[Citation]:
    citations: list[Citation] = []
    by_id = {f.finding_id: f for f in findings}

    for fid in finding_ids:
        f = by_id.get(fid)
        if not f:
            continue
        citations.append(
            Citation(
                type="finding",
                id=f.finding_id,
                title=f.title,
                severity=f.severity,
            )
        )

    wanted = {r.lower() for r in (reference_ids or [])}
    seen_ref: set[str] = set()
    for hit in knowledge_hits:
        if hit.metadata.get("doc_type") == "finding":
            continue
        source_id = str(hit.metadata.get("source_id") or hit.id)
        cwe_id = str(hit.metadata.get("cwe_id") or "")
        title = str(hit.metadata.get("title") or source_id)
        keys = {source_id.lower(), cwe_id.lower(), hit.id.lower(), title.lower()}
        if wanted and not (keys & wanted) and not any(w in title.lower() for w in wanted):
            if reference_ids:
                continue
        if source_id in seen_ref:
            continue
        seen_ref.add(source_id)
        citations.append(
            Citation(
                type="reference",
                id=source_id,
                title=title,
                url=str(hit.metadata.get("url") or None) or None,
                snippet=(hit.text[:240] + "…") if len(hit.text) > 240 else hit.text,
            )
        )
        if len([c for c in citations if c.type == "reference"]) >= 5:
            break

    return citations
