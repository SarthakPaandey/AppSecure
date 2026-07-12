"""Assemble grounded context for dynamic synthesis (findings + knowledge)."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.retrieval.findings_store import FindingRecord
from app.retrieval.vector_store import VectorHit


@dataclass
class ContextBundle:
    findings: list[FindingRecord] = field(default_factory=list)
    knowledge_hits: list[VectorHit] = field(default_factory=list)
    allowed_ids: set[str] = field(default_factory=set)
    finding_blocks: list[str] = field(default_factory=list)
    knowledge_blocks: list[str] = field(default_factory=list)
    intent: str = "general"


def assemble_context(
    *,
    findings: list[FindingRecord],
    knowledge_hits: list[VectorHit] | None = None,
    intent: str = "general",
    max_findings: int = 8,
    max_knowledge: int = 4,
) -> ContextBundle:
    capped = list(findings)[:max_findings]
    hits = list(knowledge_hits or [])[:max_knowledge]
    blocks = [f.to_prompt_block() for f in capped]
    k_blocks: list[str] = []
    for hit in hits:
        title = hit.metadata.get("title") or hit.id
        k_blocks.append(f"[{hit.metadata.get('source_id') or hit.id}] {title}\n{hit.text[:1200]}")
    return ContextBundle(
        findings=capped,
        knowledge_hits=hits,
        allowed_ids={f.finding_id for f in capped},
        finding_blocks=blocks,
        knowledge_blocks=k_blocks,
        intent=intent,
    )
