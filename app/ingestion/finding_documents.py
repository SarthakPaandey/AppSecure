"""Convert findings into embeddable documents."""

from __future__ import annotations

from typing import Any

from app.retrieval.findings_store import FindingRecord


def finding_vector_id(scan_id: str, finding_id: str) -> str:
    return f"finding:{scan_id}:{finding_id}"


def findings_to_vector_payloads(
    records: list[FindingRecord],
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    ids: list[str] = []
    texts: list[str] = []
    metas: list[dict[str, Any]] = []
    for rec in records:
        ids.append(finding_vector_id(rec.scan_id, rec.finding_id))
        texts.append(rec.to_embed_text())
        metas.append(
            {
                "doc_type": "finding",
                "source_id": rec.finding_id,
                "scan_id": rec.scan_id,
                "title": rec.title,
                "severity": rec.severity,
                "cwe_id": rec.cwe_id,
                "owasp_category": rec.owasp_category,
                "endpoint": rec.endpoint,
                "url": "",
            }
        )
    return ids, texts, metas
