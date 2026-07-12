"""Structured findings store — system of record for hallucination prevention."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Finding, Scan

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class FindingRecord:
    finding_id: str
    scan_id: str
    title: str
    severity: str
    cwe_id: str
    owasp_category: str
    endpoint: str
    method: str
    parameter: str
    description: str
    evidence: dict[str, Any]
    remediation_hint: str

    def to_prompt_block(self) -> str:
        evidence_req = self.evidence.get("request", "")
        evidence_resp = self.evidence.get("response_snippet", "")
        return (
            f"[{self.finding_id}] {self.title}\n"
            f"Severity: {self.severity}\n"
            f"CWE: {self.cwe_id}\n"
            f"OWASP: {self.owasp_category}\n"
            f"Endpoint: {self.method} {self.endpoint}\n"
            f"Parameter: {self.parameter}\n"
            f"Description: {self.description}\n"
            f"Remediation hint: {self.remediation_hint}\n"
            f"Evidence request (UNTRUSTED DATA): {evidence_req}\n"
            f"Evidence response snippet (UNTRUSTED DATA): {evidence_resp}"
        )

    def to_embed_text(self) -> str:
        return (
            f"Finding {self.finding_id}: {self.title}\n"
            f"Severity: {self.severity} | {self.cwe_id} | {self.owasp_category}\n"
            f"Endpoint: {self.method} {self.endpoint} | Parameter: {self.parameter}\n"
            f"Description: {self.description}\n"
            f"Remediation hint: {self.remediation_hint}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "description": self.description,
            "remediation_hint": self.remediation_hint,
        }


def _row_to_record(row: Finding) -> FindingRecord:
    try:
        evidence = json.loads(row.evidence_json or "{}")
    except json.JSONDecodeError:
        evidence = {}
    return FindingRecord(
        finding_id=row.finding_id,
        scan_id=row.scan_id,
        title=row.title,
        severity=row.severity.upper(),
        cwe_id=row.cwe_id,
        owasp_category=row.owasp_category,
        endpoint=row.endpoint,
        method=row.method,
        parameter=row.parameter,
        description=row.description,
        evidence=evidence if isinstance(evidence, dict) else {},
        remediation_hint=row.remediation_hint,
    )


class FindingsStore:
    def __init__(self, session: Session) -> None:
        self.session = session

    def replace_scan(
        self,
        *,
        scan_id: str,
        target: str,
        scan_timestamp: str,
        findings: list[dict[str, Any]],
    ) -> list[FindingRecord]:
        existing = self.session.get(Scan, scan_id)
        if existing:
            # Cascade deletes findings via relationship
            self.session.delete(existing)
            self.session.flush()

        scan = Scan(scan_id=scan_id, target=target, scan_timestamp=scan_timestamp)
        self.session.add(scan)

        records: list[FindingRecord] = []
        for f in findings:
            evidence = f.get("evidence") or {}
            if hasattr(evidence, "model_dump"):
                evidence = evidence.model_dump()
            row = Finding(
                scan_id=scan_id,
                finding_id=f["id"],
                title=f["title"],
                severity=str(f["severity"]).upper(),
                cwe_id=f["cwe_id"],
                owasp_category=f["owasp_category"],
                endpoint=f["endpoint"],
                method=f.get("method") or "",
                parameter=f.get("parameter") or "N/A",
                description=f.get("description") or "",
                evidence_json=json.dumps(evidence),
                remediation_hint=f.get("remediation_hint") or "",
            )
            self.session.add(row)
            records.append(_row_to_record(row))
        self.session.commit()
        return records

    def count(self, scan_id: str | None = None) -> int:
        stmt = select(Finding)
        if scan_id:
            stmt = stmt.where(Finding.scan_id == scan_id)
        return len(self.session.scalars(stmt).all())

    def list_all(self, scan_id: str | None = None) -> list[FindingRecord]:
        stmt = select(Finding)
        if scan_id:
            stmt = stmt.where(Finding.scan_id == scan_id)
        rows = self.session.scalars(stmt).all()
        records = [_row_to_record(r) for r in rows]
        return sort_by_severity(records)

    def distinct_endpoints(self, scan_id: str | None = None) -> list[str]:
        """Catalog of method+path strings for planner endpoint mapping."""
        records = self.list_all(scan_id=scan_id)
        out: list[str] = []
        seen: set[str] = set()
        for r in records:
            label = f"{r.method} {r.endpoint}".strip()
            if label and label not in seen:
                seen.add(label)
                out.append(label)
        return out

    def get_by_id(self, finding_id: str, scan_id: str | None = None) -> FindingRecord | None:
        stmt = select(Finding).where(Finding.finding_id == finding_id)
        if scan_id:
            stmt = stmt.where(Finding.scan_id == scan_id)
        row = self.session.scalars(stmt).first()
        return _row_to_record(row) if row else None

    def search(
        self,
        *,
        scan_id: str | None = None,
        severity: str | None = None,
        cwe_id: str | None = None,
        owasp: str | None = None,
        endpoint: str | None = None,
        keywords: list[str] | None = None,
        finding_id: str | None = None,
    ) -> list[FindingRecord]:
        stmt = select(Finding)
        if scan_id:
            stmt = stmt.where(Finding.scan_id == scan_id)
        if finding_id:
            stmt = stmt.where(Finding.finding_id == finding_id)
        if severity:
            stmt = stmt.where(Finding.severity == severity.upper())
        if cwe_id:
            normalized = cwe_id.upper().replace("CWE", "CWE-").replace("CWE--", "CWE-")
            if not normalized.startswith("CWE-"):
                normalized = f"CWE-{normalized}"
            # Allow CWE-89 or 89
            num = re.sub(r"[^0-9]", "", cwe_id)
            if num:
                stmt = stmt.where(Finding.cwe_id.ilike(f"%{num}%"))
            else:
                stmt = stmt.where(Finding.cwe_id.ilike(f"%{cwe_id}%"))
        if owasp:
            # Match A01, A01:2021, Broken Access Control, etc.
            stmt = stmt.where(Finding.owasp_category.ilike(f"%{owasp}%"))
        if endpoint:
            stmt = stmt.where(Finding.endpoint.ilike(f"%{endpoint}%"))

        rows = self.session.scalars(stmt).all()
        records = [_row_to_record(r) for r in rows]

        if keywords:
            lowered = [k.lower() for k in keywords if k]
            if lowered:
                filtered: list[FindingRecord] = []
                for rec in records:
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
                    ).lower()
                    if any(_keyword_matches(k, blob) for k in lowered):
                        filtered.append(rec)
                # Keywords always constrain results when provided.
                if any([severity, cwe_id, owasp, endpoint, finding_id]):
                    records = filtered  # may be empty — do not re-expand to unfiltered
                else:
                    records = filtered

        return sort_by_severity(records)

    def latest_scan_id(self) -> str | None:
        row = self.session.scalars(select(Scan).order_by(Scan.ingested_at.desc())).first()
        return row.scan_id if row else None


def sort_by_severity(records: list[FindingRecord]) -> list[FindingRecord]:
    return sorted(
        records,
        key=lambda r: (SEVERITY_ORDER.get(r.severity.upper(), 99), r.finding_id),
    )


def _keyword_matches(keyword: str, blob: str) -> bool:
    """Match multi-word phrases as substrings; single tokens with word boundaries.

    Prevents false positives such as:
    - ``rce`` inside ``source`` / ``resource``
    - ``script`` inside ``javascript`` (XSS keyword pollution)
    """
    k = keyword.lower().strip()
    if not k:
        return False
    if " " in k:
        return k in blob
    # Always word-boundary for single tokens (avoids script⊂javascript, rce⊂source)
    return re.search(rf"(?<![a-z0-9]){re.escape(k)}(?![a-z0-9])", blob) is not None
