"""Strict subtype support for existence questions.

A specific vulnerability subtype requires direct title/description/CWE/class
support. A parent family match (e.g. "injection" broadly) is not enough to
confirm "command injection" exists in the scan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.retrieval.findings_store import FindingRecord


@dataclass(frozen=True)
class ExistenceSubtype:
    """Named vulnerability subtype with direct-evidence rules."""

    name: str
    # Patterns that mean the *question* is asking for this subtype (not broad family)
    question_patterns: tuple[str, ...]
    # Phrases that must appear in finding text for direct support
    support_phrases: tuple[str, ...]
    # CWE IDs that count as direct support
    support_cwes: tuple[str, ...] = ()


# Order matters: more specific patterns first when scanning the question.
SUBTYPES: tuple[ExistenceSubtype, ...] = (
    ExistenceSubtype(
        name="command_injection",
        question_patterns=(
            r"\bcommand\s+injection\b",
            r"\bos\s+command\s+injection\b",
            r"\bshell\s+injection\b",
            r"\bos\s+command\b",
        ),
        support_phrases=(
            "command injection",
            "os command injection",
            "os command",
            "shell injection",
            "arbitrary command",
            "command execution",
            "exec(",
            "system(",
        ),
        support_cwes=("CWE-78",),
    ),
    ExistenceSubtype(
        name="sql_injection",
        question_patterns=(
            r"\bsql\s+injection\b",
            r"\bsqli\b",
            r"\bsql-i\b",
        ),
        support_phrases=(
            "sql injection",
            "sqli",
            "sql query",
            "parameterized",
        ),
        support_cwes=("CWE-89",),
    ),
    ExistenceSubtype(
        name="xss",
        question_patterns=(
            r"\bxss\b",
            r"\bcross[- ]site\s+scripting\b",
        ),
        support_phrases=(
            "xss",
            "cross-site scripting",
            "cross site scripting",
            "reflected xss",
            "stored xss",
        ),
        support_cwes=("CWE-79",),
    ),
    ExistenceSubtype(
        name="xxe",
        question_patterns=(
            r"\bxxe\b",
            r"\bxml\s+external\s+entity\b",
        ),
        support_phrases=(
            "xxe",
            "xml external entity",
            "external entity",
        ),
        support_cwes=("CWE-611",),
    ),
    ExistenceSubtype(
        name="ssrf",
        question_patterns=(
            r"\bssrf\b",
            r"\bserver[- ]side\s+request\s+forgery\b",
        ),
        support_phrases=(
            "ssrf",
            "server-side request forgery",
            "server side request forgery",
            "169.254.169.254",
            "cloud metadata",
        ),
        support_cwes=("CWE-918",),
    ),
    ExistenceSubtype(
        name="rce",
        question_patterns=(
            r"\brce\b",
            r"\bremote\s+code\s+execution\b",
            r"\bcode\s+execution\b",
            r"\breverse\s+shell\b",
        ),
        support_phrases=(
            "remote code execution",
            "rce",
            "code execution",
            "reverse shell",
            "arbitrary code",
        ),
        # RCE is often tagged under other CWEs; require explicit wording in text
        support_cwes=(),
    ),
)


def detect_existence_subtype(question: str) -> ExistenceSubtype | None:
    """If the question names a specific subtype, return it; else None (broad family OK)."""
    q = question or ""
    for sub in SUBTYPES:
        for pat in sub.question_patterns:
            if re.search(pat, q, flags=re.I):
                return sub
    return None


def _record_blob(rec: FindingRecord) -> str:
    return " ".join(
        [
            rec.title or "",
            rec.description or "",
            rec.endpoint or "",
            rec.cwe_id or "",
            rec.owasp_category or "",
            rec.remediation_hint or "",
            rec.parameter or "",
        ]
    ).lower()


def _cwe_matches(rec: FindingRecord, want: tuple[str, ...]) -> bool:
    if not want:
        return False
    raw = (rec.cwe_id or "").upper().replace("CWE", "CWE-").replace("CWE--", "CWE-")
    for c in want:
        num = re.sub(r"\D", "", c)
        if num and num in (rec.cwe_id or ""):
            return True
        if c.upper() in raw:
            return True
    return False


def finding_supports_subtype(rec: FindingRecord, subtype: ExistenceSubtype) -> bool:
    """True only when the finding row directly supports the requested subtype."""
    if _cwe_matches(rec, subtype.support_cwes):
        return True
    blob = _record_blob(rec)
    for phrase in subtype.support_phrases:
        p = phrase.lower()
        if " " in p or "(" in p:
            if p in blob:
                return True
        else:
            if re.search(rf"(?<![a-z0-9]){re.escape(p)}(?![a-z0-9])", blob):
                return True
    return False


def filter_for_existence_subtype(
    question: str,
    findings: list[FindingRecord],
) -> list[FindingRecord]:
    """For specific subtype existence, keep only rows with direct support.

    Broad family questions (e.g. "any injection findings?") pass through unchanged.
    """
    subtype = detect_existence_subtype(question)
    if subtype is None:
        return findings
    return [f for f in findings if finding_supports_subtype(f, subtype)]
