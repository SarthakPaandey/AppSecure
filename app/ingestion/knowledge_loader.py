"""Load bundled OWASP / CWE / AppSec guide knowledge documents from disk."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class KnowledgeDoc:
    doc_id: str
    doc_type: str  # cwe | owasp | guide | extra
    title: str
    text: str
    url: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    topics: list[str] = field(default_factory=list)


def _first_heading(text: str, fallback: str) -> str:
    for line in text.splitlines():
        if line.startswith("#"):
            return line.lstrip("#").strip()
    return fallback


def _extract_url(text: str) -> str | None:
    m = re.search(r"https?://\S+", text)
    return m.group(0).rstrip(").,]") if m else None


def _extract_cwes(text: str) -> list[str]:
    return sorted({f"CWE-{n}" for n in re.findall(r"CWE-(\d+)", text, flags=re.I)})


def _extract_owasp_codes(text: str) -> list[str]:
    codes = set()
    for m in re.finditer(r"\bA(0?[1-9]|10)\b", text, flags=re.I):
        codes.add(f"A{int(m.group(1)):02d}")
    return sorted(codes)


# Filename / content → retrieval topics (helps hybrid rank AppSec guides)
GUIDE_TOPICS: dict[str, list[str]] = {
    "api_security_bola_idor": ["idor", "bola", "access control", "authorization", "api"],
    "jwt_none_algorithm": ["jwt", "authentication", "none algorithm", "token"],
    "ssrf_cloud_metadata": ["ssrf", "metadata", "cloud", "source_url"],
    "sqli_parameterized_queries": ["sql injection", "sqli", "parameterized", "injection"],
    "authn_hardening": ["authentication", "password", "rate limit", "hardcoded", "login"],
    "scanner_finding_interpretation": ["scanner", "finding", "ptaas", "hallucination"],
    "owasp_api_top10_pointer": ["api security", "api top 10", "bola"],
}


def load_knowledge_dir(knowledge_dir: Path) -> list[KnowledgeDoc]:
    docs: list[KnowledgeDoc] = []
    knowledge_dir = Path(knowledge_dir)
    if not knowledge_dir.exists():
        return docs

    owasp_dir = knowledge_dir / "owasp_top10_2021"
    if owasp_dir.is_dir():
        for path in sorted(owasp_dir.glob("*.md")):
            text = path.read_text(encoding="utf-8")
            code = path.stem  # A01
            docs.append(
                KnowledgeDoc(
                    doc_id=f"owasp-{code}",
                    doc_type="owasp",
                    title=_first_heading(text, code),
                    text=text,
                    url=_extract_url(text),
                    owasp_category=code,
                    topics=["owasp", code.lower()],
                )
            )

    cwe_dir = knowledge_dir / "cwe"
    if cwe_dir.is_dir():
        for path in sorted(cwe_dir.glob("*.md")):
            text = path.read_text(encoding="utf-8")
            stem = path.stem  # CWE-89
            num = re.sub(r"[^0-9]", "", stem)
            cwe_id = f"CWE-{num}" if num else stem
            docs.append(
                KnowledgeDoc(
                    doc_id=cwe_id.lower().replace("_", "-"),
                    doc_type="cwe",
                    title=_first_heading(text, cwe_id),
                    text=text,
                    url=_extract_url(text)
                    or (f"https://cwe.mitre.org/data/definitions/{num}.html" if num else None),
                    cwe_id=cwe_id,
                    topics=["cwe", cwe_id.lower()],
                )
            )

    guides_dir = knowledge_dir / "appsec_guides"
    if guides_dir.is_dir():
        for path in sorted(guides_dir.glob("*.md")):
            text = path.read_text(encoding="utf-8")
            stem = path.stem
            cwes = _extract_cwes(text)
            owasp_codes = _extract_owasp_codes(text)
            topics = list(GUIDE_TOPICS.get(stem, []))
            topics.extend(c.lower() for c in cwes)
            topics.extend(c.lower() for c in owasp_codes)
            docs.append(
                KnowledgeDoc(
                    doc_id=f"guide-{stem}",
                    doc_type="guide",
                    title=_first_heading(text, stem),
                    text=text,
                    url=_extract_url(text),
                    # Primary CWE for metadata filter (first mentioned)
                    cwe_id=cwes[0] if cwes else None,
                    owasp_category=owasp_codes[0] if owasp_codes else None,
                    topics=sorted(set(topics)),
                )
            )

    return docs


def knowledge_inventory(knowledge_dir: Path) -> dict[str, int]:
    docs = load_knowledge_dir(knowledge_dir)
    inv: dict[str, int] = {}
    for d in docs:
        inv[d.doc_type] = inv.get(d.doc_type, 0) + 1
    inv["total"] = len(docs)
    return inv
