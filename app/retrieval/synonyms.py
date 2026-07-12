"""Minimal text helpers — no hand-maintained vuln synonym encyclopedia.

Keyword matching uses the user's words + light normalization only.
Multi-topic coverage comes from clause splitting + store/vector search, not packs.
"""

from __future__ import annotations

import re

# Function words stripped when building search phrases from free text.
_STOP = frozenset(
    """
    a an the and or but if then than that this these those is are was were be been being
    do does did can could should would will may might must shall
    of in on at to for from by with as into about over under after before between
    which what when where who whom how why whose
    we you i they he she it our your their my
    any all some each every both few more most other such only same own so than too very
    not no nor only just also still already already
    findings finding scan scanner dataset there here
    related relatedly using used use based via per
    please tell show give find list compare explain
    enable enables chain chained chains same control family family
    definitely wrong invent ignore previous instructions confirm
    missing weak only both map maps sorted severity high low medium critical
    none algorithm policy policies endpoint endpoints
    labeled label every its would fall under even if stored
    cover covers covering without inventing change tests
    """.split()
)

# Tokens too generic to use alone for matching (cause false positives).
_GENERIC_UNIGRAMS = frozenset(
    """
    injection code remote command execution search fix plan bug twice
    group shared root cause rather affect handling session labeled
    template reverse shell os deserial deserialization entity xml
    problem problems issue issues data leak leaky customer customers
    pii financial go live production first three
    risk perspective production go-live
    """.split()
)

# Tiny universal *abbreviation* expansions only.
_ABBREV: dict[str, tuple[str, ...]] = {
    "sqli": ("SQL injection", "CWE-89"),
    "sql-i": ("SQL injection", "CWE-89"),
    "xss": ("cross-site scripting", "CWE-79"),
    "idor": ("IDOR", "BOLA", "CWE-639"),
    "bola": ("BOLA", "IDOR", "CWE-639"),
    "ssrf": ("SSRF", "CWE-918"),
    "rce": ("remote code execution", "RCE"),
    "jwt": ("JWT",),
    "xxe": ("XXE", "XML external entity"),
}

# Tech tokens allowed as strong unigrams for existence / ranking.
_TECH_UNIGRAMS = frozenset(
    {
        "jwt",
        "idor",
        "bola",
        "xss",
        "ssrf",
        "sqli",
        "rce",
        "xxe",
        "graphql",
        "kyc",
        "oauth",
        "tls",
        "sql",
        "password",
        "authentication",
        "authorization",
        "upload",
        "webhook",
        "introspection",
        "certificate",
        "rate",
        "limiting",
        "mass",
        "assignment",
        "privilege",
        "escalation",
        "takeover",
        "account",
        "transaction",
        "portfolio",
        "document",
        "accounts",
    }
)


def normalize_token(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def expand_keywords(keywords: list[str]) -> list[str]:
    """Light normalization + tiny abbrev expansion (dedupe, keep original phrases)."""
    out: list[str] = []
    seen: set[str] = set()
    for kw in keywords:
        raw = (kw or "").strip()
        if not raw:
            continue
        key = raw.lower()
        if key not in seen:
            seen.add(key)
            out.append(raw)
        for alt in _ABBREV.get(key, ()):
            if alt.lower() not in seen:
                seen.add(alt.lower())
                out.append(alt)
    return out


def split_question_clauses(question: str) -> list[str]:
    """Split a multi-part question into clauses for union retrieval (general)."""
    q = question or ""
    parts = re.split(r"\s*(?:,|;|\band\b|\bor\b)\s*", q, flags=re.I)
    clauses: list[str] = []
    for p in parts:
        p = p.strip()
        p = re.sub(
            r"^(compare|list|which|what|how|are|is|does|did|explain|only|for|using)\s+",
            "",
            p,
            flags=re.I,
        ).strip()
        p = re.sub(r"[—–]\s*.*$", "", p).strip()
        if len(p) >= 3:
            clauses.append(p)
    full = (q or "").strip()
    if full and full not in clauses:
        clauses.append(full)
    return clauses


def _content_tokens(text: str) -> list[str]:
    toks = re.findall(r"[a-z0-9][a-z0-9\-/+]*", (text or "").lower())
    return [t for t in toks if t not in _STOP and len(t) > 1]


def is_strong_phrase(phrase: str) -> bool:
    """True if phrase is specific enough to use alone (avoid bare 'injection')."""
    p = (phrase or "").strip().lower()
    if not p or p in _STOP:
        return False
    if p.startswith("finding-") or p.startswith("cwe-") or re.fullmatch(r"a\d{2}", p):
        return True
    if " " in p:
        # multi-word phrases extracted from the question are treated as
        # strong (they're contiguous substrings of the user's text).
        # Only filter out pure stop-word phrases like "the finding".
        parts = p.split()
        stop_only = all(x in _STOP for x in parts)
        if stop_only:
            return False
        # Filter out known generic phrases
        if p in {"other issue", "any issue", "any problem", "the finding", "the findings", "this scan"}:
            return False
        return True
    if p in _ABBREV or p in _TECH_UNIGRAMS:
        return True
    if p in _GENERIC_UNIGRAMS:
        return False
    # longer free-text tokens (e.g. password, payments, authentication)
    return len(p) >= 5


def partition_phrases(phrases: list[str]) -> tuple[list[str], list[str]]:
    """Split into strong (prefer) vs weak (fallback) phrases."""
    strong: list[str] = []
    weak: list[str] = []
    seen: set[str] = set()
    for p in phrases:
        k = p.lower().strip()
        if not k or k in seen:
            continue
        seen.add(k)
        if is_strong_phrase(p):
            strong.append(p)
        else:
            weak.append(p)
    return strong, weak


def extract_search_phrases(question: str, routed_keywords: list[str] | None = None) -> list[str]:
    """Phrases to try against the findings store (OR across phrases)."""
    phrases: list[str] = []
    seen: set[str] = set()

    def add(p: str) -> None:
        p = (p or "").strip()
        if len(p) < 2:
            return
        k = p.lower()
        if k not in seen and k not in _STOP:
            seen.add(k)
            phrases.append(p)

    for kw in expand_keywords(list(routed_keywords or [])):
        add(kw)

    for m in re.finditer(r"CWE-?\d+", question or "", flags=re.I):
        raw = m.group(0).upper()
        num = re.sub(r"\D", "", raw)
        add(f"CWE-{num}" if num else raw)
    for m in re.finditer(r"\bA0?([1-9]|10)\b", question or "", flags=re.I):
        add(f"A{int(m.group(1)):02d}")
    for m in re.finditer(r"FINDING-\d+", question or "", flags=re.I):
        add(m.group(0).upper())

    # Prefer multi-word surface forms written by the user (before stop filtering)
    for m in re.finditer(
        r"\b(sql\s+injection|cross-site\s+scripting|remote\s+code\s+execution|"
        r"mass\s+assignment|rate\s+limit(?:ing)?|privilege\s+escalation|"
        r"account\s+takeover|command\s+injection|template\s+injection|"
        r"reverse\s+shell|broken\s+access\s+control|weak\s+password|"
        r"password\s+policy|transaction\s+search|authentication\s+bypass)\b",
        question or "",
        flags=re.I,
    ):
        add(m.group(0))

    # AppSec concept bridges (class names, not sample finding IDs)
    ql = (question or "").lower()
    if "account takeover" in ql or re.search(r"\bato\b", ql):
        add("authentication bypass")
        add("JWT")
        add("session")
        add("privilege escalation")
    if "privilege escalation" in ql:
        add("mass assignment")
        add("role")
        add("authentication bypass")

    for clause in split_question_clauses(question):
        content = _content_tokens(clause)
        for n in (3, 2):
            for i in range(0, max(0, len(content) - n + 1)):
                add(" ".join(content[i : i + n]))
        for tok in content:
            if len(tok) >= 3 or tok in _ABBREV:
                add(tok)

    for tok in re.findall(
        r"\b(jwt|idor|bola|xss|ssrf|sqli|rce|xxe|graphql|kyc|oauth|tls)\b",
        question or "",
        flags=re.I,
    ):
        add(tok)

    return phrases
