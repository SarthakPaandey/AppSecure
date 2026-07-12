"""AppSec topic taxonomy: maps natural-language topics to CWE/OWASP/keywords.

This is the single source of truth for soft-class understanding.
It replaces scattered hardcoded keyword lists in router.py, generator.py,
tool_agent.py and query_service.py with one curated map.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class Topic:
    name: str
    cwes: tuple[str, ...] = ()
    owasps: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    abbrevs: tuple[str, ...] = ()
    related: tuple[str, ...] = ()

    def matches(self, text: str) -> bool:
        t = (text or "").lower()
        # Use word-boundary matching so 'injection' doesn't match inside
        # 'command injection' (which is a distinct class) and 'auth' doesn't
        # match inside 'authentication' when the topic is something else.
        for k in self.keywords:
            if re.search(r"(?<![a-z0-9])" + re.escape(k) + r"(?![a-z0-9])", t):
                return True
        for a in self.abbrevs:
            if re.search(r"(?<![a-z0-9])" + re.escape(a) + r"(?![a-z0-9])", t):
                return True
        return False


TOPICS: dict[str, Topic] = {
    "injection": Topic(
        name="injection",
        cwes=("CWE-89", "CWE-79", "CWE-918"),
        owasps=("A03", "A10"),
        keywords=(
            "injection",
            "sql injection",
            "command injection",
            "ldap injection",
            "xpath injection",
            "nosql injection",
            "os command",
            "code injection",
        ),
        abbrevs=("sqli", "sql-i"),
        related=("ssrf", "xss"),
    ),
    "sql_injection": Topic(
        name="sql_injection",
        cwes=("CWE-89",),
        owasps=("A03",),
        keywords=("sql injection", "sql query", "parameterized query"),
        abbrevs=("sqli", "sql-i"),
    ),
    "xss": Topic(
        name="xss",
        cwes=("CWE-79",),
        owasps=("A03",),
        keywords=("cross-site scripting", "reflected xss", "stored xss", "dom xss"),
        abbrevs=("xss",),
    ),
    "ssrf": Topic(
        name="ssrf",
        cwes=("CWE-918",),
        owasps=("A10",),
        keywords=(
            "server-side request forgery",
            "ssrf",
            "cloud metadata",
            "metadata endpoint",
            "169.254.169.254",
            "internal request",
        ),
    ),
    "authentication": Topic(
        name="authentication",
        cwes=("CWE-287", "CWE-307", "CWE-521", "CWE-798"),
        owasps=("A07",),
        keywords=(
            "authentication",
            "authn",
            "login",
            "password",
            "jwt",
            "token",
            "session",
            "rate limiting",
            "brute force",
            "credential",
            "hardcoded",
            "account takeover",
            "authentication bypass",
        ),
        abbrevs=("ato",),
        related=("authorization", "mass_assignment"),
    ),
    "authorization": Topic(
        name="authorization",
        cwes=("CWE-639", "CWE-285"),
        owasps=("A01",),
        keywords=(
            "authorization",
            "authz",
            "access control",
            "broken access control",
            "object level",
            "direct object",
            "ownership",
            "permission",
        ),
        abbrevs=("idor", "bola"),
        related=("authentication",),
    ),
    "secrets": Topic(
        name="secrets",
        cwes=("CWE-798",),
        owasps=("A07",),
        keywords=(
            "secret",
            "secrets management",
            "secret management",
            "hardcoded",
            "api key",
            "apikey",
            "credential",
            "private key",
        ),
    ),
    "data_exposure": Topic(
        name="data_exposure",
        cwes=("CWE-200", "CWE-209", "CWE-918"),
        owasps=("A04", "A05", "A10"),
        keywords=(
            "pii",
            "personal information",
            "financial data",
            "sensitive data",
            "data exposure",
            "data leak",
            "information disclosure",
            "verbose error",
            "stack trace",
        ),
    ),
    "cryptographic": Topic(
        name="cryptographic",
        cwes=("CWE-295", "CWE-326", "CWE-327", "CWE-330"),
        owasps=("A02",),
        keywords=(
            "tls",
            "certificate",
            "cryptographic",
            "encryption",
            "ssl",
            "cipher",
        ),
    ),
    "mass_assignment": Topic(
        name="mass_assignment",
        cwes=("CWE-915",),
        owasps=("A08",),
        keywords=(
            "mass assignment",
            "auto-binding",
            "binding",
            "privilege escalation",
            "role elevation",
            "writable role",
            "object property",
        ),
        related=("authentication", "authorization"),
    ),
    "file_upload": Topic(
        name="file_upload",
        cwes=("CWE-434",),
        owasps=("A04",),
        keywords=("file upload", "unrestricted upload", "malicious file"),
    ),
    "graphql": Topic(
        name="graphql",
        cwes=("CWE-200",),
        owasps=("A05",),
        keywords=("graphql", "introspection"),
    ),
    "security_headers": Topic(
        name="security_headers",
        cwes=("CWE-693",),
        owasps=("A05",),
        keywords=("security headers", "content-security-policy", "hsts", "x-frame-options"),
    ),
}


ABBREV_TO_TOPICS: dict[str, tuple[str, ...]] = {
    "sqli": ("sql_injection", "injection"),
    "sql-i": ("sql_injection", "injection"),
    "sql injection": ("sql_injection", "injection"),
    "idor": ("authorization",),
    "bola": ("authorization",),
    "ssrf": ("ssrf",),
    "xss": ("xss",),
    "rce": tuple(),
    "xxe": tuple(),
    "jwt": ("authentication",),
    "ato": ("authentication",),
}


def topic_names_for_text(text: str, exclude: Iterable[str] | None = None) -> list[str]:
    """Return topic names that match the given text."""
    ex = {e.lower() for e in (exclude or [])}
    out: list[str] = []
    seen: set[str] = set()
    t = (text or "").lower()
    # Exact abbreviations first
    for abbrev, topics in ABBREV_TO_TOPICS.items():
        if abbrev in t:
            for name in topics:
                if name not in seen and name not in ex:
                    seen.add(name)
                    out.append(name)
    # Topic keywords
    for name, topic in TOPICS.items():
        if name not in seen and name not in ex and topic.matches(t):
            seen.add(name)
            out.append(name)
    return out


def cwes_for_topic(name: str) -> list[str]:
    return list(TOPICS.get(name, Topic(name="")).cwes)


def owasps_for_topic(name: str) -> list[str]:
    return list(TOPICS.get(name, Topic(name="")).owasps)


def keywords_for_topic(name: str) -> list[str]:
    topic = TOPICS.get(name)
    if not topic:
        return []
    return list(topic.keywords) + list(topic.abbrevs)


def expand_abbrev(text: str) -> list[str]:
    """Return expansions for abbreviations present in text (e.g. sqli -> SQL injection).

    Matches whole tokens only so ``rce`` does not fire inside ``resources``.
    """
    import re

    t = (text or "").lower()
    out: list[str] = []
    seen: set[str] = set()
    # Keep existing abbrev map behavior for compatibility
    ABBREV_EXPANSIONS = {
        "sqli": ["SQL injection", "CWE-89"],
        "sql-i": ["SQL injection", "CWE-89"],
        "xss": ["cross-site scripting", "CWE-79"],
        "idor": ["IDOR", "BOLA", "CWE-639"],
        "bola": ["BOLA", "IDOR", "CWE-639"],
        "ssrf": ["SSRF", "CWE-918"],
        "rce": ["remote code execution", "RCE"],
        "jwt": ["JWT"],
        "xxe": ["XXE", "XML external entity"],
    }
    for abbrev, expansions in ABBREV_EXPANSIONS.items():
        # Word-boundary match; allow hyphens in abbrev (sql-i)
        if re.search(rf"(?<![a-z0-9]){re.escape(abbrev)}(?![a-z0-9])", t):
            for e in expansions:
                if e not in seen:
                    seen.add(e)
                    out.append(e)
    return out


def is_negated(topic_name: str, text: str) -> bool:
    """Rough check: is the topic mentioned under negation in the text?"""
    import re

    t = (text or "").lower()
    topic = TOPICS.get(topic_name)
    if not topic:
        return False
    # If the whole question contains a severity negation pattern like
    # "not labeled CRITICAL" or "not high severity", the 'not' is about
    # severity, not about any vulnerability topic.
    if re.search(
        r"\b(?:not|no|non)\s+(?:labeled\s+)?(?:critical|high|medium|low)(?:\s+severity)?\b",
        t,
    ):
        return False
    # Find windows around topic keywords and check for 'not' / 'no' nearby
    for phrase in list(topic.keywords) + list(topic.abbrevs):
        for m in re.finditer(r"\b" + re.escape(phrase.lower()) + r"\b", t):
            window = t[max(0, m.start() - 40) : m.end() + 40]
            if not re.search(r"\b(not|no|non|without|excluding|except)\b", window):
                continue
            # Don't negate if the 'not' is about severity even if it's
            # adjacent to the topic keyword (the severity check above
            # already handled the global case).
            return True
    return False
