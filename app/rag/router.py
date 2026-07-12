"""Query routing: structural slots + intent cues + precision constraints.

Hard rules for severity/CWE/OWASP/path/ids. Soft class names (IDOR, JWT) become
retrieval constraints, not answer packs.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from app.clients.llm import LLMClient, parse_json_response
from app.rag.prompts import ROUTER_SYSTEM
from app.retrieval.taxonomy import (
    TOPICS,
    expand_abbrev,
    is_negated,
    topic_names_for_text,
)

logger = logging.getLogger(__name__)

VALID_INTENTS = {
    "list",
    "explain",
    "remediation",
    "severity",
    "summary",
    "cross_ref",
    "existence",
    "compare",
    "cluster",
    "general",
}

_NUM_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "1": 1,
    "2": 2,
    "3": 3,
    "4": 4,
    "5": 5,
    "6": 6,
    "7": 7,
    "8": 8,
    "9": 9,
    "10": 10,
}


@dataclass
class RouteResult:
    intent: str = "general"
    severity: str | None = None
    severities: list[str] = field(default_factory=list)
    exclude_severities: list[str] = field(default_factory=list)
    cwe_id: str | None = None
    owasp: str | None = None
    endpoint: str | None = None
    finding_id: str | None = None
    finding_ids: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    # Precision: findings must match at least one of these class tokens (in store text)
    class_constraints: list[str] = field(default_factory=list)
    # Text-only include/exclude phrases (FilterSpec) — no finding-ID packs
    include_phrases: list[str] = field(default_factory=list)
    exclude_phrases: list[str] = field(default_factory=list)
    endpoint_substrings: list[str] = field(default_factory=list)
    endpoint_strict: bool = False
    want_count: bool = False
    answer_mode: str | None = None  # count|list|top_n|existence|…
    # Structured answer field projection
    want_parameter: bool = False
    want_endpoint: bool = False
    # Structural: findings whose endpoint/parameter uses path placeholders {id}
    path_param_only: bool = False
    # Synthesis shaping (store-grounded templates, not sample packs)
    classify_problem_buckets: bool = False  # access-control vs injection vs authn
    top_n: int | None = None  # e.g. "which three findings to fix first"
    data_impact: bool = False  # PII / financial cross-customer impact
    topics: list[str] = field(default_factory=list)
    exclude_topics: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    source: str = "rules"


def _extract_number(text: str) -> int | None:
    """Extract a small integer from text, supporting words and digits."""
    m = re.search(r"\b(" + "|".join(map(re.escape, _NUM_WORDS)) + r")\b", text, re.I)
    if m:
        return _NUM_WORDS[m.group(1).lower()]
    m = re.search(r"\b(\d{1,2})\b", text)
    if m:
        return int(m.group(1))
    return None


def rule_based_route(question: str) -> RouteResult:
    """Extract high-precision slots + intent from surface form."""
    q = (question or "").lower()
    result = RouteResult(source="rules")

    # --- Finding IDs (classic FINDING-N; catalog-aware match applied after scan load) ---
    ids = [m.group(0).upper() for m in re.finditer(r"FINDING-\d+", question or "", re.I)]
    if ids:
        result.finding_ids = list(dict.fromkeys(ids))
        result.finding_id = result.finding_ids[0]

    # --- Severities ---
    for m in re.finditer(
        r"\b(?:not|non)(?:\s+labeled)?\s+(critical|high|medium|low)\b", q
    ):
        result.exclude_severities.append(m.group(1).upper())
    for m in re.finditer(r"\b(critical|high|medium|low)\b", q):
        sev = m.group(1).upper()
        start = m.start()
        window = q[max(0, start - 24) : start]
        if re.search(r"\b(?:not|non)(?:\s+labeled)?\s*$", window):
            continue
        if sev not in result.exclude_severities:
            result.severities.append(sev)
    result.severities = list(dict.fromkeys(result.severities))
    if result.severities:
        result.severity = result.severities[0]

    if m := re.search(r"cwe-?(\d+)", q, re.I):
        result.cwe_id = f"CWE-{m.group(1)}"

    if m := re.search(r"\ba0?([1-9]|10)\b", q):
        result.owasp = f"A{int(m.group(1)):02d}"
    elif "broken access control" in q:
        result.owasp = "A01"

    # --- Endpoint/path extraction ---
    if m := re.search(r"(/(?:api|static|graphql)[a-zA-Z0-9_/{}.-]*)", question or ""):
        result.endpoint = m.group(1)
        result.endpoint_substrings.append(m.group(1))

    _ep_stop = {
        "the", "any", "this", "that", "which", "what", "exact", "full",
        "api", "all", "each", "every", "same", "other", "related", "affected",
        "vulnerable", "finding", "findings", "not",
    }
    for m in re.finditer(
        r"\b([a-z][a-z0-9_-]{2,})\s+endpoint\b|"
        r"\bendpoints?\s+(?:related\s+to\s+|on\s+|for\s+)?([a-z][a-z0-9_/-]{2,})",
        q,
    ):
        ep = (m.group(1) or m.group(2) or "").strip("/ ")
        if ep and ep not in _ep_stop:
            result.endpoint_substrings.append(ep)
            result.endpoint_strict = True

    # --- Abbreviations / keywords from taxonomy ---
    result.keywords = list(dict.fromkeys(expand_abbrev(q)))
    # AppSec class abbreviations only (not product path names)
    for tok in re.findall(
        r"\b(jwt|idor|bola|xss|ssrf|sqli|rce|xxe|graphql|oauth|csrf)\b", q
    ):
        if tok not in result.keywords:
            result.keywords.append(tok)

    # --- Field projection ---
    # Path-parameter shape (endpoint /{id}) is structural — not free-text "parameters"
    result.path_param_only = bool(
        re.search(
            r"\bpath\s+param(?:eter)?s?\b|"
            r"\bpath\s+parameters?\s+rather\s+than\b|"
            r"\bin\s+the\s+path\b.*\bparam|"
            r"\bpath\s+(?:variable|placeholder)s?\b",
            q,
        )
    )
    result.want_parameter = bool(
        re.search(r"\bparameters?\b|\bquery string\b|\bquery param", q)
    ) and not result.path_param_only
    result.want_endpoint = bool(
        re.search(r"\bendpoints?\b|\bexact endpoint\b|\bwhich endpoint\b", q)
    )
    if result.path_param_only:
        result.intent = "list"
        result.answer_mode = "list"
        # Avoid soft phrase noise; shape filter alone is enough
        result.include_phrases = []
        result.class_constraints = []

    # --- Detect topics using taxonomy ---
    detected_topics = topic_names_for_text(q)
    negated_topics = [t for t in detected_topics if is_negated(t, q)]
    included_topics = [t for t in detected_topics if t not in negated_topics]
    result.topics = included_topics
    result.exclude_topics = negated_topics

    # Map topics to class constraints and include phrases
    for topic_name in included_topics:
        topic = TOPICS.get(topic_name)
        if not topic:
            continue
        result.class_constraints.extend(topic.keywords)
        result.class_constraints.extend(topic.abbrevs)
        result.class_constraints.extend(topic.cwes)
        result.include_phrases.extend(topic.keywords)
        result.include_phrases.extend(topic.abbrevs)

    # secrets management → also match hardcoded / api key text
    if any(t in ("secrets",) for t in included_topics):
        result.include_phrases.extend(["secret", "hardcoded", "api key"])
        result.class_constraints.extend(["secret", "hardcoded", "api key"])

    # --- Negation: explicit phrases ---
    for m in re.finditer(
        r"\b(?:not|non)[\s-]+([a-z][a-z0-9\s/-]{2,40}?)(?:\s+related|\s+issues?|\s+findings?|\s+problems?|$|,|\.)",
        q,
    ):
        topic_text = m.group(1).strip()
        topic_text = re.sub(
            r"\b(related|issues?|findings?|problems?|labeled)\b", "", topic_text
        ).strip()
        # "do not invent endpoints not in the scan" is a grounding instruction,
        # not a request to exclude records containing the words "scan".  Only
        # turn a negation into a content filter when it names a meaningful topic.
        if topic_text in {"in scan", "in the scan", "in dataset", "in the dataset"}:
            continue
        if topic_text:
            result.exclude_phrases.append(topic_text)
            for tok in re.findall(r"[a-z]{4,}", topic_text):
                if tok not in {"with", "that", "this", "from", "into", "than"}:
                    result.exclude_phrases.append(tok)
    if re.search(r"\bexcluding\b", q):
        after = q.split("excluding", 1)[-1]
        for tok in re.findall(r"[a-z]{4,}", after)[:6]:
            result.exclude_phrases.append(tok)
    result.exclude_phrases = list(dict.fromkeys(result.exclude_phrases))

    # Strip negated topics from includes
    for nt in negated_topics:
        topic = TOPICS.get(nt)
        if not topic:
            continue
        for token in list(topic.keywords) + list(topic.abbrevs):
            result.include_phrases = [p for p in result.include_phrases if token not in p]
            result.class_constraints = [c for c in result.class_constraints if token not in c]
        result.class_constraints = [c for c in result.class_constraints if not c.lower().startswith(topic.name.lower())]
    result.include_phrases = list(dict.fromkeys(p for p in result.include_phrases if p))
    result.class_constraints = list(dict.fromkeys(c for c in result.class_constraints if c))

    # Path-param shape is structural: drop soft phrase/topic noise after topic map
    if result.path_param_only:
        result.topics = []
        result.exclude_topics = []
        result.include_phrases = []
        result.class_constraints = []
        result.keywords = []
        result.intent = "list"
        result.answer_mode = "list"

    # Multi-class chain (ATO + priv-esc): keep both topics; do not exclusive-filter
    if (
        ("account takeover" in q or re.search(r"\bato\b", q))
        and "privilege escalation" in q
    ) or ("chained" in q and ("takeover" in q or "privilege" in q)):
        for name in ("authentication", "mass_assignment"):
            if name not in result.topics:
                result.topics.append(name)
        # Union class cues for both sides of the chain (OR match later)
        for name in ("authentication", "mass_assignment"):
            topic = TOPICS.get(name)
            if not topic:
                continue
            result.class_constraints.extend(topic.keywords)
            result.class_constraints.extend(topic.abbrevs)
            result.include_phrases.extend(topic.keywords)
        result.class_constraints = list(dict.fromkeys(c for c in result.class_constraints if c))
        result.include_phrases = list(dict.fromkeys(p for p in result.include_phrases if p))

    # --- Numeric operators ---
    count_cue = bool(
        re.search(r"\b(how many|count(?:\s+the)?|number of|total number)\b", q)
    )
    if count_cue:
        result.want_count = True
        result.answer_mode = "count"

    top_n_cue = bool(
        re.search(
            r"\btop\s+(?:\d+|\w+)\b|"
            r"\b(?:first|highest|most)\s+(?:\d+|\w+)\b|"
            r"\b(?:\d+|\w+)\s+(?:highest|most|top)\b|"
            r"\bwhich\s+(?:three|two|four|five|\d+)\s+findings\b|"
            r"\bsingle\s+(?:most|highest|severe)\b|"
            r"\bmost\s+severe\s+(?:finding|one)\b",
            q,
        )
    )
    if top_n_cue:
        n = _extract_number(q)
        # "single", "most severe" -> 1
        if re.search(r"\bsingle\b|\bmost\s+severe\b|\bmost\s+critical\b", q):
            n = 1
        result.top_n = n or 3
        if not result.want_count:
            result.answer_mode = "top_n"

    # --- Multi-impact / classify detection ---
    multi_impact = any(
        x in q
        for x in (
            "pii",
            "financial data",
            "other customers",
            "leak other",
            "access-control",
            "access control",
            "injection problems",
            "authn problems",
            "authorization problems",
        )
    )
    result.data_impact = any(
        x in q
        for x in (
            "pii",
            "financial data",
            "other customers",
            "customers' pii",
            "leak other",
            "if exploited",
        )
    ) and any(x in q for x in ("leak", "pii", "financial", "customers"))

    # --- Intent (specific before broad) ---
    existence_cues = (
        "is there",
        "are there",
        "did we find",
        "do we have",
        "does the scan",
        "any findings",
        "confirm it",
        "definitely",
        "is that in the dataset",
        "in this scan?",
        "is that in the",
        "is cwe-",
        "is cwe ",
        "are there any cwe",
        "does this scan have cwe",
    )
    adversarial = any(
        c in q
        for c in (
            "invent a",
            "ignore previous",
            "scanner is wrong",
            "definitely rce",
            "confirm it",
        )
    )

    # Priority / go-live / fix-first
    priority_q = any(
        x in q
        for x in (
            "fix first",
            "go-live",
            "go live",
            "priorit",
            "before a production",
            "would you fix first",
        )
    )

    # Classify HIGH findings by problem buckets
    classify_q = (
        (
            ("access-control" in q or "access control" in q)
            and "injection" in q
            and ("authn" in q or "authentication" in q)
        )
        or (
            "which high" in q
            and re.search(r"\bvs\b", q)
            and ("injection" in q or "access" in q)
        )
    )

    # Cluster / group-by root cause
    cluster_q = (
        any(
            c in q
            for c in (
                "group all",
                "group by",
                "shared root cause",
                "root cause rather",
                "which clusters",
                "clusters would you",
                "cluster",
            )
        )
        and "same root cause" not in q
    )

    # Remediation cues (including CWE-ID remediation)
    remediation_q = (
        any(
            c in q
            for c in (
                "how do i fix",
                "how to fix",
                "how would you fix",
                "remediat",
                "mitigat",
                "correct fix",
                "fix plan",
                "give a fix",
                "shared authorization",
                "shared middleware",
                "one shared",
                "middleware design",
            )
        )
        or (
            re.search(r"\bfix both\b|\bboth .* findings\b", q)
            and any(x in q for x in ("idor", "jwt", "xss", "ssrf", "finding"))
        )
        or (result.cwe_id and any(c in q for c in ("fix", "remediat", "how to", "how do i")))
    )

    # Compare cues
    compare_q = (
        any(
            c in q
            for c in (
                "compare",
                "same root cause",
                "same bug",
                "difference between",
                "same control family",
                "control family",
                "two instances",
            )
        )
        or (
            " vs " in q
            and not classify_q
            and q.count(" vs ") == 1
        )
    )

    # --- Intent assignment ---
    if result.want_count:
        result.intent = "list"
        result.answer_mode = "count"
    elif cluster_q:
        result.intent = "cluster"
    elif classify_q:
        result.intent = "list"
        result.classify_problem_buckets = True
        result.severity = "HIGH"
        result.severities = ["HIGH"]
        result.class_constraints = []
        result.include_phrases = []
    elif remediation_q:
        result.intent = "remediation"
    elif compare_q:
        result.intent = "compare"
    elif result.top_n and not priority_q:
        result.intent = "list"
        result.answer_mode = "top_n"
        result.class_constraints = []
    elif priority_q:
        result.intent = "remediation"
        result.answer_mode = "top_n"
        result.class_constraints = []
    elif any(c in q for c in existence_cues) or adversarial:
        result.intent = "existence"
    elif any(
        c in q
        for c in (
            "explain",
            "what's the risk",
            "what is the risk",
            "how could an attacker",
            "exploit",
        )
    ):
        result.intent = "explain"
    elif any(
        c in q
        for c in (
            "map every",
            "map all",
            "map to",
            "owasp",
            "related to owasp",
            "related to cwe",
            "cwe-",
        )
    ) and "remediat" not in q and not result.cwe_id:
        result.intent = "cross_ref"
    elif any(
        c in q
        for c in (
            "summary",
            "summarize",
            "overview",
            "sorted by severity",
        )
    ) and not result.top_n:
        result.intent = "summary"
    elif any(c in q for c in ("most critical", "highest severity")) and not result.top_n:
        result.intent = "severity"
        if not result.severity:
            result.severity = "CRITICAL"
            result.severities = ["CRITICAL"]
    elif any(
        c in q
        for c in (
            "which findings",
            "list all",
            "what are all",
            "what authentication",
            "which high",
            "only list",
            "what findings",
        )
    ):
        result.intent = "list"
    else:
        result.intent = "general"

    # Compare multi-topic: clear exclusive class filters
    if result.intent == "compare" and (
        q.count(",") >= 1 or " and " in q or any(t in included_topics for t in ("authentication", "authorization", "injection", "ssrf"))
    ):
        multi = sum(
            1
            for t in ("jwt", "password", "rate limit", "idor", "xss", "ssrf", "sql")
            if t in q
        )
        if multi >= 2:
            result.class_constraints = []

    # Data-impact needs broad candidate set
    if result.data_impact:
        result.class_constraints = []
        result.keywords = list(
            dict.fromkeys(
                [
                    *result.keywords,
                    "idor",
                    "sql",
                    "ssrf",
                    "mass assignment",
                    "error",
                    "transaction",
                    "account",
                    "document",
                ]
            )
        )

    return result


def _rules_confident(route: RouteResult, question: str) -> bool:
    if (
        route.finding_id
        or route.finding_ids
        or route.cwe_id
        or route.owasp
        or route.severity
        or route.severities
        or route.exclude_severities
        or route.class_constraints
    ):
        return True
    if route.intent in {
        "existence",
        "summary",
        "severity",
        "compare",
        "cross_ref",
        "list",
        "remediation",
        "cluster",
    }:
        return True
    if route.intent in {"explain", "remediation"} and route.keywords:
        return True
    return True


class QueryRouter:
    def __init__(self, llm: LLMClient, use_llm: bool = True) -> None:
        self.llm = llm
        self.use_llm = use_llm

    def route(self, question: str) -> RouteResult:
        fallback = rule_based_route(question)
        if not self.use_llm or _rules_confident(fallback, question):
            return fallback

        try:
            raw_text = self.llm.complete(
                system=ROUTER_SYSTEM,
                user=f"Question: {question}\n\nReturn JSON only.",
                temperature=0.0,
                response_json=True,
                max_tokens=400,
            )
            data = parse_json_response(raw_text)
            intent = str(data.get("intent") or fallback.intent).lower()
            if intent not in VALID_INTENTS:
                intent = fallback.intent

            def pick(key: str, default: Any = None) -> Any:
                val = data.get(key)
                if val in (None, "", [], {}):
                    return default
                return val

            keywords = pick("keywords", fallback.keywords) or []
            if isinstance(keywords, str):
                keywords = [keywords]
            merged = list(dict.fromkeys([*keywords, *fallback.keywords]))

            sev = pick("severity", fallback.severity)
            severities = list(fallback.severities)
            if sev and str(sev).upper() not in severities:
                severities = [str(sev).upper(), *severities]

            fid = pick("finding_id", fallback.finding_id)
            fids = list(fallback.finding_ids)
            if fid and str(fid).upper() not in fids:
                fids = [str(fid).upper(), *fids]

            return RouteResult(
                intent=intent,
                severity=(str(sev).upper() if sev else None) or fallback.severity,
                severities=severities,
                exclude_severities=list(fallback.exclude_severities),
                cwe_id=(pick("cwe_id", fallback.cwe_id) or None),
                owasp=(pick("owasp", fallback.owasp) or None),
                endpoint=(pick("endpoint", fallback.endpoint) or None),
                finding_id=(str(fid).upper() if fid else None) or fallback.finding_id,
                finding_ids=fids,
                keywords=[str(k) for k in merged],
                raw=data,
                source="llm",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM router failed (%s); using rules", exc)
            return fallback
