"""Deterministic finding set algebra — no finding-ID packs, no LLM counts.

FilterSpec is filled by the router from language operators (count, top_n,
severity, CWE, endpoint, include/exclude phrases). apply_filters only matches
store text and structured fields.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.retrieval.findings_store import FindingRecord, SEVERITY_ORDER
from app.retrieval.synonyms import expand_keywords
from app.retrieval.taxonomy import TOPICS, keywords_for_topic, topic_names_for_text


@dataclass
class FilterSpec:
    include_severities: list[str] = field(default_factory=list)
    exclude_severities: list[str] = field(default_factory=list)
    include_phrases: list[str] = field(default_factory=list)
    exclude_phrases: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    owasp: str | None = None
    endpoint_substrings: list[str] = field(default_factory=list)
    endpoint_strict: bool = False
    finding_ids: list[str] = field(default_factory=list)
    top_n: int | None = None
    want_count: bool = False
    # count | list | top_n | existence | remediation | explain | compare | cluster | summary | general
    answer_mode: str = "list"
    # Taxonomy topics to include/exclude (resolved to CWEs + keywords)
    include_topics: list[str] = field(default_factory=list)
    exclude_topics: list[str] = field(default_factory=list)
    # Structural: keep findings with {param} style path/endpoint placeholders
    path_param_only: bool = False


def record_blob(rec: FindingRecord) -> str:
    return " ".join(
        [
            rec.title or "",
            rec.description or "",
            rec.endpoint or "",
            rec.cwe_id or "",
            rec.owasp_category or "",
            rec.remediation_hint or "",
            rec.parameter or "",
            rec.method or "",
        ]
    ).lower()


def _phrase_matches(blob: str, phrase: str) -> bool:
    p = (phrase or "").lower().strip()
    if len(p) < 2:
        return False
    # Multi-word phrases: substring OK
    if " " in p:
        return p in blob
    # CWE-79 must not match CWE-798; use token boundaries (hyphen allowed in token)
    if re.match(r"^cwe-?\d+$", p):
        num = re.sub(r"\D", "", p)
        return bool(
            re.search(rf"(?<![a-z0-9])cwe-?{num}(?![0-9])", blob, flags=re.I)
        )
    # other hyphenated tokens (e.g. cross-site): boundary-aware
    if "-" in p:
        return bool(
            re.search(rf"(?<![a-z0-9]){re.escape(p)}(?![a-z0-9])", blob)
        )
    # whole-token-ish match for unigrams
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(p)}(?![a-z0-9])", blob))


def matches_any_phrase(rec: FindingRecord, phrases: list[str]) -> bool:
    if not phrases:
        return True
    blob = record_blob(rec)
    expanded = expand_keywords(list(phrases))
    return any(_phrase_matches(blob, p) for p in expanded)


def matches_all_required(rec: FindingRecord, phrases: list[str]) -> bool:
    """OR across phrases (any include phrase is enough)."""
    return matches_any_phrase(rec, phrases)


def apply_filters(
    findings: list[FindingRecord],
    spec: FilterSpec,
) -> list[FindingRecord]:
    """Apply FilterSpec as AND of dimensions; then severity-sort; optional top_n."""
    out: list[FindingRecord] = list(findings)

    # Explicit IDs are exact — do not AND soft phrases/topics (avoids false
    # empties when abbreviations leak into keywords, e.g. rce⊂resources).
    id_locked = bool(spec.finding_ids)
    if id_locked:
        want = {x.upper() for x in spec.finding_ids}
        out = [f for f in out if f.finding_id.upper() in want]

    if spec.include_severities:
        sevs = {s.upper() for s in spec.include_severities}
        out = [f for f in out if (f.severity or "").upper() in sevs]

    if spec.exclude_severities:
        sevs = {s.upper() for s in spec.exclude_severities}
        out = [f for f in out if (f.severity or "").upper() not in sevs]

    if spec.cwe_ids:
        def cwe_ok(f: FindingRecord) -> bool:
            fc = (f.cwe_id or "").upper().replace("CWE", "CWE-").replace("CWE--", "CWE-")
            for c in spec.cwe_ids:
                num = re.sub(r"\D", "", c)
                if num and num in (f.cwe_id or ""):
                    return True
                if c.upper() in fc or c.upper() in (f.cwe_id or "").upper():
                    return True
            return False

        out = [f for f in out if cwe_ok(f)]

    if spec.owasp:
        o = spec.owasp.lower()
        out = [f for f in out if o in (f.owasp_category or "").lower()]

    if spec.endpoint_substrings:
        subs = [s.lower() for s in spec.endpoint_substrings if s]
        if spec.endpoint_strict:
            out = [
                f
                for f in out
                if any(s in (f.endpoint or "").lower() for s in subs)
            ]
        else:
            out = [
                f
                for f in out
                if any(
                    s in (f.endpoint or "").lower()
                    or s in (f.title or "").lower()
                    or s in (f.description or "").lower()
                    for s in subs
                )
            ]

    if spec.include_phrases and not id_locked:
        out = [f for f in out if matches_all_required(f, spec.include_phrases)]

    if spec.exclude_phrases and not id_locked:
        out = [f for f in out if not matches_any_phrase(f, spec.exclude_phrases)]

    if spec.path_param_only:
        out = [
            f
            for f in out
            if "{" in (f.endpoint or "") or "{" in (f.parameter or "")
        ]

    if spec.include_topics and not id_locked:
        topic_phrases: list[str] = []
        topic_cwes: list[str] = []
        for t in spec.include_topics:
            topic_phrases.extend(keywords_for_topic(t))
            topic_cwes.extend(TOPICS.get(t, object()).cwes or ())
        topic_cwes = [c for c in topic_cwes if c]
        # Phrase match OR CWE match — many sample findings omit CWE fields
        def topic_ok(f: FindingRecord) -> bool:
            if topic_phrases and matches_any_phrase(f, topic_phrases):
                return True
            if topic_cwes:
                for c in topic_cwes:
                    num = re.sub(r"\D", "", c)
                    if num and num in (f.cwe_id or ""):
                        return True
            return False

        if topic_phrases or topic_cwes:
            out = [f for f in out if topic_ok(f)]

    if spec.exclude_topics and not id_locked:
        exclude_phrases: list[str] = []
        exclude_cwes: list[str] = []
        for t in spec.exclude_topics:
            exclude_phrases.extend(keywords_for_topic(t))
            exclude_cwes.extend(TOPICS.get(t, object()).cwes or ())
        exclude_cwes = [c for c in exclude_cwes if c]

        def excluded_by_topic(f: FindingRecord) -> bool:
            if exclude_phrases and matches_any_phrase(f, exclude_phrases):
                return True
            for c in exclude_cwes:
                num = re.sub(r"\D", "", c)
                if num and num in (f.cwe_id or ""):
                    return True
            return False

        out = [f for f in out if not excluded_by_topic(f)]

    out = sorted(
        out,
        key=lambda r: (
            SEVERITY_ORDER.get((r.severity or "").upper(), 99),
            r.finding_id,
        ),
    )

    if spec.top_n is not None and spec.top_n > 0:
        out = out[: int(spec.top_n)]

    return out


def route_to_filter_spec(route: object) -> FilterSpec:
    """Build FilterSpec from a RouteResult-like object (duck-typed)."""
    sevs = list(getattr(route, "severities", None) or [])
    if not sevs and getattr(route, "severity", None):
        sevs = [route.severity]
    excl = list(getattr(route, "exclude_severities", None) or [])
    cwes: list[str] = []
    if getattr(route, "cwe_id", None):
        cwes.append(route.cwe_id)
    cwes.extend(getattr(route, "cwe_ids", None) or [])
    include_phrases = list(getattr(route, "include_phrases", None) or [])
    # class_constraints historically used as include phrases
    include_phrases.extend(getattr(route, "class_constraints", None) or [])
    include_phrases.extend(getattr(route, "keywords", None) or [])
    exclude_phrases = list(getattr(route, "exclude_phrases", None) or [])
    include_topics = list(getattr(route, "topics", None) or [])
    exclude_topics = list(getattr(route, "exclude_topics", None) or [])
    endpoints = list(getattr(route, "endpoint_substrings", None) or [])
    if getattr(route, "endpoint", None):
        endpoints.append(route.endpoint)

    mode = getattr(route, "answer_mode", None) or getattr(route, "intent", None) or "list"
    want_count = bool(getattr(route, "want_count", False))
    top_n = getattr(route, "top_n", None)
    if want_count:
        mode = "count"
    elif top_n and mode in {"list", "summary", "severity", "general", "remediation"}:
        # top_n list mode unless remediate synthesis requested with go-live template
        if mode != "remediation" or getattr(route, "priority_justify", False):
            pass
        if getattr(route, "answer_mode", None) == "top_n" or (
            top_n and mode in {"list", "summary", "severity", "general"}
        ):
            mode = "top_n"

    return FilterSpec(
        include_severities=[s.upper() for s in sevs],
        exclude_severities=[s.upper() for s in excl],
        path_param_only=bool(getattr(route, "path_param_only", False)),
        include_phrases=list(dict.fromkeys([p for p in include_phrases if p])),
        exclude_phrases=list(dict.fromkeys([p for p in exclude_phrases if p])),
        cwe_ids=list(dict.fromkeys(cwes)),
        owasp=getattr(route, "owasp", None),
        endpoint_substrings=list(dict.fromkeys([e for e in endpoints if e])),
        endpoint_strict=bool(getattr(route, "endpoint_strict", False)),
        finding_ids=list(getattr(route, "finding_ids", None) or []),
        top_n=top_n,
        want_count=want_count,
        answer_mode=str(mode),
        include_topics=list(dict.fromkeys([t for t in include_topics if t])),
        exclude_topics=list(dict.fromkeys([t for t in exclude_topics if t])),
    )
