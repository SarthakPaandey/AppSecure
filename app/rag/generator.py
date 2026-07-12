"""Grounded answer generation: structured, LLM, and synthesis templates."""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.clients.llm import LLMClient, parse_json_response
from app.rag.prompts import ANSWER_SYSTEM, build_answer_user_prompt
from app.retrieval.findings_store import FindingRecord, SEVERITY_ORDER
from app.retrieval.taxonomy import TOPICS, topic_names_for_text
from app.retrieval.vector_store import VectorHit

logger = logging.getLogger(__name__)

# Intents answered deterministically from the store (no LLM JSON).
STRUCTURED_ONLY_INTENTS = frozenset({"summary", "list", "severity", "cross_ref", "cluster"})


@dataclass
class GenerationResult:
    answer: str
    findings_referenced: list[str] = field(default_factory=list)
    reference_ids: list[str] = field(default_factory=list)
    abstained: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


class AnswerGenerator:
    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def generate(
        self,
        *,
        question: str,
        intent: str,
        findings: list[FindingRecord],
        knowledge_hits: list[VectorHit],
        want_parameter: bool = False,
        want_endpoint: bool = False,
        top_n: int | None = None,
        classify_problem_buckets: bool = False,
        data_impact: bool = False,
        want_count: bool = False,
        use_dynamic_synthesis: bool = False,
    ) -> GenerationResult:
        q_l = (question or "").lower()

        # --- Path A: structured / cluster (no LLM JSON) ---
        if intent == "cluster" and findings:
            out = self._template_cluster(findings)
            out.raw = {"source": "structured"}
            return out

        # Deterministic count from filtered set only (never invent N)
        if want_count:
            out = self._template_count(findings, question=question)
            out.raw = {"source": "structured"}
            return out

        # HIGH findings → access-control / injection / authn (store fields only)
        if classify_problem_buckets and findings:
            out = self._template_problem_buckets(findings, severity="HIGH")
            out.raw = {"source": "structured"}
            return out

        # Top-N inventory or go-live justification
        if top_n and findings:
            justify = any(
                x in q_l
                for x in (
                    "fix first",
                    "go-live",
                    "go live",
                    "priorit",
                    "production",
                    "why",
                )
            ) or intent == "remediation"
            if justify:
                out = self._template_priority_top_n(findings, n=top_n)
            else:
                out = self._template_top_n(findings, n=top_n)
            out.raw = {"source": "structured"}
            return out

        # Empty filtered set for inventory intents
        if not findings and intent in {
            "list",
            "summary",
            "severity",
            "existence",
            "cross_ref",
        }:
            out = abstention_response(question, intent)
            out.raw = {"source": "abstain"}
            return out

        # Cross-customer PII / financial impact shortlist
        if data_impact and findings and not use_dynamic_synthesis:
            impact = [f for f in findings if self._is_data_impact_finding(f)]
            if impact:
                out = self._template_data_impact(impact)
                out.raw = {"source": "structured"}
                return out

        if intent in STRUCTURED_ONLY_INTENTS and findings:
            out = self._deterministic_summary(
                findings,
                intent=intent,
                question=question,
                want_parameter=want_parameter,
                want_endpoint=want_endpoint,
            )
            out.raw = {"source": "structured"}
            return out

        if not findings:
            out = abstention_response(question, intent)
            out.raw = {"source": "abstain"}
            return out

        if intent == "existence":
            out = self._existence_yes(
                findings,
                question,
                want_parameter=want_parameter or "parameter" in question.lower(),
                want_endpoint=want_endpoint or "endpoint" in question.lower(),
            )
            out.raw = {"source": "structured"}
            return out

        # Offline / dynamic-off: generic compare from store rows (no demo-specific prose)
        if not use_dynamic_synthesis and intent == "compare" and findings:
            out = self._template_compare(findings, question=question)
            out.raw = {"source": "structured"}
            return out

        # --- Path B: LLM for explain / remediation / compare / general ---
        data = self._llm_json_with_retry(
            question=question,
            intent=intent,
            findings=findings,
            knowledge_hits=knowledge_hits,
        )
        if data is not None:
            answer = str(data.get("answer") or "").strip()
            findings_ref = data.get("findings_referenced") or []
            ref_ids = data.get("reference_ids") or []
            if isinstance(findings_ref, str):
                findings_ref = [findings_ref]
            if isinstance(ref_ids, str):
                ref_ids = [ref_ids]
            abstained = bool(data.get("abstained", False))
            if answer:
                if not findings_ref and not abstained:
                    findings_ref = [f.finding_id for f in findings[:8]]
                data = dict(data)
                data["source"] = "llm"
                return GenerationResult(
                    answer=answer,
                    findings_referenced=[str(x) for x in findings_ref],
                    reference_ids=[str(x) for x in ref_ids],
                    abstained=abstained,
                    raw=data,
                )

        # --- Path C: synthesis-shaped template fallback (binds endpoint/param from rows) ---
        logger.warning("LLM JSON unavailable after retry; using template answer from findings store")
        out = self._template_explain(findings, question=question, intent=intent)
        out.raw = {"source": "template"}
        return out

    def _llm_json_with_retry(
        self,
        *,
        question: str,
        intent: str,
        findings: list[FindingRecord],
        knowledge_hits: list[VectorHit],
    ) -> dict[str, Any] | None:
        cap = 6 if intent in {"compare", "list", "summary", "cluster", "remediation"} else 4
        findings_blocks = [f.to_prompt_block() for f in findings[:cap]]
        knowledge_blocks = []
        for hit in knowledge_hits[:3]:
            title = hit.metadata.get("title") or hit.id
            source = hit.metadata.get("source_id") or hit.id
            text = hit.text if len(hit.text) <= 700 else hit.text[:700] + "…"
            knowledge_blocks.append(f"[{source}] {title}\n{text}")

        user = build_answer_user_prompt(
            question=question,
            findings_blocks=findings_blocks,
            knowledge_blocks=knowledge_blocks,
            intent=intent,
        )

        broken = ""
        try:
            raw = self.llm.complete(
                system=ANSWER_SYSTEM,
                user=user,
                temperature=0.0,
                response_json=True,
                max_tokens=1000,
            )
            broken = raw
            return parse_json_response(raw)
        except Exception as exc1:  # noqa: BLE001
            logger.warning("LLM JSON attempt 1 failed: %s", exc1)

        try:
            repair_user = (
                "Convert the following into ONE valid JSON object with keys exactly:\n"
                "answer (string), findings_referenced (array of strings), "
                "reference_ids (array of strings), abstained (boolean).\n"
                "Use only these finding IDs if needed: "
                + ", ".join(f.finding_id for f in findings[:8])
                + "\n\nBroken model output:\n"
                + (
                    broken[:2500]
                    if broken
                    else "(empty — write a short grounded answer from finding IDs only)"
                )
                + "\n\nAlso answer this question using only those findings:\n"
                + question
            )
            raw2 = self.llm.complete(
                system=(
                    "You output valid JSON only. No markdown fences. No extra keys. "
                    "Keep answer under 200 words. For remediation, describe a shared fix "
                    "when multiple findings share a control family."
                ),
                user=repair_user,
                temperature=0.0,
                response_json=True,
                max_tokens=800,
            )
            return parse_json_response(raw2)
        except Exception as exc2:  # noqa: BLE001
            logger.warning("LLM JSON attempt 2 (repair) failed: %s", exc2)
            return None

    def _fmt_ep(self, f: FindingRecord) -> str:
        if f.endpoint.upper().startswith(f.method.upper()):
            return f.endpoint
        return f"{f.method} {f.endpoint}".strip()

    def _existence_yes(
        self,
        findings: list[FindingRecord],
        question: str,
        *,
        want_parameter: bool = False,
        want_endpoint: bool = True,
    ) -> GenerationResult:
        lines = [
            f"Yes — the scan contains {len(findings)} matching finding(s):",
            "",
        ]
        for f in findings:
            ep = self._fmt_ep(f)
            detail = f"({ep}; {f.cwe_id}; {f.owasp_category}"
            if want_parameter or "parameter" in question.lower():
                detail += f"; parameter=`{f.parameter}`"
            detail += ")"
            lines.append(
                f"- **{f.severity}** `{f.finding_id}`: {f.title} {detail}"
            )
        return GenerationResult(
            answer="\n".join(lines),
            findings_referenced=[f.finding_id for f in findings],
            abstained=False,
        )

    def _template_count(
        self, findings: list[FindingRecord], *, question: str = ""
    ) -> GenerationResult:
        n = len(findings)
        q = (question or "").lower()
        label = "matching"
        for sev in ("critical", "high", "medium", "low"):
            if sev in q:
                label = sev.upper()
                break
        lines = [
            f"There are **{n}** {label} finding(s) in this scan"
            + (":" if n else " (none matched your filter)."),
        ]
        if n:
            lines.append("")
            for f in sort_findings(findings):
                lines.append(
                    f"- **{f.severity}** `{f.finding_id}`: {f.title} "
                    f"({self._fmt_ep(f)}; {f.cwe_id})"
                )
        return GenerationResult(
            answer="\n".join(lines).strip(),
            findings_referenced=[f.finding_id for f in findings],
            abstained=False,
        )

    def _template_top_n(
        self, findings: list[FindingRecord], *, n: int
    ) -> GenerationResult:
        top = sort_findings(findings)[:n]
        lines = [
            f"**Top {len(top)}** highest-severity finding(s) from the scan:",
            "",
        ]
        for i, f in enumerate(top, 1):
            lines.append(
                f"{i}. **{f.severity}** `{f.finding_id}`: {f.title} "
                f"({self._fmt_ep(f)}; {f.cwe_id})"
            )
        return GenerationResult(
            answer="\n".join(lines).strip(),
            findings_referenced=[f.finding_id for f in top],
            abstained=False,
        )

    @staticmethod
    def _problem_bucket(f: FindingRecord) -> str:
        """Map a finding to access-control | injection | authn | other from store fields."""
        cwe = (f.cwe_id or "").upper()
        owasp = (f.owasp_category or "").upper()
        blob = f"{f.title or ''} {f.description or ''} {f.remediation_hint or ''}".lower()

        injection_cwes = set(TOPICS["injection"].cwes)
        authn_cwes = set(TOPICS["authentication"].cwes)
        authz_cwes = set(TOPICS["authorization"].cwes)
        injection_kw = set(TOPICS["injection"].keywords) | set(TOPICS["injection"].abbrevs)
        authn_kw = set(TOPICS["authentication"].keywords)
        authz_kw = set(TOPICS["authorization"].keywords) | set(TOPICS["authorization"].abbrevs)

        # Injection / server-side input abuse (incl. SSRF for this taxonomy)
        if cwe in injection_cwes or any(k in blob for k in injection_kw):
            return "injection"
        # Authn / session
        if cwe in authn_cwes or any(k in blob for k in authn_kw) or owasp.startswith("A07"):
            return "authn"
        # Access control / authz
        if cwe in authz_cwes or any(k in blob for k in authz_kw) or owasp.startswith("A01"):
            return "access-control"
        return "other"

    def _template_problem_buckets(
        self, findings: list[FindingRecord], *, severity: str = "HIGH"
    ) -> GenerationResult:
        """Classify HIGH (or filtered) findings by problem family using store CWE/title only."""
        sev = (severity or "HIGH").upper()
        pool = [
            f
            for f in findings
            if (f.severity or "").upper() == sev
            or not severity  # if no filter, keep all passed in
        ]
        if not pool:
            pool = [f for f in findings if (f.severity or "").upper() == sev]
        # Prefer explicit severity filter on input list
        pool = [f for f in findings if (f.severity or "").upper() == sev] or list(findings)

        buckets: dict[str, list[FindingRecord]] = {
            "access-control": [],
            "injection": [],
            "authn": [],
            "other": [],
        }
        for f in sort_findings(pool):
            buckets[self._problem_bucket(f)].append(f)

        labels = {
            "access-control": "Access-control problems",
            "injection": "Injection / server-side request problems",
            "authn": "Authentication / session problems",
            "other": "Other HIGH findings",
        }
        lines = [
            f"**{sev} findings** classified by problem family "
            f"(using each finding's stored severity + CWE/title — not guessed):",
            "",
        ]
        refs: list[str] = []
        for key in ("access-control", "injection", "authn", "other"):
            items = buckets[key]
            lines.append(f"### {labels[key]}")
            if not items:
                lines.append(f"- *(none at {sev} in this scan)*")
            else:
                for f in items:
                    lines.append(
                        f"- **{f.severity}** `{f.finding_id}`: {f.title} "
                        f"({self._fmt_ep(f)}; **{f.cwe_id}**; {f.owasp_category})"
                    )
                    refs.append(f.finding_id)
            lines.append("")

        return GenerationResult(
            answer="\n".join(lines).strip(),
            findings_referenced=refs,
            abstained=False,
        )

    def _template_priority_top_n(
        self, findings: list[FindingRecord], *, n: int = 3
    ) -> GenerationResult:
        """Pick exactly n highest-severity findings with a short fix-first rationale."""
        ordered = sort_findings(findings)
        # Prefer CRITICALs first when present
        crits = [f for f in ordered if (f.severity or "").upper() == "CRITICAL"]
        rest = [f for f in ordered if (f.severity or "").upper() != "CRITICAL"]
        top: list[FindingRecord] = []
        for f in crits + rest:
            if f.finding_id not in {x.finding_id for x in top}:
                top.append(f)
            if len(top) >= n:
                break

        lines = [
            f"**Top {len(top)} findings to fix first** before production go-live "
            f"(ordered by severity, then business impact):",
            "",
        ]
        for i, f in enumerate(top, 1):
            why = self._priority_why(f)
            lines.append(
                f"{i}. **{f.severity}** `{f.finding_id}`: {f.title} "
                f"({self._fmt_ep(f)}; {f.cwe_id})"
            )
            lines.append(f"   - **Why first:** {why}")
            if f.remediation_hint:
                lines.append(f"   - **Fix:** {f.remediation_hint}")
            lines.append("")

        return GenerationResult(
            answer="\n".join(lines).strip(),
            findings_referenced=[f.finding_id for f in top],
            abstained=False,
        )

    @staticmethod
    def _priority_why(f: FindingRecord) -> str:
        """Why this row is high priority — prefer store fields, not product prose."""
        sev = (f.severity or "").upper() or "UNKNOWN"
        cwe = (f.cwe_id or "").strip() or "CWE n/a"
        ep = f"{(f.method or '').strip()} {(f.endpoint or '').strip()}".strip() or "endpoint n/a"
        param = (f.parameter or "").strip()
        title = (f.title or "").strip() or f.finding_id
        hint = (f.remediation_hint or "").strip()
        bits = [f"{sev} · {cwe} on `{ep}`"]
        if param and param.upper() != "N/A":
            bits.append(f"param `{param}`")
        bits.append(title)
        if hint:
            bits.append(f"hint: {hint}")
        return " — ".join(bits)

    @staticmethod
    def _is_data_impact_finding(f: FindingRecord) -> bool:
        cwe = (f.cwe_id or "").upper()
        blob = f"{f.title or ''} {f.description or ''} {f.endpoint or ''}".lower()
        impact_cwes = set(TOPICS["data_exposure"].cwes) | set(TOPICS["injection"].cwes) | set(TOPICS["authorization"].cwes)
        impact_kw = (
            set(TOPICS["data_exposure"].keywords)
            | set(TOPICS["injection"].keywords)
            | set(TOPICS["authorization"].abbrevs)
        )
        if cwe in impact_cwes:
            return True
        return any(k in blob for k in impact_kw)

    def _template_data_impact(self, findings: list[FindingRecord]) -> GenerationResult:
        ordered = sort_findings(findings)
        lines = [
            "Findings that can enable **cross-user / sensitive data exposure** "
            "(or access that leads there), ordered by severity:",
            "",
        ]
        for f in ordered:
            impact = self._data_impact_note(f)
            lines.append(
                f"- **{f.severity}** `{f.finding_id}`: {f.title} "
                f"({self._fmt_ep(f)}; param=`{f.parameter}`; {f.cwe_id})"
            )
            lines.append(f"  - **Impact path:** {impact}")
            if f.description:
                lines.append(f"  - **Evidence summary:** {f.description}")
        return GenerationResult(
            answer="\n".join(lines).strip(),
            findings_referenced=[f.finding_id for f in ordered],
            abstained=False,
        )

    @staticmethod
    def _data_impact_note(f: FindingRecord) -> str:
        """Pattern-level impact from CWE/title — no product-specific resources."""
        cwe = (f.cwe_id or "").upper()
        blob = f"{f.title or ''} {f.description or ''}".lower()
        notes = {
            "CWE-639": "Horizontal access to another principal's objects (BOLA/IDOR).",
            "CWE-89": "Query injection can read or alter rows the caller should not see.",
            "CWE-918": (
                "Server-side URL fetch can reach internal services or cloud metadata; "
                "may pivot to sensitive stores."
            ),
            "CWE-915": "Mass assignment / property control can escalate privileges or widen data access.",
            "CWE-209": "Verbose errors leak internals useful for further data-targeted attacks.",
            "CWE-200": "Information exposure increases attack surface against sensitive data.",
        }
        if cwe in notes:
            return notes[cwe]
        if "idor" in blob or "bola" in blob:
            return notes["CWE-639"]
        if "sql" in blob:
            return notes["CWE-89"]
        if "ssrf" in blob:
            return notes["CWE-918"]
        if "mass assignment" in blob:
            return notes["CWE-915"]
        if "error" in blob or "stack" in blob:
            return notes["CWE-209"]
        # Fall back to row text rather than inventing product context
        if f.remediation_hint:
            return f"Store remediation hint: {f.remediation_hint}"
        return f"See finding description for impact: {(f.description or f.title or '')[:180]}"

    def _template_compare(
        self, findings: list[FindingRecord], *, question: str = ""
    ) -> GenerationResult:
        """Compare retrieved findings using store fields only (no sample-specific prose)."""
        ordered = sort_findings(findings)
        families = [self._control_family(f) for f in ordered[:8]]
        unique = list(dict.fromkeys(families))
        same_broad = len(unique) == 1
        lines = [
            (
                "**Same broad control family, different specific controls.**"
                if same_broad and len(ordered) >= 2
                else (
                    "**Related findings, different control families.**"
                    if len(unique) > 1
                    else "**Comparison of retrieved findings.**"
                )
            ),
            "",
            "### Findings (from scan store)",
        ]
        for f in ordered[:8]:
            param = f"`{f.parameter}`" if f.parameter and f.parameter != "N/A" else "n/a"
            lines.append(
                f"- **{f.severity}** `{f.finding_id}`: {f.title} "
                f"({self._fmt_ep(f)}; param={param}; {f.cwe_id or 'CWE n/a'}) — "
                f"family: {self._control_family(f)}"
            )
        lines.extend(
            [
                "",
                "### How they relate",
                (
                    f"- **Shared family:** {unique[0]}. They are not three unrelated domains, "
                    "but they are **not the same bug** — each needs its own control."
                    if same_broad and unique
                    else f"- **Families present:** {', '.join(unique)}."
                ),
                "- **Different controls:** fix each finding’s root cause (title/CWE/remediation "
                "from the row), not a single shared patch unless the family truly unifies them.",
                "- Bind remediation to **endpoint + parameter** on each row; do not invent fields.",
            ]
        )
        return GenerationResult(
            answer="\n".join(lines).strip(),
            findings_referenced=[f.finding_id for f in ordered[:8]],
            abstained=False,
        )

    def _template_cluster(self, findings: list[FindingRecord]) -> GenerationResult:
        """Group findings by control family / OWASP+CWE — not by severity alone."""
        buckets: dict[str, list[FindingRecord]] = defaultdict(list)
        for f in findings:
            family = self._control_family(f)
            buckets[family].append(f)

        # Sort families by highest severity inside
        def fam_key(name: str) -> tuple:
            items = buckets[name]
            best = min(SEVERITY_ORDER.get(x.severity.upper(), 99) for x in items)
            return (best, name)

        lines = [
            "Findings grouped by **shared root-cause / control family** "
            "(not only by severity):",
            "",
        ]
        for family in sorted(buckets.keys(), key=fam_key):
            items = sort_findings(buckets[family])
            lines.append(f"### {family} ({len(items)})")
            for f in items:
                lines.append(
                    f"- **{f.severity}** `{f.finding_id}`: {f.title} "
                    f"({self._fmt_ep(f)}; {f.cwe_id})"
                )
            lines.append("")

        return GenerationResult(
            answer="\n".join(lines).strip(),
            findings_referenced=[f.finding_id for f in findings],
            abstained=False,
        )

    @staticmethod
    def _control_family(f: FindingRecord) -> str:
        title = (f.title or "").lower()
        owasp = (f.owasp_category or "").upper()
        cwe = (f.cwe_id or "").upper()
        blob = f"{title} {f.description or ''}".lower()

        family_map = [
            (("authorization",), "Broken object-level authorization (IDOR/BOLA)"),
            (("authentication",), "Authentication / session (JWT & identity)"),
            (("sql_injection",), "Injection (SQL)"),
            (("xss",), "Injection (XSS)"),
            (("ssrf",), "SSRF / server-side request abuse"),
            (("mass_assignment",), "Mass assignment / object property control"),
            (("file_upload",), "File upload / untrusted content"),
            (("cryptographic",), "Transport / security misconfiguration"),
            (("graphql",), "API surface exposure (GraphQL)"),
            (("secrets",), "Secrets management"),
        ]
        for topic_names, label in family_map:
            topic = TOPICS.get(topic_names[0])
            if not topic:
                continue
            cwes = set(topic.cwes)
            kws = set(topic.keywords) | set(topic.abbrevs)
            if cwe in cwes or any(k in blob for k in kws):
                return label

        # Password/rate-limiting still auth hardening even if not JWT
        if "password" in blob or "rate limit" in blob or "brute" in blob:
            return "Authentication hardening (passwords & rate limits)"

        if owasp.startswith("A01"):
            return "Access control (OWASP A01)"
        if owasp.startswith("A07"):
            return "Identification & authentication failures (A07)"
        if owasp.startswith("A03"):
            return "Injection family (A03)"
        return f"Other ({owasp or cwe or 'uncategorized'})"

    def _template_explain(
        self,
        findings: list[FindingRecord],
        *,
        question: str,
        intent: str,
    ) -> GenerationResult:
        """Synthesis-shaped fallback when LLM JSON is unavailable."""
        q = (question or "").lower()
        parts: list[str] = []

        if intent == "remediation" and len(findings) >= 2:
            families = {self._control_family(f) for f in findings}
            if len(families) == 1:
                family = next(iter(families))
                parts.append(
                    f"**Shared control family** (`{family}`) — apply a consistent fix "
                    "pattern across the endpoints below; use each row's remediation hint."
                )
                parts.append("")
                # Union of store remediation hints only (no canned product prose)
                hints = []
                for f in findings[:8]:
                    h = (f.remediation_hint or "").strip()
                    if h and h not in hints:
                        hints.append(h)
                if hints:
                    parts.append("**Remediation hints from the scan store:**")
                    for h in hints:
                        parts.append(f"- {h}")
                    parts.append("")
                parts.append("**Findings covered:**")
            else:
                parts.append(
                    "Remediation guidance (multiple control families — fix per family "
                    "using each finding's store fields):"
                )
                parts.append("")
        elif intent == "compare":
            parts.append(
                "**Comparison** (shared root cause vs different resources/controls):"
            )
            parts.append("")
            families = {self._control_family(f) for f in findings}
            if len(families) == 1:
                parts.append(
                    f"These findings share the same control family: **{next(iter(families))}**. "
                    "They may be the same bug pattern on different resources/endpoints."
                )
            else:
                parts.append(
                    "These findings span **different** control families "
                    f"({', '.join(sorted(families))}) — related at a high level but not "
                    "the same root fix."
                )
            parts.append("")
        elif intent == "remediation":
            parts.append(
                "Remediation guidance based on **scan store fields** "
                "(endpoint, parameter, remediation_hint):"
            )
            parts.append("")
        else:
            parts.append(
                "Explanation based on **retrieved finding rows** "
                "(no assumed product paths or parameters):"
            )
            parts.append("")

        for f in findings[:5]:
            parts.append(f"### {f.finding_id}: {f.title}")
            parts.append(f"- **Severity:** {f.severity}")
            parts.append(f"- **Endpoint:** {self._fmt_ep(f)}")
            parts.append(f"- **Parameter:** `{f.parameter}`")
            parts.append(f"- **CWE / OWASP:** {f.cwe_id} · {f.owasp_category}")
            parts.append(f"- **What was found:** {f.description}")
            if f.remediation_hint:
                parts.append(f"- **Remediation (from store):** {f.remediation_hint}")
            parts.append("")

        return GenerationResult(
            answer="\n".join(parts).strip(),
            findings_referenced=[f.finding_id for f in findings],
            abstained=False,
            raw={"source": "template_fallback"},
        )

    def _deterministic_summary(
        self,
        findings: list[FindingRecord],
        *,
        intent: str = "list",
        question: str = "",
        want_parameter: bool = False,
        want_endpoint: bool = False,
    ) -> GenerationResult:
        """User-facing structured answer from the findings store."""
        n = len(findings)
        q = (question or "").lower()
        show_param = want_parameter or "parameter" in q
        show_ep = want_endpoint or "endpoint" in q or intent in {"cross_ref", "list", "severity"}

        if intent == "cross_ref":
            header = (
                f"Based on the scan data, {n} finding(s) match your filter "
                f"(ordered by severity CRITICAL → LOW):"
            )
        elif intent == "severity":
            header = f"Highest-priority finding(s) from the scan ({n}):"
        elif intent == "summary":
            header = (
                f"Scan findings summary ({n} finding(s)), ordered by severity "
                f"(CRITICAL > HIGH > MEDIUM > LOW):"
            )
        else:
            header = (
                f"Matching finding(s) from the scan ({n}), ordered by severity "
                f"(CRITICAL > HIGH > MEDIUM > LOW):"
            )

        lines = [header, ""]
        for f in findings:
            ep = self._fmt_ep(f)
            meta_bits = []
            if show_ep:
                meta_bits.append(ep)
            if show_param:
                meta_bits.append(f"parameter=`{f.parameter}`")
            meta_bits.extend([f.cwe_id, f.owasp_category])
            meta = "; ".join(x for x in meta_bits if x)
            lines.append(
                f"- **{f.severity}** `{f.finding_id}`: {f.title} ({meta})"
            )
            if intent in {"list", "cross_ref", "severity"} and f.remediation_hint:
                lines.append(f"  - Remediation hint: {f.remediation_hint}")

        return GenerationResult(
            answer="\n".join(lines),
            findings_referenced=[f.finding_id for f in findings],
            reference_ids=[],
            abstained=False,
            raw={"source": "structured_store"},
        )


def sort_findings(findings: list[FindingRecord]) -> list[FindingRecord]:
    return sorted(
        findings,
        key=lambda r: (SEVERITY_ORDER.get(r.severity.upper(), 99), r.finding_id),
    )


def abstention_response(question: str, intent: str) -> GenerationResult:
    q = question.lower()
    if intent == "existence" or any(
        x in q for x in ("is there", "are there", "rce", "remote code")
    ):
        answer = (
            "No matching findings were found in the ingested scan data for this question. "
            "In particular, this scan does not contain evidence of the vulnerability type "
            "you asked about (for example, remote code execution). "
            "I will not invent findings, endpoints, or severities that are not in the dataset."
        )
    else:
        answer = (
            "No matching findings were found in the ingested scan data for this question. "
            "I will not invent vulnerabilities, endpoints, or finding IDs that are not present "
            f"in the dataset. (intent={intent})"
        )
    return GenerationResult(
        answer=answer,
        findings_referenced=[],
        reference_ids=[],
        abstained=True,
    )
