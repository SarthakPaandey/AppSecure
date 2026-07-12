"""Structured query plan from the semantic planner (Pydantic)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

IntentLit = Literal[
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
]

AnswerModeLit = Literal[
    "count",
    "list",
    "top_n",
    "existence",
    "explain",
    "remediation",
    "compare",
    "cluster",
    "summary",
]

ExecutionLit = Literal[
    "structured",
    "hybrid",
    "abstain",
    "refuse",
]


class QueryPlan(BaseModel):
    """LLM-extracted intent + filter slots (never invents store rows).

    Planner is a constrained interpreter for ambiguous questions only.
    It must not produce final answers. Optional ``in_scope`` / ``execution``
    guide the orchestrator; explicit structural rules always win on merge.
    """

    intent: IntentLit = "general"
    answer_mode: AnswerModeLit | None = None
    include_severities: list[str] = Field(default_factory=list)
    exclude_severities: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    owasp: str | None = None
    endpoint_substrings: list[str] = Field(default_factory=list)
    endpoint_strict: bool = False
    include_topics: list[str] = Field(default_factory=list)
    exclude_topics: list[str] = Field(default_factory=list)
    include_phrases: list[str] = Field(default_factory=list)
    exclude_phrases: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    top_n: int | None = None
    want_count: bool = False
    want_parameter: bool = False
    want_endpoint: bool = False
    confidence: float = 0.5
    rationale: str = ""
    # Scope: high-conf false → refuse; low-conf / missing → fail open to retrieve
    in_scope: bool = True
    # Optional execution hint (orchestrator may ignore)
    execution: ExecutionLit | None = None

    @field_validator("include_severities", "exclude_severities", mode="before")
    @classmethod
    def _norm_sevs(cls, v: Any) -> list[str]:
        if not v:
            return []
        if isinstance(v, str):
            v = [v]
        out = []
        for s in v:
            u = str(s).strip().upper()
            if u in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                out.append(u)
        return out

    @field_validator("cwe_ids", mode="before")
    @classmethod
    def _norm_cwes(cls, v: Any) -> list[str]:
        if not v:
            return []
        if isinstance(v, str):
            v = [v]
        out: list[str] = []
        for raw in v:
            s = str(raw).strip().upper().replace("CWE", "CWE-").replace("CWE--", "CWE-")
            if not s.startswith("CWE-"):
                digits = "".join(ch for ch in s if ch.isdigit())
                if digits:
                    s = f"CWE-{digits}"
            if s.startswith("CWE-"):
                out.append(s)
        return out

    @field_validator("finding_ids", mode="before")
    @classmethod
    def _norm_fids(cls, v: Any) -> list[str]:
        """Accept catalog-style IDs (FINDING-001, SHIP-AUTH-01, web:xss:44, …)."""
        if not v:
            return []
        if isinstance(v, str):
            v = [v]
        out: list[str] = []
        for raw in v:
            s = str(raw).strip()
            if not s or len(s) > 64:
                continue
            # Reject whitespace / path-like junk
            if any(ch.isspace() for ch in s):
                continue
            out.append(s)
        return list(dict.fromkeys(out))

    @field_validator("top_n", mode="before")
    @classmethod
    def _norm_top_n(cls, v: Any) -> int | None:
        if v is None or v == "":
            return None
        try:
            n = int(v)
            return n if 1 <= n <= 50 else None
        except (TypeError, ValueError):
            return None

    @field_validator("in_scope", mode="before")
    @classmethod
    def _norm_in_scope(cls, v: Any) -> bool:
        if v is None:
            return True  # missing → fail open
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.strip().lower() not in {"false", "0", "no", "out"}
        return bool(v)
