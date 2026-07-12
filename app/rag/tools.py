"""Finding-store tools for Groq function calling (no hallucinated data access).

The agent may only read through these tools; answers must still cite real IDs.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.retrieval.findings_store import FindingRecord, FindingsStore, sort_by_severity
from app.retrieval.hybrid import HybridRetriever
from app.rag.router import RouteResult

logger = logging.getLogger(__name__)

# OpenAI-compatible tool schemas for Groq chat.completions
FINDINGS_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_findings",
            "description": (
                "List findings from the scan with optional exact filters "
                "(severity, CWE, OWASP code, endpoint substring, keywords). "
                "Use for inventory, filters, and existence checks."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "description": "CRITICAL|HIGH|MEDIUM|LOW",
                    },
                    "cwe_id": {"type": "string", "description": "e.g. CWE-89"},
                    "owasp": {"type": "string", "description": "e.g. A01"},
                    "endpoint": {
                        "type": "string",
                        "description": "Substring of API path",
                    },
                    "keywords": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Keywords matched against finding text",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max findings to return (default 15)",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_finding",
            "description": "Get one finding by exact ID (FINDING-001).",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "FINDING-XXX",
                    }
                },
                "required": ["finding_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_findings",
            "description": (
                "Semantic + lexical search over findings for free-text topics "
                "(e.g. privilege escalation, authentication issues). "
                "Prefer list_findings when filters are exact."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "count_findings",
            "description": "Return how many findings exist in the current scan.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]


def finding_to_tool_dict(f: FindingRecord) -> dict[str, Any]:
    return {
        "id": f.finding_id,
        "title": f.title,
        "severity": f.severity,
        "cwe_id": f.cwe_id,
        "owasp_category": f.owasp_category,
        "endpoint": f"{f.method} {f.endpoint}".strip(),
        "parameter": f.parameter,
        "description": f.description,
        "remediation_hint": f.remediation_hint,
    }


class FindingsToolExecutor:
    """Execute tool calls against the structured store + hybrid search."""

    def __init__(
        self,
        *,
        findings_store: FindingsStore,
        retriever: HybridRetriever,
        scan_id: str | None,
    ) -> None:
        self.findings_store = findings_store
        self.retriever = retriever
        self.scan_id = scan_id
        self.seen_findings: dict[str, FindingRecord] = {}
        self._cache: dict[str, str] = {}

    def execute(self, name: str, arguments: dict[str, Any] | str) -> str:
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments or "{}")
            except json.JSONDecodeError:
                arguments = {}
        args = arguments or {}
        cache_key = json.dumps({"name": name, "args": args}, sort_keys=True)
        if cache_key in self._cache:
            return self._cache[cache_key]
        try:
            if name == "list_findings":
                result = self._list_findings(args)
            elif name == "get_finding":
                result = self._get_finding(args)
            elif name == "search_findings":
                result = self._search_findings(args)
            elif name == "count_findings":
                n = self.findings_store.count(scan_id=self.scan_id)
                result = json.dumps({"count": n, "scan_id": self.scan_id})
            else:
                result = json.dumps({"error": f"unknown tool: {name}"})
        except Exception as exc:  # noqa: BLE001
            logger.warning("Tool %s failed: %s", name, exc)
            result = json.dumps({"error": str(exc)})
        self._cache[cache_key] = result
        return result

    def _track(self, records: list[FindingRecord]) -> list[dict[str, Any]]:
        out = []
        for f in records:
            self.seen_findings[f.finding_id] = f
            out.append(finding_to_tool_dict(f))
        return out

    def _list_findings(self, args: dict[str, Any]) -> str:
        limit = int(args.get("limit") or 15)
        keywords = args.get("keywords") or []
        if isinstance(keywords, str):
            keywords = [keywords]
        records = self.findings_store.search(
            scan_id=self.scan_id,
            severity=args.get("severity"),
            cwe_id=args.get("cwe_id"),
            owasp=args.get("owasp"),
            endpoint=args.get("endpoint"),
            keywords=list(keywords) if keywords else None,
        )
        records = sort_by_severity(records)[:limit]
        return json.dumps(
            {"count": len(records), "findings": self._track(records)},
            ensure_ascii=False,
        )

    def _get_finding(self, args: dict[str, Any]) -> str:
        fid = str(args.get("finding_id") or "").strip().upper()
        rec = self.findings_store.get_by_id(fid, scan_id=self.scan_id)
        if not rec:
            return json.dumps({"error": f"{fid} not found in scan"})
        self.seen_findings[rec.finding_id] = rec
        return json.dumps({"finding": finding_to_tool_dict(rec)}, ensure_ascii=False)

    def _search_findings(self, args: dict[str, Any]) -> str:
        query = str(args.get("query") or "").strip()
        limit = int(args.get("limit") or 8)
        if not query:
            return json.dumps({"error": "query required", "findings": []})
        q_l = query.lower()
        # Prefer exact CWE when the tool model names a known class (reduces drift)
        if any(x in q_l for x in ("idor", "bola", "object level", "cwe-639", "cwe 639")):
            cwe_hits = self.findings_store.search(
                scan_id=self.scan_id, cwe_id="CWE-639"
            )
            if cwe_hits:
                records = sort_by_severity(cwe_hits)[:limit]
                return json.dumps(
                    {
                        "count": len(records),
                        "findings": self._track(records),
                        "used_bm25": False,
                        "filter": "cwe-639",
                    },
                    ensure_ascii=False,
                )
        route = RouteResult(intent="general", keywords=[query])
        # Class constraints help hybrid IR when query mentions a vuln class
        if any(x in q_l for x in ("idor", "bola", "object level")):
            route.class_constraints = [
                "idor",
                "bola",
                "object level",
                "insecure direct",
                "cwe-639",
            ]
            route.intent = "list"
        result = self.retriever.retrieve(
            question=query, route=route, scan_id=self.scan_id
        )
        records = result.findings[:limit]
        return json.dumps(
            {
                "count": len(records),
                "findings": self._track(records),
                "used_bm25": result.used_bm25,
            },
            ensure_ascii=False,
        )
