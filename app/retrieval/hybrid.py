"""Hybrid retrieval: structured store + BM25 + dense + light rerank.

Production-oriented stack (not sample-size tuned):
  1) Precise SQL filters (severity / CWE / OWASP / path / ids)
  2) Free-text: BM25 ∪ dense vectors → RRF fusion → lightweight rerank
  3) Strong-phrase gates for existence (no fuzzy invent of absent classes)
  4) Multi-clause coverage for multi-topic questions
  5) Knowledge vector retrieval + optional CWE/OWASP bridge

Scales with inverted-index BM25 + top-k dense; SQLite remains system of record.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.config import Settings
from app.rag.router import RouteResult, rule_based_route
from app.retrieval.bm25_index import FindingsBM25Index, reciprocal_rank_fusion
from app.retrieval.findings_store import FindingRecord, FindingsStore, sort_by_severity
from app.retrieval.cross_encoder import CrossEncoderReranker, get_cross_encoder_reranker
from app.retrieval.rerank import hybrid_rerank_findings
from app.retrieval.synonyms import (
    expand_keywords,
    extract_search_phrases,
    partition_phrases,
    split_question_clauses,
)
from app.retrieval.taxonomy import TOPICS, keywords_for_topic
from app.retrieval.vector_store import VectorHit, VectorStore


@dataclass
class HybridRetrievalResult:
    findings: list[FindingRecord] = field(default_factory=list)
    knowledge_hits: list[VectorHit] = field(default_factory=list)
    used_semantic_findings: bool = False
    used_bm25: bool = False
    rerank_mode_used: str = "light"


class HybridRetriever:
    def __init__(
        self,
        *,
        findings_store: FindingsStore,
        vector_store: VectorStore,
        settings: Settings,
        bm25_index: FindingsBM25Index | None = None,
        cross_encoder: CrossEncoderReranker | None = None,
    ) -> None:
        self.findings_store = findings_store
        self.vector_store = vector_store
        self.settings = settings
        self.bm25_index = bm25_index or FindingsBM25Index()
        # Shared lazy CE (disabled when rerank_mode=light or cross_encoder_enabled=False)
        mode = (getattr(settings, "rerank_mode", "auto") or "auto").lower()
        ce_enabled = bool(getattr(settings, "cross_encoder_enabled", True)) and mode != "light"
        self.cross_encoder = cross_encoder or get_cross_encoder_reranker(
            model_name=getattr(
                settings, "cross_encoder_model", "cross-encoder/ms-marco-MiniLM-L-6-v2"
            ),
            enabled=ce_enabled,
        )
        self._last_rerank_mode = "light"

    def rebuild_bm25(self, scan_id: str | None = None) -> int:
        """Rebuild BM25 from the findings store (call after ingest)."""
        records = self.findings_store.list_all(scan_id=scan_id)
        return self.bm25_index.rebuild_from_records(records)

    def retrieve(
        self,
        *,
        question: str,
        route: RouteResult,
        scan_id: str | None,
        top_k_knowledge: int | None = None,
    ) -> HybridRetrievalResult:
        top_k = top_k_knowledge or max(self.settings.default_top_k_knowledge, 6)

        rules = rule_based_route(question)
        route.keywords = list(dict.fromkeys([*(route.keywords or []), *rules.keywords]))
        route.severity = route.severity or rules.severity
        route.severities = list(
            dict.fromkeys([*(route.severities or []), *(rules.severities or [])])
        )
        route.exclude_severities = list(
            dict.fromkeys(
                [*(route.exclude_severities or []), *(rules.exclude_severities or [])]
            )
        )
        route.cwe_id = route.cwe_id or rules.cwe_id
        route.owasp = route.owasp or rules.owasp
        route.endpoint = route.endpoint or rules.endpoint
        route.finding_ids = list(
            dict.fromkeys([*(route.finding_ids or []), *(rules.finding_ids or [])])
        )
        route.finding_id = route.finding_id or rules.finding_id
        if route.finding_id and route.finding_id not in route.finding_ids:
            route.finding_ids = [route.finding_id, *route.finding_ids]
        if route.intent == "general" and rules.intent != "general":
            route.intent = rules.intent
        if rules.intent in {"cluster", "remediation"} and route.intent in {
            "summary",
            "general",
        }:
            route.intent = rules.intent
        # Precision constraints from surface form
        if rules.class_constraints:
            route.class_constraints = list(
                dict.fromkeys(
                    [*(route.class_constraints or []), *rules.class_constraints]
                )
            )
        route.want_parameter = bool(
            getattr(route, "want_parameter", False) or rules.want_parameter
        )
        route.want_endpoint = bool(
            getattr(route, "want_endpoint", False) or rules.want_endpoint
        )

        phrases = extract_search_phrases(question, route.keywords)
        strong_phrases, weak_phrases = partition_phrases(phrases)
        clauses = split_question_clauses(question)

        has_id_filter = bool(route.finding_ids)
        has_struct = any(
            [
                route.severities,
                route.severity,
                route.cwe_id,
                route.owasp,
                route.endpoint,
                has_id_filter,
            ]
        )
        # exclude-only is also a structural constraint
        has_exclude = bool(route.exclude_severities)

        findings: list[FindingRecord] = []
        used_semantic = False
        used_bm25 = False

        # --- Path-parameter structural filter (from endpoint shape, not vuln packs) ---
        path_param_q = bool(
            re.search(r"\bpath\s+param", question or "", flags=re.I)
        )
        if path_param_q and not has_id_filter:
            all_rows = self.findings_store.list_all(scan_id=scan_id)
            findings = [
                f
                for f in all_rows
                if "{" in (f.endpoint or "") or "{" in (f.parameter or "")
            ]
            findings = self._apply_severity_filters(findings, route)
            knowledge_hits = self._retrieve_knowledge(
                question=question, route=route, findings=findings, top_k=top_k
            )
            return HybridRetrievalResult(
                findings=findings[:50],
                knowledge_hits=knowledge_hits,
                used_semantic_findings=False,
            )

        # --- Summary / cluster: full inventory (cluster synthesizes later) ---
        if (
            route.intent in {"summary", "cluster"}
            and not has_id_filter
            and not route.cwe_id
            and not route.owasp
        ):
            findings = self.findings_store.list_all(scan_id=scan_id)
            findings = self._apply_severity_filters(findings, route)
            knowledge_hits = self._retrieve_knowledge(
                question=question, route=route, findings=findings, top_k=top_k
            )
            return HybridRetrievalResult(
                findings=findings[:50],
                knowledge_hits=knowledge_hits,
                used_semantic_findings=False,
            )

        # --- Explicit finding IDs (all of them) ---
        if has_id_filter:
            by_id: dict[str, FindingRecord] = {}
            for fid in route.finding_ids:
                rec = self.findings_store.get_by_id(fid, scan_id=scan_id)
                if rec:
                    by_id[rec.finding_id] = rec
            findings = sort_by_severity(list(by_id.values()))
            findings = self._apply_severity_filters(findings, route)
        elif has_struct:
            findings = self._structured_search(scan_id, route)
            # Intersect with strong tech keywords when both severity and class named
            # e.g. CRITICAL + GraphQL
            if findings and strong_phrases and (route.severities or route.severity):
                narrowed = self._filter_by_phrases(findings, strong_phrases)
                # Only apply if at least one keyword looks like a product/tech class
                techish = [
                    p
                    for p in strong_phrases
                    if p.lower()
                    in {
                        "graphql",
                        "jwt",
                        "xss",
                        "ssrf",
                        "sqli",
                        "rce",
                        "xxe",
                        "idor",
                        "bola",
                        "kyc",
                        "oauth",
                    }
                    or "graphql" in p.lower()
                ]
                if techish:
                    tech_narrowed = self._filter_by_phrases(findings, techish)
                    findings = tech_narrowed  # may be empty → correct for CRITICAL GraphQL
        else:
            findings, used_semantic, used_bm25 = self._free_text_findings(
                question=question,
                scan_id=scan_id,
                strong_phrases=strong_phrases,
                weak_phrases=weak_phrases,
                clauses=clauses,
                intent=route.intent,
            )
            findings = self._apply_severity_filters(findings, route)

        # exclude severity when no other struct path applied it
        if has_exclude and findings:
            findings = self._apply_severity_filters(findings, route)

        # Class constraints (e.g. "both IDOR findings") — precision filter
        class_constraints = list(getattr(route, "class_constraints", None) or [])
        if class_constraints and findings and route.intent != "compare":
            filtered = self._filter_by_class_constraints(findings, class_constraints)
            if filtered:
                findings = filtered
            elif route.intent in {"remediation", "explain", "list"}:
                # Prefer empty over wrong class when user named a clear entity class
                findings = []

        # Existence: strong phrases only; empty → stop (no fuzzy invent)
        if route.intent == "existence":
            if not has_id_filter:
                findings = self._existence_search(
                    scan_id=scan_id,
                    question=question,
                    route=route,
                    strong_phrases=strong_phrases,
                    clauses=clauses,
                )
            if class_constraints and findings:
                filtered = self._filter_by_class_constraints(findings, class_constraints)
                findings = filtered  # may be empty
            if not findings:
                findings = []
                used_semantic = False
                used_bm25 = False

        knowledge_hits = self._retrieve_knowledge(
            question=question,
            route=route,
            findings=findings,
            top_k=top_k,
        )

        # Knowledge bridge only for thin free-text non-existence results.
        # Skip when class-constrained (would re-expand past IDOR-only etc.).
        if (
            route.intent not in {"existence", "summary", "cluster"}
            and not has_struct
            and not has_id_filter
            and not class_constraints
            and knowledge_hits
            and 0 < len(findings) < 3
        ):
            bridged = self._findings_bridged_from_knowledge(knowledge_hits, scan_id)
            if bridged:
                findings = self._merge(findings, bridged)
                findings = self._apply_severity_filters(findings, route)

        if route.intent in {"summary", "list", "severity", "cross_ref", "cluster"}:
            findings = findings[:50]
        elif route.intent in {"remediation", "explain"} and class_constraints:
            findings = findings[:6]
        else:
            findings = findings[:12]

        return HybridRetrievalResult(
            findings=findings,
            knowledge_hits=knowledge_hits,
            used_semantic_findings=used_semantic,
            used_bm25=used_bm25,
            rerank_mode_used=getattr(self, "_last_rerank_mode", "light"),
        )

    def _structured_search(
        self, scan_id: str | None, route: RouteResult
    ) -> list[FindingRecord]:
        sevs = route.severities or ([route.severity] if route.severity else [])
        if sevs:
            by_id: dict[str, FindingRecord] = {}
            for sev in sevs:
                for f in self.findings_store.search(
                    scan_id=scan_id,
                    severity=sev,
                    cwe_id=route.cwe_id,
                    owasp=route.owasp,
                    endpoint=route.endpoint,
                ):
                    by_id[f.finding_id] = f
            findings = sort_by_severity(list(by_id.values()))
        else:
            findings = self.findings_store.search(
                scan_id=scan_id,
                cwe_id=route.cwe_id,
                owasp=route.owasp,
                endpoint=route.endpoint,
            )
        return self._apply_severity_filters(findings, route)

    def _apply_severity_filters(
        self, findings: list[FindingRecord], route: RouteResult
    ) -> list[FindingRecord]:
        out = findings
        sevs = route.severities or ([route.severity] if route.severity else [])
        # Only force include-filter when we used multi-sev without already filtering
        # (structured_search already filtered includes). For free-text + exclude:
        if route.exclude_severities:
            excl = {s.upper() for s in route.exclude_severities}
            out = [f for f in out if f.severity.upper() not in excl]
        return out

    def _existence_search(
        self,
        *,
        scan_id: str | None,
        question: str,
        route: RouteResult,
        strong_phrases: list[str],
        clauses: list[str],
    ) -> list[FindingRecord]:
        """Existence: only strong phrases; multi-OR classes unioned carefully.

        Bare generic words like 'injection' are never used alone.
        """
        # If severity/endpoint/cwe structure present, start from that set
        base: list[FindingRecord] | None = None
        if route.severities or route.severity or route.cwe_id or route.owasp or route.endpoint:
            base = self._structured_search(scan_id, route)

        # Per-clause strong hits (for "A, B, or C" style)
        clause_hits: list[FindingRecord] = []
        useful_clauses = [
            c
            for c in clauses
            if c.strip().lower() != (question or "").strip().lower() and len(c) >= 4
        ]
        if useful_clauses:
            for clause in useful_clauses[:8]:
                c_strong, _ = partition_phrases(extract_search_phrases(clause, None))
                if not c_strong:
                    continue
                hits = self._union_phrase_search(scan_id, c_strong)
                if base is not None:
                    base_ids = {f.finding_id for f in base}
                    hits = [h for h in hits if h.finding_id in base_ids]
                clause_hits = self._merge(clause_hits, hits)
            # Also try full-question strong phrases
            full_hits = self._union_phrase_search(scan_id, strong_phrases)
            if base is not None:
                base_ids = {f.finding_id for f in base}
                full_hits = [h for h in full_hits if h.finding_id in base_ids]
            # Prefer clause union if any clause produced hits; else full strong
            if clause_hits:
                return clause_hits
            if full_hits:
                return full_hits
            # Structured-only existence (e.g. CRITICAL GraphQL already narrowed)
            if base is not None and strong_phrases:
                tech = self._filter_by_phrases(base, strong_phrases)
                return tech
            return []

        # Single-clause existence
        hits = self._union_phrase_search(scan_id, strong_phrases)
        if base is not None:
            base_ids = {f.finding_id for f in base}
            hits = [h for h in hits if h.finding_id in base_ids]
            if not hits and strong_phrases:
                return self._filter_by_phrases(base, strong_phrases)
            if not strong_phrases:
                return base
        return hits

    def _filter_by_phrases(
        self, findings: list[FindingRecord], phrases: list[str]
    ) -> list[FindingRecord]:
        if not phrases:
            return findings
        expanded = expand_keywords(phrases)
        out: list[FindingRecord] = []
        for rec in findings:
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
            from app.retrieval.findings_store import _keyword_matches

            if any(_keyword_matches(k, blob) for k in expanded):
                out.append(rec)
        return out

    @staticmethod
    def _merge(
        base: list[FindingRecord], extra: list[FindingRecord]
    ) -> list[FindingRecord]:
        by_id = {f.finding_id: f for f in base}
        for f in extra:
            by_id[f.finding_id] = f
        return sort_by_severity(list(by_id.values()))

    def _free_text_findings(
        self,
        *,
        question: str,
        scan_id: str | None,
        strong_phrases: list[str],
        weak_phrases: list[str],
        clauses: list[str],
        intent: str,
    ) -> tuple[list[FindingRecord], bool, bool]:
        """Production free-text: BM25 ∪ dense (RRF) + phrase precision + rerank.

        Precision rules (still general, not sample packs):
          - existence: phrase-strict only (caller)
          - explain/remediate: if high-precision phrases hit, those lead
          - compare multi-clause: union of per-clause top hits (not global dump)
          - otherwise full hybrid fusion for scale
        """
        used_semantic = False
        used_bm25 = False

        if intent == "existence":
            findings = self._union_phrase_search(scan_id, strong_phrases)
            if not findings and weak_phrases:
                findings = self._union_phrase_search(scan_id, weak_phrases)
            return findings, used_semantic, used_bm25

        if len(self.bm25_index.index) == 0:
            self.rebuild_bm25(scan_id=None)

        # High-precision store keyword hits
        phrase_hits = self._union_phrase_search(scan_id, strong_phrases)
        if not phrase_hits and weak_phrases:
            phrase_hits = self._union_phrase_search(scan_id, weak_phrases)

        # --- Compare multi-topic: top hits per clause, then drop non-matching ---
        useful_clauses = [
            c
            for c in clauses
            if c.strip().lower() != (question or "").strip().lower() and len(c) >= 4
        ]
        if intent == "compare" and len(useful_clauses) >= 2:
            by_id: dict[str, FindingRecord] = {}
            for clause in useful_clauses[:8]:
                c_strong, c_weak = partition_phrases(
                    extract_search_phrases(clause, None)
                )
                seeds = c_strong or c_weak
                c_phrase = self._union_phrase_search(scan_id, seeds)
                c_bm25 = self._bm25_records(clause, scan_id, top_k=2)
                used_bm25 = used_bm25 or bool(c_bm25)
                # Prefer phrase match for this clause; BM25 only as fill
                pool = c_phrase[:2] if c_phrase else c_bm25[:2]
                if not pool:
                    pool = self._semantic_findings(clause, scan_id, top_k=1)
                    used_semantic = used_semantic or bool(pool)
                # Keep only records that match this clause's strong tokens
                for rec in pool:
                    if seeds and not self._record_matches_any(rec, seeds):
                        continue
                    by_id[rec.finding_id] = rec
            if by_id:
                ordered = sort_by_severity(list(by_id.values()))
                return ordered[:6], used_semantic, used_bm25

        # Priority / go-live questions: always surface CRITICAL findings
        q_l = (question or "").lower()
        priority_q = any(
            x in q_l
            for x in (
                "fix first",
                "go-live",
                "go live",
                "priorit",
                "before a production",
                "would you fix first",
            )
        )

        # --- Explain / remediate: phrase-first when precise hits exist ---
        # Skip phrase-only short-circuit for priority Qs (need full severity picture)
        # and when phrase hits look accidental (single generic token match).
        if intent in {"explain", "remediation"} and phrase_hits and not priority_q:
            # Expand slightly with BM25 on the same question for near-duplicates
            extra = self._bm25_records(question, scan_id, top_k=4)
            used_bm25 = bool(extra)
            by_id = {f.finding_id: f for f in phrase_hits}
            for rec in extra:
                # only add if shares a strong phrase token with the question
                blob = (rec.title + " " + rec.description).lower()
                if any(
                    p.lower() in blob
                    for p in strong_phrases
                    if len(p) >= 3 and " " not in p
                ) or any(p.lower() in blob for p in strong_phrases if " " in p):
                    by_id[rec.finding_id] = rec
            cands = [(r, 1.0) for r in by_id.values()]
            ordered, mode_used = hybrid_rerank_findings(
                query=question,
                candidates=cands,
                intent=intent,
                top_k=min(8, len(cands)),
                mode=getattr(self.settings, "rerank_mode", "auto"),
                cross_encoder=self.cross_encoder,
            )
            self._last_rerank_mode = mode_used
            return (
                ordered or sort_by_severity(list(by_id.values()))[:8],
                used_semantic,
                used_bm25,
            )

        # --- Full hybrid fusion (list/general/open-ended) — production scale path ---
        pool_k = min(max(getattr(self.settings, "bm25_top_k", 40), 20), 50)
        rrf_k = getattr(self.settings, "rrf_k", 60)

        bm25_scores: dict[str, float] = {}
        bm25_ids: list[str] = []
        try:
            for h in self.bm25_index.search(question, top_k=pool_k, scan_id=scan_id):
                bm25_scores[h.doc_id] = h.score
            if useful_clauses:
                for clause in useful_clauses[:8]:
                    for h in self.bm25_index.search(
                        clause, top_k=max(5, pool_k // 4), scan_id=scan_id
                    ):
                        bm25_scores[h.doc_id] = max(
                            bm25_scores.get(h.doc_id, 0.0), h.score
                        )
            bm25_ids = [
                d
                for d, _ in sorted(
                    bm25_scores.items(), key=lambda x: x[1], reverse=True
                )[:pool_k]
            ]
            used_bm25 = bool(bm25_ids)
        except Exception:
            bm25_ids = []

        dense_recs = self._semantic_findings(question, scan_id, top_k=pool_k // 2)
        dense_ids = [r.finding_id for r in dense_recs]
        used_semantic = bool(dense_ids)
        if useful_clauses:
            for clause in useful_clauses[:6]:
                for r in self._semantic_findings(clause, scan_id, top_k=3):
                    if r.finding_id not in dense_ids:
                        dense_ids.append(r.finding_id)
                        dense_recs.append(r)

        phrase_ids = [f.finding_id for f in phrase_hits]

        lists_for_rrf: list[list[str]] = []
        w_for_rrf: list[float] = []
        if bm25_ids:
            lists_for_rrf.append(bm25_ids)
            w_for_rrf.append(1.2)
        if dense_ids:
            lists_for_rrf.append(dense_ids)
            w_for_rrf.append(1.0)
        if phrase_ids:
            lists_for_rrf.append(phrase_ids)
            w_for_rrf.append(1.4)

        if not lists_for_rrf:
            return [], used_semantic, used_bm25

        fused = reciprocal_rank_fusion(lists_for_rrf, k=rrf_k, weights=w_for_rrf)

        by_id: dict[str, FindingRecord] = {}
        for rec in phrase_hits:
            by_id[rec.finding_id] = rec
        for rec in dense_recs:
            by_id[rec.finding_id] = rec
        for doc_id, _ in fused:
            if doc_id not in by_id:
                rec = self.findings_store.get_by_id(doc_id, scan_id=scan_id)
                if rec:
                    by_id[doc_id] = rec

        candidates: list[tuple[FindingRecord, float]] = []
        for doc_id, rrf_score in fused:
            rec = by_id.get(doc_id)
            if not rec:
                continue
            base = rrf_score + 0.015 * bm25_scores.get(doc_id, 0.0)
            # Precision boost for phrase-confirmed docs
            if doc_id in set(phrase_ids):
                base += 0.08
            candidates.append((rec, base))

        # Priority / go-live: ensure CRITICAL findings are in the candidate pool
        if priority_q:
            for rec in self.findings_store.search(scan_id=scan_id, severity="CRITICAL"):
                if rec.finding_id not in {c[0].finding_id for c in candidates}:
                    candidates.append((rec, 0.2))
                by_id[rec.finding_id] = rec

        # Keep free-text list/general shortlists tight for LLM context quality
        out_k = 8 if priority_q else (6 if intent in {"list", "general"} else min(pool_k, 12))
        findings, mode_used = hybrid_rerank_findings(
            query=question,
            candidates=candidates,
            intent=intent,
            top_k=out_k,
            mode=getattr(self.settings, "rerank_mode", "auto"),
            cross_encoder=self.cross_encoder,
        )
        self._last_rerank_mode = mode_used
        return findings, used_semantic, used_bm25

    def _bm25_records(
        self, query: str, scan_id: str | None, top_k: int = 10
    ) -> list[FindingRecord]:
        out: list[FindingRecord] = []
        try:
            for h in self.bm25_index.search(query, top_k=top_k, scan_id=scan_id):
                rec = self.findings_store.get_by_id(h.doc_id, scan_id=scan_id)
                if rec:
                    out.append(rec)
        except Exception:
            return []
        return out

    @staticmethod
    def _record_blob(rec: FindingRecord) -> str:
        return " ".join(
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

    def _record_matches_any(self, rec: FindingRecord, phrases: list[str]) -> bool:
        blob = self._record_blob(rec)
        for p in phrases:
            p = (p or "").lower().strip()
            if len(p) < 2:
                continue
            if " " in p:
                if p in blob:
                    return True
            elif re.search(rf"(?<![a-z0-9]){re.escape(p)}(?![a-z0-9])", blob):
                return True
        return False

    def _filter_by_class_constraints(
        self, findings: list[FindingRecord], constraints: list[str]
    ) -> list[FindingRecord]:
        """Keep findings whose store text matches a named vulnerability class.

        Expands taxonomy topic names into keywords + CWE numbers so class
        constraints are not just raw string matches.
        """
        if not constraints:
            return findings
        # Expand any taxonomy topic names into keywords/CWEs
        expanded: list[str] = []
        topic_cwes: list[str] = []
        for c in constraints:
            c_lower = (c or "").lower()
            matched_topic = False
            for name, topic in TOPICS.items():
                if name.lower() == c_lower or any(a.lower() == c_lower for a in topic.abbrevs):
                    expanded.extend(keywords_for_topic(name))
                    topic_cwes.extend(topic.cwes)
                    matched_topic = True
                    break
            if not matched_topic:
                expanded.append(c)
        expanded = list(dict.fromkeys([e for e in expanded if e]))
        topic_cwes = list(dict.fromkeys([c for c in topic_cwes if c]))

        out: list[FindingRecord] = []
        for rec in findings:
            if self._record_matches_any(rec, expanded):
                out.append(rec)
                continue
            # Also accept CWE number match from taxonomy topics
            if topic_cwes and rec.cwe_id:
                rec_cwe = re.sub(r"\D", "", rec.cwe_id)
                if any(rec_cwe == re.sub(r"\D", "", c) for c in topic_cwes):
                    out.append(rec)
        return out

    def _union_phrase_search(
        self,
        scan_id: str | None,
        phrases: list[str],
        *,
        severity: str | None = None,
        cwe_id: str | None = None,
        owasp: str | None = None,
        endpoint: str | None = None,
    ) -> list[FindingRecord]:
        by_id: dict[str, FindingRecord] = {}
        for phrase in phrases:
            hits = self.findings_store.search(
                scan_id=scan_id,
                severity=severity,
                cwe_id=cwe_id,
                owasp=owasp,
                endpoint=endpoint,
                keywords=expand_keywords([phrase]),
            )
            for h in hits:
                by_id[h.finding_id] = h
        return sort_by_severity(list(by_id.values()))

    def _semantic_findings(
        self,
        question: str,
        scan_id: str | None,
        top_k: int | None = None,
    ) -> list[FindingRecord]:
        k = top_k or self.settings.default_top_k_findings_semantic
        if scan_id:
            where: dict | None = {"$and": [{"doc_type": "finding"}, {"scan_id": scan_id}]}
        else:
            where = {"doc_type": "finding"}
        try:
            hits = self.vector_store.query(text=question, top_k=k, where=where)
        except Exception:
            hits = self.vector_store.query(
                text=question, top_k=k, where={"doc_type": "finding"}
            )

        out: list[FindingRecord] = []
        seen: set[str] = set()
        for hit in hits:
            fid = str(hit.metadata.get("source_id") or "")
            if not fid or fid in seen:
                continue
            rec = self.findings_store.get_by_id(fid, scan_id=scan_id)
            if rec:
                seen.add(fid)
                out.append(rec)
        return sort_by_severity(out)

    def _findings_bridged_from_knowledge(
        self,
        knowledge_hits: list[VectorHit],
        scan_id: str | None,
    ) -> list[FindingRecord]:
        by_id: dict[str, FindingRecord] = {}
        cwes: set[str] = set()
        owasps: set[str] = set()
        for h in knowledge_hits:
            meta = h.metadata or {}
            for key in ("cwe_id", "source_id", "id"):
                val = str(meta.get(key) or "")
                for m in re.finditer(r"CWE-?(\d+)", val, flags=re.I):
                    cwes.add(m.group(1))
            for m in re.finditer(r"CWE-?(\d+)", h.text or "", flags=re.I):
                cwes.add(m.group(1))
            for key in ("owasp_category", "source_id", "id"):
                val = str(meta.get(key) or "")
                for m in re.finditer(r"\bA0?([1-9]|10)\b", val, flags=re.I):
                    owasps.add(f"A{int(m.group(1)):02d}")
            for m in re.finditer(r"\bA0?([1-9]|10)\b", h.text or "", flags=re.I):
                owasps.add(f"A{int(m.group(1)):02d}")
            title = str(meta.get("title") or "")
            strong, _ = partition_phrases(
                extract_search_phrases(title + " " + (h.text or "")[:200], None)
            )
            for phrase in strong[:6]:
                for f in self.findings_store.search(
                    scan_id=scan_id, keywords=expand_keywords([phrase])
                ):
                    by_id[f.finding_id] = f

        for num in cwes:
            for f in self.findings_store.search(scan_id=scan_id, cwe_id=f"CWE-{num}"):
                by_id[f.finding_id] = f
        for code in owasps:
            for f in self.findings_store.search(scan_id=scan_id, owasp=code):
                by_id[f.finding_id] = f
        return sort_by_severity(list(by_id.values()))

    def _retrieve_knowledge(
        self,
        *,
        question: str,
        route: RouteResult,
        findings: list[FindingRecord],
        top_k: int,
    ) -> list[VectorHit]:
        query_text = question
        if route.intent in {"remediation", "explain", "compare", "list"}:
            query_text = f"{question} remediation mitigation"

        hits = self.vector_store.query(text=query_text, top_k=max(top_k + 8, 12))

        cwe_nums = {
            "".join(ch for ch in (f.cwe_id or "") if ch.isdigit())
            for f in findings
            if f.cwe_id
        }
        owasp_codes: set[str] = set()
        for f in findings:
            m = re.search(r"(A\d{2})", f.owasp_category or "", re.I)
            if m:
                owasp_codes.add(m.group(1).upper())
        if route.owasp:
            o = route.owasp.upper()
            owasp_codes.add(o if o.startswith("A") else route.owasp)

        scored: list[tuple[float, VectorHit]] = []
        for h in hits:
            if h.metadata.get("doc_type") == "finding":
                continue
            score = max(0.0, 2.0 - float(h.distance or 1.0))
            meta = (
                str(h.metadata.get("cwe_id", ""))
                + str(h.metadata.get("owasp_category", ""))
                + str(h.metadata.get("source_id", ""))
                + h.id
            ).upper()
            if any(n and n in meta for n in cwe_nums):
                score += 3.0
            if any(c in meta for c in owasp_codes):
                score += 2.0
            if h.metadata.get("doc_type") == "guide":
                score += 1.0
            scored.append((score, h))
        scored.sort(key=lambda x: x[0], reverse=True)

        out: list[VectorHit] = []
        seen: set[str] = set()
        for _, h in scored:
            if h.id in seen:
                continue
            seen.add(h.id)
            out.append(h)
            if len(out) >= top_k:
                break
        return out
