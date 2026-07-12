"""Local neural cross-encoder reranker (no paid API).

Uses sentence-transformers CrossEncoder, default:
  cross-encoder/ms-marco-MiniLM-L-6-v2

Lazy-loaded on first use. Falls back gracefully if the package/model
is unavailable so unit tests and air-gapped deploys still work.
"""

from __future__ import annotations

import logging
import threading
from typing import Protocol

from app.retrieval.findings_store import FindingRecord

logger = logging.getLogger(__name__)

DEFAULT_CE_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"


class CrossEncoderBackend(Protocol):
    def score_pairs(self, pairs: list[tuple[str, str]]) -> list[float]: ...


class SentenceTransformersCrossEncoder:
    """Wraps sentence_transformers.CrossEncoder."""

    def __init__(self, model_name: str = DEFAULT_CE_MODEL) -> None:
        from sentence_transformers import CrossEncoder  # lazy heavy import

        self.model_name = model_name
        logger.info("Loading cross-encoder model %s …", model_name)
        # device=cpu is portable for take-home / laptops
        self._model = CrossEncoder(model_name)
        logger.info("Cross-encoder ready: %s", model_name)

    def score_pairs(self, pairs: list[tuple[str, str]]) -> list[float]:
        if not pairs:
            return []
        scores = self._model.predict(pairs, show_progress_bar=False)
        # numpy array or list
        return [float(s) for s in scores]


class CrossEncoderReranker:
    """Process-wide lazy CE with thread-safe init."""

    def __init__(
        self,
        *,
        model_name: str = DEFAULT_CE_MODEL,
        enabled: bool = True,
    ) -> None:
        self.model_name = model_name
        self.enabled = enabled
        self._backend: CrossEncoderBackend | None = None
        self._failed = False
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        if not self.enabled or self._failed:
            return False
        return self._ensure_backend() is not None

    def _ensure_backend(self) -> CrossEncoderBackend | None:
        if not self.enabled or self._failed:
            return None
        if self._backend is not None:
            return self._backend
        with self._lock:
            if self._backend is not None:
                return self._backend
            if self._failed:
                return None
            try:
                self._backend = SentenceTransformersCrossEncoder(self.model_name)
            except Exception as exc:  # noqa: BLE001
                self._failed = True
                logger.warning(
                    "Cross-encoder unavailable (%s); using light rerank fallback",
                    exc,
                )
                return None
            return self._backend

    def rerank(
        self,
        *,
        query: str,
        candidates: list[tuple[FindingRecord, float]],
        top_k: int = 20,
        base_weight: float = 0.15,
    ) -> list[FindingRecord] | None:
        """Return CE-ordered findings, or None if CE cannot run.

        Final score ≈ base_weight * normalized_base + (1 - base_weight) * normalized_ce
        so RRF prior still has a small influence.
        """
        backend = self._ensure_backend()
        if backend is None or not candidates:
            return None

        # Cap CE work for latency (production: score shortlist only)
        shortlist = candidates[: max(top_k * 2, 24)]
        pairs: list[tuple[str, str]] = []
        records: list[FindingRecord] = []
        bases: list[float] = []
        for rec, base in shortlist:
            doc = (
                f"{rec.title}\n"
                f"Severity: {rec.severity} | {rec.cwe_id} | {rec.owasp_category}\n"
                f"Endpoint: {rec.method} {rec.endpoint} | Param: {rec.parameter}\n"
                f"{rec.description}\n"
                f"Remediation: {rec.remediation_hint}"
            )
            # truncate very long docs for MiniLM
            if len(doc) > 1500:
                doc = doc[:1500]
            pairs.append((query or "", doc))
            records.append(rec)
            bases.append(float(base))

        try:
            ce_scores = backend.score_pairs(pairs)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cross-encoder predict failed: %s", exc)
            return None

        if len(ce_scores) != len(records):
            return None

        def _norm(vals: list[float]) -> list[float]:
            if not vals:
                return []
            lo, hi = min(vals), max(vals)
            if hi - lo < 1e-9:
                return [0.5] * len(vals)
            return [(v - lo) / (hi - lo) for v in vals]

        n_base = _norm(bases)
        n_ce = _norm(ce_scores)
        w = min(max(base_weight, 0.0), 0.5)
        combined = [
            (records[i], (1.0 - w) * n_ce[i] + w * n_base[i])
            for i in range(len(records))
        ]
        combined.sort(key=lambda x: x[1], reverse=True)

        out: list[FindingRecord] = []
        seen: set[str] = set()
        for rec, _ in combined:
            if rec.finding_id in seen:
                continue
            seen.add(rec.finding_id)
            out.append(rec)
            if len(out) >= top_k:
                break
        return out


# Shared singleton for the process (optional override in tests)
_default_reranker: CrossEncoderReranker | None = None
_default_lock = threading.Lock()


def get_cross_encoder_reranker(
    *,
    model_name: str = DEFAULT_CE_MODEL,
    enabled: bool = True,
) -> CrossEncoderReranker:
    global _default_reranker
    with _default_lock:
        if _default_reranker is None:
            _default_reranker = CrossEncoderReranker(
                model_name=model_name, enabled=enabled
            )
        return _default_reranker


def reset_cross_encoder_for_tests() -> None:
    global _default_reranker
    with _default_lock:
        _default_reranker = None
