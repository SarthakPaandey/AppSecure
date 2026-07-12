"""OpenAI-compatible embedding client (ModelScope / Qwen)."""

from __future__ import annotations

import logging
from typing import Protocol

from openai import OpenAI

from app.config import Settings

logger = logging.getLogger(__name__)


class EmbeddingClient(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...

    @property
    def dimension(self) -> int | None: ...


class EmbeddingError(RuntimeError):
    """Raised when the embedding provider fails after retries (callers may fail soft)."""


class OpenAICompatibleEmbeddings:
    """Thin wrapper so vector store / ingest never couple to a vendor."""

    def __init__(self, settings: Settings) -> None:
        if not settings.embedding_api_key:
            raise ValueError(
                "MODELSCOPE_API_KEY is not set. Copy .env.example to .env and add your key."
            )
        timeout_s = float(getattr(settings, "embed_timeout_s", 10.0) or 10.0)
        max_retries = int(getattr(settings, "embed_max_retries", 0) or 0)
        self._client = OpenAI(
            base_url=settings.embedding_base_url,
            api_key=settings.embedding_api_key,
            max_retries=max(0, max_retries),
            timeout=max(1.0, timeout_s),
        )
        self._model = settings.embedding_model
        self._dimension: int | None = None
        self._timeout_s = timeout_s

    @property
    def dimension(self) -> int | None:
        return self._dimension

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        # Batch modestly to avoid payload limits
        batch_size = 16
        all_vectors: list[list[float]] = []
        try:
            for i in range(0, len(texts), batch_size):
                batch = texts[i : i + batch_size]
                # Normalize empty strings — some APIs reject them
                batch = [t if t.strip() else " " for t in batch]
                response = self._client.embeddings.create(
                    model=self._model,
                    input=batch,
                    encoding_format="float",
                )
                # Ensure order by index
                ordered = sorted(response.data, key=lambda d: d.index)
                vectors = [item.embedding for item in ordered]
                if self._dimension is None and vectors:
                    self._dimension = len(vectors[0])
                    logger.info("Embedding dimension detected: %s", self._dimension)
                all_vectors.extend(vectors)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Embedding provider failed (timeout_s=%s): %s", self._timeout_s, exc
            )
            raise EmbeddingError(f"embed failed: {exc}") from exc
        return all_vectors


class FakeEmbeddings:
    """Deterministic bag-of-tokens embeddings for unit tests (no network).

    Shared tokens → similar vectors, so multi-clause semantic retrieval is testable
    without a hand-maintained synonym pack or live embedding API.
    """

    def __init__(self, dimension: int = 32) -> None:
        self._dimension = dimension

    @property
    def dimension(self) -> int:
        return self._dimension

    def embed(self, texts: list[str]) -> list[list[float]]:
        import re

        vectors: list[list[float]] = []
        for text in texts:
            vec = [0.0] * self._dimension
            toks = re.findall(r"[a-z0-9]+", (text or "").lower())
            if not toks:
                toks = ["empty"]
            for tok in toks:
                # stable per-token bucket
                h = 0
                for ch in tok:
                    h = (h * 31 + ord(ch)) % (10**9 + 7)
                vec[h % self._dimension] += 1.0
                # second hash for slightly richer space
                vec[(h // 7) % self._dimension] += 0.5
            norm = sum(v * v for v in vec) ** 0.5 or 1.0
            vectors.append([v / norm for v in vec])
        return vectors
