"""Chroma-backed vector store for findings narratives + security knowledge."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import chromadb
from chromadb.api.models.Collection import Collection

from app.clients.embeddings import EmbeddingClient

logger = logging.getLogger(__name__)

COLLECTION_NAME = "appsec_knowledge"


@dataclass
class VectorHit:
    id: str
    text: str
    metadata: dict[str, Any]
    distance: float | None = None


class VectorStore:
    def __init__(
        self,
        *,
        chroma_path: Path,
        embeddings: EmbeddingClient,
    ) -> None:
        Path(chroma_path).mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(chroma_path))
        self._embeddings = embeddings
        self._collection: Collection = self._client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )

    @property
    def count(self) -> int:
        return self._collection.count()

    def upsert_documents(
        self,
        *,
        ids: list[str],
        texts: list[str],
        metadatas: list[dict[str, Any]],
    ) -> int:
        if not ids:
            return 0
        # Chroma metadata values must be str/int/float/bool
        clean_meta = [_sanitize_metadata(m) for m in metadatas]
        vectors = self._embeddings.embed(texts)
        self._collection.upsert(
            ids=ids,
            documents=texts,
            embeddings=vectors,
            metadatas=clean_meta,
        )
        return len(ids)

    def delete_by_scan(self, scan_id: str) -> None:
        """Remove finding vectors for a scan (knowledge docs retained)."""
        try:
            self._collection.delete(where={"scan_id": scan_id})
        except Exception as exc:  # noqa: BLE001
            logger.warning("delete_by_scan(%s) soft-failed: %s", scan_id, exc)

    def delete_ids(self, ids: list[str]) -> None:
        if ids:
            self._collection.delete(ids=ids)

    def query(
        self,
        *,
        text: str,
        top_k: int = 4,
        where: dict[str, Any] | None = None,
    ) -> list[VectorHit]:
        if top_k <= 0:
            return []
        embedding = self._embeddings.embed([text])[0]
        kwargs: dict[str, Any] = {
            "query_embeddings": [embedding],
            "n_results": min(top_k, max(self.count, 1)),
            "include": ["documents", "metadatas", "distances"],
        }
        if where:
            kwargs["where"] = where
        if self.count == 0:
            return []
        try:
            result = self._collection.query(**kwargs)
        except Exception as exc:  # noqa: BLE001
            # Fail closed: never drop isolation filters (e.g. scan_id).
            # Retrying bare would leak vectors from other scans / doc types.
            if where:
                logger.warning(
                    "vector query with filter failed (%s); returning no hits (fail-closed)",
                    exc,
                )
                return []
            logger.warning("vector query failed (%s); returning no hits", exc)
            return []

        hits: list[VectorHit] = []
        ids = (result.get("ids") or [[]])[0]
        docs = (result.get("documents") or [[]])[0]
        metas = (result.get("metadatas") or [[]])[0]
        dists = (result.get("distances") or [[]])[0]
        for i, doc_id in enumerate(ids):
            hits.append(
                VectorHit(
                    id=doc_id,
                    text=docs[i] or "",
                    metadata=metas[i] or {},
                    distance=dists[i] if i < len(dists) else None,
                )
            )
        return hits

    def query_by_doc_type(
        self,
        *,
        text: str,
        doc_type: str,
        top_k: int = 4,
        extra_where: dict[str, Any] | None = None,
    ) -> list[VectorHit]:
        where: dict[str, Any] = {"doc_type": doc_type}
        if extra_where:
            where = {"$and": [where, extra_where]}
        return self.query(text=text, top_k=top_k, where=where)


def _sanitize_metadata(meta: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in meta.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
        else:
            out[k] = str(v)
    return out
