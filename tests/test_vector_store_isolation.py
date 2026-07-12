"""Vector query must not drop isolation filters on failure."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from app.clients.embeddings import FakeEmbeddings
from app.retrieval.vector_store import VectorStore


def test_filtered_query_fails_closed(tmp_path: Path):
    vs = VectorStore(chroma_path=tmp_path / "chroma", embeddings=FakeEmbeddings(8))
    # Seed one doc so count > 0
    vs.upsert_documents(
        ids=["f1"],
        texts=["SQL injection finding narrative"],
        metadatas=[{"scan_id": "scan-a", "doc_type": "finding"}],
    )

    def boom(**kwargs):
        if "where" in kwargs:
            raise RuntimeError("filter rejected")
        # If we ever retried bare, this would succeed and "leak"
        return {
            "ids": [["leaked-other-scan"]],
            "documents": [["other scan finding"]],
            "metadatas": [[{"scan_id": "scan-b"}]],
            "distances": [[0.1]],
        }

    vs._collection.query = MagicMock(side_effect=boom)  # type: ignore[method-assign]

    hits = vs.query(
        text="SQL injection",
        top_k=5,
        where={"scan_id": "scan-a"},
    )
    assert hits == []
    # Must not have fallen back to unfiltered query
    for call in vs._collection.query.call_args_list:
        assert "where" in call.kwargs


def test_unfiltered_query_failure_also_empty(tmp_path: Path):
    vs = VectorStore(chroma_path=tmp_path / "chroma", embeddings=FakeEmbeddings(8))
    vs.upsert_documents(
        ids=["k1"],
        texts=["knowledge"],
        metadatas=[{"doc_type": "cwe"}],
    )
    vs._collection.query = MagicMock(side_effect=RuntimeError("chroma down"))  # type: ignore[method-assign]
    assert vs.query(text="anything", top_k=3) == []


def test_cross_scan_filter_never_leaks(tmp_path: Path):
    """Failed filtered query for scan-a must not return scan-b vectors."""
    vs = VectorStore(chroma_path=tmp_path / "chroma", embeddings=FakeEmbeddings(8))
    vs.upsert_documents(
        ids=["a1", "b1"],
        texts=["scan A SQLi finding", "scan B SQLi finding"],
        metadatas=[
            {"scan_id": "scan-a", "doc_type": "finding"},
            {"scan_id": "scan-b", "doc_type": "finding"},
        ],
    )

    def boom(**kwargs):
        if kwargs.get("where"):
            raise RuntimeError("where clause unsupported")
        return {
            "ids": [["b1"]],
            "documents": [["scan B SQLi finding"]],
            "metadatas": [[{"scan_id": "scan-b", "doc_type": "finding"}]],
            "distances": [[0.01]],
        }

    vs._collection.query = MagicMock(side_effect=boom)  # type: ignore[method-assign]
    hits = vs.query(text="SQL injection", top_k=5, where={"scan_id": "scan-a"})
    assert hits == []
    assert all("where" in c.kwargs for c in vs._collection.query.call_args_list)
