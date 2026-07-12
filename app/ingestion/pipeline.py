"""Ingestion orchestration: structured store + vector index."""

from __future__ import annotations

import logging
import time
from typing import Any

from sqlalchemy.orm import Session

from app.api.schemas import IngestRequest, IngestResponse, ReferenceDocumentIn
from app.ingestion.finding_documents import findings_to_vector_payloads
from app.ingestion.knowledge_loader import KnowledgeDoc, load_knowledge_dir
from app.retrieval.bm25_index import FindingsBM25Index
from app.retrieval.findings_store import FindingsStore
from app.retrieval.vector_store import VectorStore
from app.config import Settings

logger = logging.getLogger(__name__)


class IngestionPipeline:
    def __init__(
        self,
        *,
        session: Session,
        vector_store: VectorStore,
        settings: Settings,
        bm25_index: FindingsBM25Index | None = None,
    ) -> None:
        self.session = session
        self.vector_store = vector_store
        self.settings = settings
        self.findings_store = FindingsStore(session)
        self.bm25_index = bm25_index or FindingsBM25Index()

    def ingest(self, request: IngestRequest) -> IngestResponse:
        started = time.perf_counter()
        scan = request.scan
        finding_dicts: list[dict[str, Any]] = []
        for f in scan.findings:
            d = f.model_dump()
            d["id"] = f.id
            finding_dicts.append(d)

        records = self.findings_store.replace_scan(
            scan_id=scan.scan_id,
            target=scan.target,
            scan_timestamp=scan.scan_timestamp,
            findings=finding_dicts,
        )

        # Replace finding vectors for this scan
        self.vector_store.delete_by_scan(scan.scan_id)
        ids, texts, metas = findings_to_vector_payloads(records)
        finding_chunks = self.vector_store.upsert_documents(
            ids=ids, texts=texts, metadatas=metas
        )

        # Rebuild BM25 over *all* findings in the store (multi-scan ready)
        all_records = self.findings_store.list_all()
        bm25_docs = self.bm25_index.rebuild_from_records(all_records)

        knowledge_docs = load_knowledge_dir(self.settings.knowledge_dir)
        by_type: dict[str, int] = {}
        for d in knowledge_docs:
            by_type[d.doc_type] = by_type.get(d.doc_type, 0) + 1
        knowledge_chunks = self._upsert_knowledge(knowledge_docs)
        extra_chunks = self._upsert_extra_refs(request.reference_documents)

        total_vectors = self.vector_store.count
        latency_ms = int((time.perf_counter() - started) * 1000)
        logger.info(
            "Ingested scan %s: %s findings, bm25_docs=%s, knowledge=%s, extra=%s, vectors=%s, %sms",
            scan.scan_id,
            len(records),
            bm25_docs,
            by_type,
            extra_chunks,
            total_vectors,
            latency_ms,
        )
        return IngestResponse(
            scan_id=scan.scan_id,
            findings_ingested=len(records),
            knowledge_chunks=total_vectors,
            status="ok",
            latency_ms=latency_ms,
        )

    def ensure_bundled_knowledge(self) -> int:
        docs = load_knowledge_dir(self.settings.knowledge_dir)
        return self._upsert_knowledge(docs)

    def _upsert_knowledge(self, docs: list[KnowledgeDoc]) -> int:
        if not docs:
            return 0
        ids = [d.doc_id for d in docs]
        texts = [d.text for d in docs]
        metas = [
            {
                "doc_type": d.doc_type,
                "source_id": d.doc_id,
                "title": d.title,
                "url": d.url or "",
                "cwe_id": d.cwe_id or "",
                "owasp_category": d.owasp_category or "",
                # Comma-joined for Chroma metadata (string only)
                "topics": ",".join(d.topics) if d.topics else "",
            }
            for d in docs
        ]
        return self.vector_store.upsert_documents(ids=ids, texts=texts, metadatas=metas)

    def _upsert_extra_refs(self, refs: list[ReferenceDocumentIn]) -> int:
        if not refs:
            return 0
        ids: list[str] = []
        texts: list[str] = []
        metas: list[dict[str, Any]] = []
        for i, ref in enumerate(refs):
            doc_id = ref.id or f"extra-{i}-{abs(hash(ref.title)) % 10_000_000}"
            ids.append(doc_id)
            texts.append(f"{ref.title}\n\n{ref.text}")
            metas.append(
                {
                    "doc_type": "extra",
                    "source_id": doc_id,
                    "title": ref.title,
                    "url": ref.source_url or "",
                }
            )
        return self.vector_store.upsert_documents(ids=ids, texts=texts, metadatas=metas)
