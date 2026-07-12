"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router
from app.clients.embeddings import OpenAICompatibleEmbeddings
from app.clients.llm import OpenAICompatibleLLM
from app.config import get_settings
from app.db.session import init_db, session_factory
from app.retrieval.bm25_index import FindingsBM25Index
from app.retrieval.findings_store import FindingsStore
from app.retrieval.vector_store import VectorStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    init_db(settings)

    # Clients — constructed once; fail fast if keys missing at first use is softer,
    # but we construct here so /health can report models.
    embeddings = OpenAICompatibleEmbeddings(settings)
    llm = OpenAICompatibleLLM(settings)
    vector_store = VectorStore(chroma_path=settings.chroma_path, embeddings=embeddings)
    bm25_index = FindingsBM25Index()
    # Warm BM25 from SQLite so free-text works after restart without re-ingest
    try:
        SessionLocal = session_factory()
        with SessionLocal() as session:
            n = bm25_index.rebuild_from_records(FindingsStore(session).list_all())
            logger.info("BM25 index warmed with %s finding documents", n)
    except Exception as exc:  # noqa: BLE001
        logger.warning("BM25 warm-start skipped: %s", exc)

    app.state.settings = settings
    app.state.embeddings = embeddings
    app.state.llm = llm
    app.state.vector_store = vector_store
    app.state.bm25_index = bm25_index
    logger.info(
        "App started | embed=%s | llm_chain=%s | reasoning=%s | chroma=%s | retrieval=BM25+dense+RRF",
        settings.embedding_model,
        settings.llm_model_chain(),
        settings.llm_reasoning_effort or "none",
        settings.chroma_path,
    )
    yield


app = FastAPI(
    title="Vulnerability Explainer RAG Agent",
    description=(
        "RAG-backed API for natural language questions over application security "
        "scan findings, with grounded answers and citations."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(router)


def create_app() -> FastAPI:
    return app
