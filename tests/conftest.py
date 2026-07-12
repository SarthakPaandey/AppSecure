"""Shared pytest fixtures with fake embed/LLM (no network)."""

from __future__ import annotations

import json
import os
from pathlib import Path

# Keep unit tests offline and fast: no CE model download unless explicitly enabled.
os.environ.setdefault("RERANK_MODE", "light")
os.environ.setdefault("CROSS_ENCODER_ENABLED", "false")
# Unit tests use hybrid path; tool-agent is covered in dedicated tests + live suite
os.environ.setdefault("USE_TOOL_AGENT", "false")
# Planner needs live LLM; unit tests use rules-only routing
os.environ.setdefault("USE_SEMANTIC_PLANNER", "false")
os.environ.setdefault("USE_DYNAMIC_SYNTHESIS", "false")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes import router
from app.clients.embeddings import FakeEmbeddings
from app.clients.llm import FakeLLM
from app.config import Settings, get_settings
from app.db.models import Base
from app.db.session import get_session
from app.retrieval.bm25_index import FindingsBM25Index
from app.retrieval.vector_store import VectorStore

get_settings.cache_clear()

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = json.loads((ROOT / "data" / "sample_findings.json").read_text())


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return Settings(
        modelscope_api_key="test-embed",
        groq_api_key="test-llm",
        data_dir=tmp_path,
        sqlite_path=tmp_path / "test.db",
        chroma_path=tmp_path / "chroma",
        knowledge_dir=ROOT / "data" / "knowledge",
        rerank_mode="light",
        cross_encoder_enabled=False,
        use_tool_agent=False,
    )


@pytest.fixture()
def fake_llm() -> FakeLLM:
    return FakeLLM()


@pytest.fixture()
def client(settings: Settings, fake_llm: FakeLLM, tmp_path: Path):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    embeddings = FakeEmbeddings(dimension=32)
    vector_store = VectorStore(chroma_path=settings.chroma_path, embeddings=embeddings)
    bm25_index = FindingsBM25Index()

    app = FastAPI()
    app.include_router(router)
    app.state.settings = settings
    app.state.embeddings = embeddings
    app.state.llm = fake_llm
    app.state.vector_store = vector_store
    app.state.bm25_index = bm25_index

    def _override_session():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_session] = _override_session

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def sample_scan() -> dict:
    return SAMPLE
