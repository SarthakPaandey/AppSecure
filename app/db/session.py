"""SQLite engine / session factory."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.db.models import Base

_engine = None
_SessionLocal: sessionmaker[Session] | None = None


def init_db(settings: Settings) -> None:
    global _engine, _SessionLocal
    path = Path(settings.sqlite_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    url = f"sqlite:///{path.resolve()}"
    _engine = create_engine(url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=_engine)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)


def get_session() -> Generator[Session, None, None]:
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    session = _SessionLocal()
    try:
        yield session
    finally:
        session.close()


def session_factory() -> sessionmaker[Session]:
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _SessionLocal
