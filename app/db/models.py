"""SQLAlchemy models for scan findings (system of record)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    scan_timestamp: Mapped[str] = mapped_column(String(64), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    findings: Mapped[list[Finding]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "finding_id", name="uq_scan_finding"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("scans.scan_id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    cwe_id: Mapped[str] = mapped_column(String(32), index=True)
    owasp_category: Mapped[str] = mapped_column(String(128), index=True)
    endpoint: Mapped[str] = mapped_column(String(512), index=True)
    method: Mapped[str] = mapped_column(String(32), default="")
    parameter: Mapped[str] = mapped_column(String(256), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    evidence_json: Mapped[str] = mapped_column(Text, default="{}")
    remediation_hint: Mapped[str] = mapped_column(Text, default="")

    scan: Mapped[Scan] = relationship("Scan", back_populates="findings")
