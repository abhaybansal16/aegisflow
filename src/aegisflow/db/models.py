"""Initial relational model for repositories, scans, findings, and observations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegisflow.db.base import Base


class Repository(Base):
    """A source-code repository that AegisFlow scans over time."""

    __tablename__ = "repositories"
    __table_args__ = (
        UniqueConstraint("provider", "external_id", name="uq_repositories_provider_external_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    scan_runs: Mapped[list[ScanRun]] = relationship(back_populates="repository")
    findings: Mapped[list[Finding]] = relationship(back_populates="repository")


class ScanRun(Base):
    """One security-scan import associated with a repository and commit."""

    __tablename__ = "scan_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    repository_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("repositories.id", ondelete="RESTRICT"), nullable=False
    )
    commit_sha: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="running")
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    repository: Mapped[Repository] = relationship(back_populates="scan_runs")
    observations: Mapped[list[Observation]] = relationship(back_populates="scan_run")


class Finding(Base):
    """A durable, actionable issue tracked in a repository across scan runs."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("repository_id", "fingerprint", name="uq_findings_repository_fingerprint"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    repository_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("repositories.id", ondelete="RESTRICT"), nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="new")
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    repository: Mapped[Repository] = relationship(back_populates="findings")
    observations: Mapped[list[Observation]] = relationship(back_populates="finding")


class Observation(Base):
    """Tool-specific evidence observed during one scan run for one finding."""

    __tablename__ = "observations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="RESTRICT"), nullable=False
    )
    scan_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="RESTRICT"), nullable=False
    )
    tool: Mapped[str] = mapped_column(String(80), nullable=False)
    tool_finding_id: Mapped[str | None] = mapped_column(String(512))
    source_report_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    location_path: Mapped[str | None] = mapped_column(String(1024))
    start_line: Mapped[int | None]
    end_line: Mapped[int | None]
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    finding: Mapped[Finding] = relationship(back_populates="observations")
    scan_run: Mapped[ScanRun] = relationship(back_populates="observations")