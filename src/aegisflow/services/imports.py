"""Atomically import normalized Semgrep results into the AegisFlow database."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from aegisflow.adapters.semgrep import parse_semgrep_report
from aegisflow.db.models import Finding, Observation, Repository, ScanRun
from aegisflow.schemas.finding import CanonicalFinding
from aegisflow.services.fingerprints import create_finding_fingerprint


@dataclass(frozen=True)
class ImportSummary:
    """A small, inspectable result returned after one successful import."""

    repository_id: str
    scan_run_id: str
    created_findings: int
    reused_findings: int
    observations_created: int


def import_semgrep_report(
    engine: Engine,
    report: dict[str, Any],
    repository_full_name: str,
    commit_sha: str,
    provider: str = "github",
    external_repository_id: str | None = None,
) -> ImportSummary:
    """Parse and atomically persist a saved Semgrep report.

    `report` has already been decoded from JSON. The transformation code remains
    separate from file I/O, just as in the adapter step.
    """

    findings = parse_semgrep_report(
        report=report,
        repository=repository_full_name,
        commit_sha=commit_sha,
    )
    raw_results = report.get("results")
    if not isinstance(raw_results, list):
        raise TypeError("Semgrep report requires a list-valued 'results' field")
    if len(findings) != len(raw_results):
        raise ValueError("Each Semgrep result must produce exactly one canonical finding")

    report_hash = _hash_report(report)
    repository_external_id = external_repository_id or repository_full_name

    with Session(engine, expire_on_commit=False) as session:
        with session.begin():
            repository = _get_or_create_repository(
                session=session,
                provider=provider,
                external_id=repository_external_id,
                full_name=repository_full_name,
            )
            scan_run = ScanRun(repository_id=repository.id, commit_sha=commit_sha)
            session.add(scan_run)
            session.flush()

            created_findings = 0
            reused_findings = 0
            for finding, raw_result in zip(findings, raw_results):
                persisted_finding, created = _get_or_create_finding(
                    session=session,
                    repository_id=repository.id,
                    finding=finding,
                )
                if created:
                    created_findings += 1
                else:
                    reused_findings += 1

                observation = Observation(
                    finding_id=persisted_finding.id,
                    scan_run_id=scan_run.id,
                    tool=finding.tool,
                    tool_finding_id=_tool_finding_id(finding),
                    source_report_hash=report_hash,
                    location_path=finding.location.path,
                    start_line=finding.location.start_line,
                    end_line=finding.location.end_line,
                    raw_payload=raw_result,
                )
                session.add(observation)

            scan_run.status = "completed"
            scan_run.completed_at = datetime.now(timezone.utc)

        return ImportSummary(
            repository_id=str(repository.id),
            scan_run_id=str(scan_run.id),
            created_findings=created_findings,
            reused_findings=reused_findings,
            observations_created=len(findings),
        )


def _get_or_create_repository(
    session: Session,
    provider: str,
    external_id: str,
    full_name: str,
) -> Repository:
    """Return one repository, creating it only the first time it is imported."""

    repository = session.scalar(
        select(Repository).where(
            Repository.provider == provider,
            Repository.external_id == external_id,
        )
    )
    if repository is not None:
        return repository

    repository = Repository(
        provider=provider,
        external_id=external_id,
        full_name=full_name,
    )
    session.add(repository)
    session.flush()
    return repository


def _get_or_create_finding(
    session: Session,
    repository_id: Any,
    finding: CanonicalFinding,
) -> tuple[Finding, bool]:
    """Return the durable finding, updating its last-seen time when it exists."""

    fingerprint = create_finding_fingerprint(finding)
    persisted_finding = session.scalar(
        select(Finding).where(
            Finding.repository_id == repository_id,
            Finding.fingerprint == fingerprint,
        )
    )
    if persisted_finding is not None:
        persisted_finding.last_seen_at = datetime.now(timezone.utc)
        persisted_finding.severity = finding.severity.value
        persisted_finding.title = finding.title
        return persisted_finding, False

    persisted_finding = Finding(
        repository_id=repository_id,
        fingerprint=fingerprint,
        category=finding.category.value,
        rule_id=finding.rule_id,
        severity=finding.severity.value,
        title=finding.title,
    )
    session.add(persisted_finding)
    session.flush()
    return persisted_finding, True


def _hash_report(report: dict[str, Any]) -> str:
    """Hash JSON canonically so whitespace does not affect provenance."""

    encoded_report = json.dumps(report, sort_keys=True, separators=(",", ":"))
    return sha256(encoded_report.encode("utf-8")).hexdigest()


def _tool_finding_id(finding: CanonicalFinding) -> str:
    """Create a stable Semgrep-specific reference for this initial milestone."""

    return "{}:{}:{}".format(
        finding.rule_id or "unknown-rule",
        finding.location.path,
        finding.location.start_line,
    )