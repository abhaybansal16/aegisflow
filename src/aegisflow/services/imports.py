"""Persist normalized scanner findings through one atomic AegisFlow workflow."""

from __future__ import annotations

import json
from collections.abc import Sequence
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
    """Import a Semgrep report through the shared normalized-findings workflow."""

    findings = parse_semgrep_report(
        report=report,
        repository=repository_full_name,
        commit_sha=commit_sha,
    )
    raw_results = report.get("results")
    if not isinstance(raw_results, list):
        raise TypeError("Semgrep report requires a list-valued 'results' field")

    return import_normalized_findings(
        engine=engine,
        repository_full_name=repository_full_name,
        commit_sha=commit_sha,
        findings=findings,
        raw_payloads=raw_results,
        source_report=report,
        provider=provider,
        external_repository_id=external_repository_id,
    )


def import_normalized_findings(
    engine: Engine,
    repository_full_name: str,
    commit_sha: str,
    findings: Sequence[CanonicalFinding],
    raw_payloads: Sequence[dict[str, Any]],
    source_report: dict[str, Any],
    provider: str = "github",
    external_repository_id: str | None = None,
) -> ImportSummary:
    """Persist normalized findings and raw scanner evidence in one transaction.

    The caller supplies a normalized finding and its corresponding raw evidence
    in the same position. This service owns repository lookup, scan lifecycle,
    durable-finding reuse, observations, and transactional rollback.
    """

    _validate_import_inputs(
        repository_full_name=repository_full_name,
        commit_sha=commit_sha,
        findings=findings,
        raw_payloads=raw_payloads,
    )
    report_hash = _hash_report(source_report)
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
            for finding, raw_payload in zip(findings, raw_payloads):
                persisted_finding, created = _get_or_create_finding(
                    session=session,
                    repository_id=repository.id,
                    finding=finding,
                )
                if created:
                    created_findings += 1
                else:
                    reused_findings += 1

                session.add(
                    Observation(
                        finding_id=persisted_finding.id,
                        scan_run_id=scan_run.id,
                        tool=finding.tool,
                        tool_finding_id=_tool_finding_id(finding),
                        source_report_hash=report_hash,
                        location_path=finding.location.path,
                        start_line=finding.location.start_line,
                        end_line=finding.location.end_line,
                        raw_payload=raw_payload,
                    )
                )

            scan_run.status = "completed"
            scan_run.completed_at = datetime.now(timezone.utc)

        return ImportSummary(
            repository_id=str(repository.id),
            scan_run_id=str(scan_run.id),
            created_findings=created_findings,
            reused_findings=reused_findings,
            observations_created=len(findings),
        )


def _validate_import_inputs(
    repository_full_name: str,
    commit_sha: str,
    findings: Sequence[CanonicalFinding],
    raw_payloads: Sequence[dict[str, Any]],
) -> None:
    """Reject mismatched normalized findings and raw evidence before any write."""

    if len(findings) != len(raw_payloads):
        raise ValueError("Each normalized finding requires exactly one raw payload")

    for finding in findings:
        if finding.repository != repository_full_name:
            raise ValueError("All findings must belong to the imported repository")
        if finding.commit_sha != commit_sha:
            raise ValueError("All findings must belong to the imported commit")


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
    """Return a durable finding, updating its last-seen time when it exists."""

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
    """Hash JSON canonically so insignificant whitespace does not affect provenance."""

    encoded_report = json.dumps(report, sort_keys=True, separators=(",", ":"))
    return sha256(encoded_report.encode("utf-8")).hexdigest()


def _tool_finding_id(finding: CanonicalFinding) -> str:
    """Create a stable tool-level reference for source or package evidence."""

    location = finding.location
    if location.path is not None:
        return "{}:{}:{}".format(
            finding.rule_id or "unknown-rule",
            location.path,
            location.start_line,
        )
    return "{}:{}:{}".format(
        finding.rule_id or "unknown-rule",
        location.package_name or "unknown-package",
        location.target or "unknown-target",
    )