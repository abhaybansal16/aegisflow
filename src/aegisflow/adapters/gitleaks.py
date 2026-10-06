"""Normalize Gitleaks secret-detection reports into AegisFlow findings."""

from __future__ import annotations

from typing import Any

from aegisflow.schemas.finding import (
    CanonicalFinding,
    FindingCategory,
    Location,
    Severity,
)

# Gitleaks reports a detected secret, not a graded vulnerability: its native
# JSON has no severity field. A confirmed secret is treated as high severity
# regardless of which rule matched it, since any leaked credential warrants
# rotation.
GITLEAKS_SEVERITY = Severity.HIGH
GITLEAKS_CONFIDENCE = 0.85


class GitleaksReportError(ValueError):
    """Raised when a report does not have the Gitleaks structure we expect."""


def parse_gitleaks_report(
    report: list[dict[str, Any]],
    repository: str,
    commit_sha: str,
) -> list[CanonicalFinding]:
    """Convert every Gitleaks leak in a decoded JSON report into a finding."""

    if not isinstance(report, list):
        raise GitleaksReportError("Gitleaks report must be a JSON array of leaks")

    findings: list[CanonicalFinding] = []
    for leak in report:
        if not isinstance(leak, dict):
            raise GitleaksReportError("Each Gitleaks leak must be a JSON object")
        findings.append(
            _parse_leak(
                leak=leak,
                repository=repository,
                commit_sha=commit_sha,
            )
        )
    return findings


def _parse_leak(
    leak: dict[str, Any],
    repository: str,
    commit_sha: str,
) -> CanonicalFinding:
    """Translate one Gitleaks leak into one CanonicalFinding."""

    rule_id = _required_text(leak, "RuleID")
    path = _required_text(leak, "File")
    description = _optional_text(leak, "Description")
    start_line = _required_line_number(leak, "StartLine")
    end_line = _optional_line_number(leak, "EndLine")

    return CanonicalFinding(
        repository=repository,
        commit_sha=commit_sha,
        category=FindingCategory.SECRET,
        rule_id=rule_id,
        severity=GITLEAKS_SEVERITY,
        confidence=GITLEAKS_CONFIDENCE,
        title=description or f"Secret detected by rule {rule_id}",
        location=Location(
            path=path,
            start_line=start_line,
            end_line=end_line,
        ),
        tool="gitleaks",
    )


def _required_text(data: dict[str, Any], field: str) -> str:
    """Return a required non-empty string field from scanner data."""

    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise GitleaksReportError(f"Gitleaks leak requires non-empty '{field}'")
    return value


def _optional_text(data: dict[str, Any], field: str) -> str | None:
    """Return a non-empty optional string or None."""

    value = data.get(field)
    if isinstance(value, str) and value.strip():
        return value
    return None


def _required_line_number(data: dict[str, Any], field: str) -> int:
    """Return a required positive line number from scanner data."""

    value = data.get(field)
    if not isinstance(value, int) or value <= 0:
        raise GitleaksReportError(f"Gitleaks leak requires positive '{field}'")
    return value


def _optional_line_number(data: dict[str, Any], field: str) -> int | None:
    """Return a positive line number when Gitleaks provided it, else None."""

    value = data.get(field)
    if value is None:
        return None
    return _required_line_number(data, field)
