"""Translate a small Semgrep JSON report into AegisFlow findings."""

from typing import Any

from aegisflow.schemas.finding import (
    CanonicalFinding,
    FindingCategory,
    Location,
    Severity,
)


class SemgrepReportError(ValueError):
    """Raised when a report does not have the Semgrep structure we expect."""


SEMGREP_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "ERROR": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "WARNING": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.LOW,
}


def parse_semgrep_report(
    report: dict[str, Any],
    repository: str,
    commit_sha: str,
) -> list[CanonicalFinding]:
    """Convert every Semgrep result in a decoded JSON report into a finding."""

    results = report.get("results")
    if not isinstance(results, list):
        raise SemgrepReportError("Semgrep report requires a list-valued 'results' field")

    findings: list[CanonicalFinding] = []
    for result in results:
        findings.append(
            _parse_result(
                result=result,
                repository=repository,
                commit_sha=commit_sha,
            )
        )
    return findings


def _parse_result(
    result: dict[str, Any],
    repository: str,
    commit_sha: str,
) -> CanonicalFinding:
    """Translate one Semgrep result into one CanonicalFinding."""

    extra = result.get("extra", {})
    start = result.get("start", {})
    end = result.get("end", {})

    if not isinstance(extra, dict):
        raise SemgrepReportError("Semgrep result has invalid 'extra' data")
    if not isinstance(start, dict) or not isinstance(end, dict):
        raise SemgrepReportError("Semgrep result has invalid source positions")

    rule_id = _required_text(result, "check_id")
    path = _required_text(result, "path")
    message = _required_text(extra, "message")
    severity_name = _required_text(extra, "severity").upper()
    severity = SEMGREP_SEVERITY_MAP.get(severity_name, Severity.MEDIUM)

    return CanonicalFinding(
        repository=repository,
        commit_sha=commit_sha,
        category=FindingCategory.SAST,
        rule_id=rule_id,
        severity=severity,
        confidence=0.70,
        title=message,
        location=Location(
            path=path,
            start_line=_required_line_number(start, "line"),
            end_line=_optional_line_number(end, "line"),
        ),
        tool="semgrep",
    )


def _required_text(data: dict[str, Any], field: str) -> str:
    """Return a required non-empty string field from scanner data."""

    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise SemgrepReportError(f"Semgrep result requires non-empty '{field}'")
    return value


def _required_line_number(data: dict[str, Any], field: str) -> int:
    """Return a required positive line number from scanner data."""

    value = data.get(field)
    if not isinstance(value, int) or value <= 0:
        raise SemgrepReportError(f"Semgrep result requires positive '{field}'")
    return value


def _optional_line_number(data: dict[str, Any], field: str) -> int | None:
    """Return a positive line number when Semgrep provided it, else None."""

    value = data.get(field)
    if value is None:
        return None
    return _required_line_number(data, field)