"""Normalize Trivy vulnerability reports into AegisFlow findings."""

from __future__ import annotations

from typing import Any

from aegisflow.schemas.finding import (
    CanonicalFinding,
    FindingCategory,
    Location,
    Severity,
)


class TrivyReportError(ValueError):
    """Raised when a Trivy report cannot be normalized safely."""


def parse_trivy_report(
    report: dict[str, Any],
    repository: str,
    commit_sha: str,
) -> list[CanonicalFinding]:
    """Convert Trivy package vulnerabilities into canonical findings."""

    results = report.get("Results")
    if not isinstance(results, list):
        raise TrivyReportError("Trivy report requires a list-valued 'Results' field")

    findings: list[CanonicalFinding] = []
    for result in results:
        if not isinstance(result, dict):
            raise TrivyReportError("Each Trivy result must be a JSON object")

        target = _require_string(result, "Target", "Trivy result")
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise TrivyReportError(
                "Trivy result field 'Vulnerabilities' must be a list when present"
            )

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise TrivyReportError("Each Trivy vulnerability must be a JSON object")
            findings.append(
                _normalize_vulnerability(
                    vulnerability=vulnerability,
                    repository=repository,
                    commit_sha=commit_sha,
                    target=target,
                )
            )

    return findings


def _normalize_vulnerability(
    vulnerability: dict[str, Any],
    repository: str,
    commit_sha: str,
    target: str,
) -> CanonicalFinding:
    """Normalize one Trivy vulnerability record."""

    vulnerability_id = _require_string(
        vulnerability,
        "VulnerabilityID",
        "Trivy vulnerability",
    )
    package_name = _require_string(vulnerability, "PkgName", "Trivy vulnerability")
    installed_version = _require_string(
        vulnerability,
        "InstalledVersion",
        "Trivy vulnerability",
    )
    severity = _parse_severity(_require_string(vulnerability, "Severity", "Trivy vulnerability"))
    title = _optional_string(vulnerability, "Title")

    return CanonicalFinding(
        repository=repository,
        commit_sha=commit_sha,
        category=FindingCategory.SCA,
        rule_id=vulnerability_id,
        cve=vulnerability_id if vulnerability_id.startswith("CVE-") else None,
        fixed_version=_optional_string(vulnerability, "FixedVersion"),
        severity_source=_optional_string(vulnerability, "SeveritySource"),
        severity=severity,
        confidence=0.9,
        title=title or f"{vulnerability_id} affects {package_name}",
        location=Location(
            package_name=package_name,
            package_version=installed_version,
            target=target,
        ),
        tool="trivy",
    )


def _require_string(value: dict[str, Any], key: str, context: str) -> str:
    """Return a required non-empty string from a JSON object."""

    field_value = value.get(key)
    if not isinstance(field_value, str) or not field_value.strip():
        raise TrivyReportError(f"{context} requires a non-empty '{key}' field")
    return field_value


def _optional_string(value: dict[str, Any], key: str) -> str | None:
    """Return a non-empty optional string or None."""

    field_value = value.get(key)
    if isinstance(field_value, str) and field_value.strip():
        return field_value
    return None


def _parse_severity(raw_severity: str) -> Severity:
    """Translate Trivy's uppercase severity label into the shared enum."""

    try:
        return Severity(raw_severity.lower())
    except ValueError as error:
        raise TrivyReportError(
            f"Unsupported Trivy severity '{raw_severity}'"
        ) from error