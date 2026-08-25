import json
from pathlib import Path

import pytest

from aegisflow.adapters.trivy import TrivyReportError, parse_trivy_report
from aegisflow.schemas.finding import FindingCategory, Severity

FIXTURE_PATH = Path("tests/fixtures/trivy_report.json")


def load_fixture() -> dict:
    with FIXTURE_PATH.open(encoding="utf-8") as fixture_file:
        return json.load(fixture_file)


def test_parse_trivy_report_normalizes_package_vulnerabilities() -> None:
    findings = parse_trivy_report(
        report=load_fixture(),
        repository="demo/vulnerable-service",
        commit_sha="0123456789abcdef",
    )

    assert len(findings) == 2

    first_finding = findings[0]
    assert first_finding.category is FindingCategory.SCA
    assert first_finding.rule_id == "CVE-2025-12345"
    assert first_finding.cve == "CVE-2025-12345"
    assert first_finding.severity is Severity.HIGH
    assert first_finding.fixed_version == "2.32.4"
    assert first_finding.severity_source == "ghsa"
    assert first_finding.location.package_name == "requests"
    assert first_finding.location.package_version == "2.31.0"
    assert first_finding.location.target == "requirements.txt"
    assert first_finding.location.start_line is None
    assert first_finding.tool == "trivy"


def test_parse_trivy_report_rejects_invalid_results_shape() -> None:
    with pytest.raises(TrivyReportError, match="list-valued 'Results'"):
        parse_trivy_report(
            report={"Results": "not a list"},
            repository="demo/vulnerable-service",
            commit_sha="0123456789abcdef",
        )