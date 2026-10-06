import json
from pathlib import Path

import pytest

from aegisflow.adapters.gitleaks import GitleaksReportError, parse_gitleaks_report
from aegisflow.schemas.finding import FindingCategory, Severity

FIXTURE_PATH = Path("tests/fixtures/gitleaks_report.json")


def load_fixture() -> list:
    with FIXTURE_PATH.open(encoding="utf-8") as fixture_file:
        return json.load(fixture_file)


def test_gitleaks_adapter_creates_a_canonical_secret_finding() -> None:
    findings = parse_gitleaks_report(
        report=load_fixture(),
        repository="demo/vulnerable-service",
        commit_sha="0123456789abcdef",
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.SECRET
    assert finding.tool == "gitleaks"
    assert finding.rule_id == "generic-api-key"
    assert finding.severity is Severity.HIGH
    assert finding.title == "Generic API Key"
    assert finding.location.path == "src/config.py"
    assert finding.location.start_line == 12
    assert finding.location.end_line == 12


def test_gitleaks_adapter_rejects_a_report_that_is_not_a_list() -> None:
    with pytest.raises(GitleaksReportError, match="JSON array"):
        parse_gitleaks_report(
            report={"not": "a list"},
            repository="demo/vulnerable-service",
            commit_sha="0123456789abcdef",
        )


def test_gitleaks_adapter_falls_back_to_rule_id_when_description_is_missing() -> None:
    leak = load_fixture()[0]
    del leak["Description"]

    findings = parse_gitleaks_report(
        report=[leak],
        repository="demo/vulnerable-service",
        commit_sha="0123456789abcdef",
    )

    assert findings[0].title == "Secret detected by rule generic-api-key"
