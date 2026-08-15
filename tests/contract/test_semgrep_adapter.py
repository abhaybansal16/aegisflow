import json
from pathlib import Path

import pytest

from aegisflow.adapters.semgrep import SemgrepReportError, parse_semgrep_report
from aegisflow.schemas.finding import FindingCategory, Severity

FIXTURE_PATH = Path("tests/fixtures/semgrep_report.json")


def load_fixture() -> dict:
    with FIXTURE_PATH.open(encoding="utf-8") as fixture_file:
        return json.load(fixture_file)


def test_semgrep_adapter_creates_a_canonical_sast_finding() -> None:
    findings = parse_semgrep_report(
        report=load_fixture(),
        repository="demo/vulnerable-service",
        commit_sha="0123456789abcdef",
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.SAST
    assert finding.tool == "semgrep"
    assert finding.rule_id == "python.flask.security.injection.sqlalchemy.text"
    assert finding.severity is Severity.HIGH
    assert finding.location.path == "src/query.py"
    assert finding.location.start_line == 64


def test_semgrep_adapter_rejects_a_report_without_a_results_list() -> None:
    with pytest.raises(SemgrepReportError, match="list-valued 'results'"):
        parse_semgrep_report(
            report={"results": "not a list"},
            repository="demo/vulnerable-service",
            commit_sha="0123456789abcdef",
        )