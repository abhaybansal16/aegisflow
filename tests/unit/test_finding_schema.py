import pytest
from pydantic import ValidationError

from aegisflow.schemas.finding import (
    CanonicalFinding,
    FindingCategory,
    Location,
    Severity,
)


def test_canonical_finding_accepts_valid_sast_data() -> None:
    finding = CanonicalFinding(
        repository="demo/vulnerable-service",
        commit_sha="0123456789abcdef",
        category=FindingCategory.SAST,
        rule_id="python.sql-injection",
        severity=Severity.HIGH,
        confidence=0.95,
        title="Untrusted input reaches a SQL query",
        location=Location(path="src/query.py", start_line=64),
        tool="semgrep",
    )

    assert finding.schema_version == "1.0"
    assert finding.location.path == "src/query.py"
    assert finding.severity is Severity.HIGH


def test_canonical_finding_rejects_confidence_above_one() -> None:
    with pytest.raises(ValidationError):
        CanonicalFinding(
            repository="demo/vulnerable-service",
            commit_sha="0123456789abcdef",
            category=FindingCategory.SAST,
            severity=Severity.HIGH,
            confidence=1.5,
            title="Invalid confidence example",
            location=Location(path="src/query.py", start_line=64),
            tool="semgrep",
        )


def test_location_rejects_zero_line_number() -> None:
    with pytest.raises(ValidationError):
        Location(path="src/query.py", start_line=0)