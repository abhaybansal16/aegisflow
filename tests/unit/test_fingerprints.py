from aegisflow.schemas.finding import (
    CanonicalFinding,
    FindingCategory,
    Location,
    Severity,
)
from aegisflow.services.fingerprints import create_finding_fingerprint


def make_package_finding(installed_version: str) -> CanonicalFinding:
    """Build one package vulnerability with a variable observed version."""

    return CanonicalFinding(
        repository="demo/vulnerable-service",
        commit_sha="0123456789abcdef",
        category=FindingCategory.SCA,
        rule_id="CVE-2025-12345",
        cve="CVE-2025-12345",
        fixed_version="2.32.4",
        severity=Severity.HIGH,
        confidence=0.9,
        title="Example vulnerability in requests",
        location=Location(
            package_name="requests",
            package_version=installed_version,
            target="requirements.txt",
        ),
        tool="trivy",
    )


def test_package_fingerprint_ignores_observed_installed_version() -> None:
    older_observation = make_package_finding("2.31.0")
    newer_observation = make_package_finding("2.31.1")

    assert create_finding_fingerprint(older_observation) == create_finding_fingerprint(
        newer_observation
    )


def test_package_fingerprint_changes_when_target_changes() -> None:
    requirements_finding = make_package_finding("2.31.0")
    image_finding = requirements_finding.model_copy(
        update={
            "location": Location(
                package_name="requests",
                package_version="2.31.0",
                target="service-image:1.0.0",
            )
        }
    )

    assert create_finding_fingerprint(requirements_finding) != create_finding_fingerprint(
        image_finding
    )