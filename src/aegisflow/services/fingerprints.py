"""Create deterministic identities for normalized AegisFlow findings."""

from hashlib import sha256

from aegisflow.schemas.finding import CanonicalFinding


def create_finding_fingerprint(finding: CanonicalFinding) -> str:
    """Return a stable identity for one durable normalized finding."""

    identity_parts = [
        finding.repository,
        finding.category.value,
        finding.rule_id or "",
        *_location_identity_parts(finding),
    ]
    canonical_value = "\x00".join(identity_parts)
    return sha256(canonical_value.encode("utf-8")).hexdigest()


def _location_identity_parts(finding: CanonicalFinding) -> list[str]:
    """Choose identity fields that match the source or package evidence kind."""

    location = finding.location
    if location.path is not None:
        return [
            "source",
            location.path,
            str(location.start_line or ""),
        ]

    return [
        "package",
        location.package_name or "",
        location.target or "",
    ]