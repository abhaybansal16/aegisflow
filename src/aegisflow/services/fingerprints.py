"""Create deterministic identities for normalized AegisFlow findings."""

from hashlib import sha256

from aegisflow.schemas.finding import CanonicalFinding


def create_finding_fingerprint(finding: CanonicalFinding) -> str:
    """Return a stable SHA-256 digest for the same normalized source finding.

    This first version deliberately uses repository, category, rule, file path,
    and start line. We will improve the strategy later for code movement and
    cross-tool correlation.
    """

    identity_parts = [
        finding.repository,
        finding.category.value,
        finding.rule_id or "",
        finding.location.path,
        str(finding.location.start_line),
    ]
    canonical_value = "\x00".join(identity_parts)
    return sha256(canonical_value.encode("utf-8")).hexdigest()