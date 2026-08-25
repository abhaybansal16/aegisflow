"""The first version of AegisFlow's shared finding contract."""

from enum import Enum

from pydantic import BaseModel, Field, model_validator


class FindingCategory(str, Enum):
    """The scanner family that produced a normalized finding."""

    SAST = "sast"
    SCA = "sca"
    SECRET = "secret"
    CONTAINER = "container"


class Severity(str, Enum):
    """AegisFlow's small, normalized severity scale."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Location(BaseModel):
    """A code or package location reported by a security scanner."""

    path: str | None = None
    start_line: int | None = Field(default=None, gt=0)
    end_line: int | None = Field(default=None, gt=0)
    package_name: str | None = None
    package_version: str | None = None
    target: str | None = None

    @model_validator(mode="after")
    def validate_location_kind(self) -> "Location":
        """Require either a source path or a package identity."""

        if not self.path and not self.package_name:
            raise ValueError("location requires a path or package_name")
        if (
            self.start_line is not None
            and self.end_line is not None
            and self.end_line < self.start_line
        ):
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class CanonicalFinding(BaseModel):
    """A scanner-normalized security finding used by downstream AegisFlow code."""

    schema_version: str = "1.0"
    repository: str
    commit_sha: str
    category: FindingCategory
    rule_id: str | None = None
    cve: str | None = None
    fixed_version: str | None = None
    severity_source: str | None = None
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    location: Location
    tool: str