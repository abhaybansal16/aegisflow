"""The first version of AegisFlow's shared finding contract."""

from enum import Enum

from pydantic import BaseModel, Field


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
    """The source-code location reported by a scanner."""

    path: str
    start_line: int = Field(gt=0)
    end_line: int | None = Field(default=None, gt=0)


class CanonicalFinding(BaseModel):
    """A scanner-normalized security finding used by downstream AegisFlow code."""

    schema_version: str = "1.0"
    repository: str
    commit_sha: str
    category: FindingCategory
    rule_id: str | None = None
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    location: Location
    tool: str