from pydantic import BaseModel, Field


class ContextualSignals(BaseModel):
    """
    Evidence signals with tri-state logic:
    - True: We have evidence it IS true.
    - False: We have evidence it is NOT true.
    - None: We do not have enough information (Unknown).
    """

    is_exposed: bool | None = Field(default=None)
    is_exploitable: bool | None = Field(default=None)
    is_reachable: bool | None = Field(default=None)
    has_remediation: bool | None = Field(default=None)


class ScoreExplanation(BaseModel):
    """Transparent breakdown of how a priority score was calculated."""

    score: int = Field(ge=0, le=100)
    version: str = "contextual-v1"
    signals: ContextualSignals
    reasoning: str
