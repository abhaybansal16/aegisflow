from aegisflow.schemas.scoring import ContextualSignals, ScoreExplanation


def test_scoring_explanation_serialization() -> None:
    signals = ContextualSignals(
        is_exposed=True,
        is_exploitable=True,
        is_reachable=False,
        has_remediation=True,
    )

    explanation = ScoreExplanation(
        score=75,
        signals=signals,
        reasoning="Exposed and exploitable with a fix, but reachability is unconfirmed.",
    )

    data = explanation.model_dump()
    assert data["score"] == 75
    assert data["signals"]["is_exposed"] is True
    assert data["version"] == "contextual-v1"
