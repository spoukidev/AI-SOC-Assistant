from app.models import Severity
from app.security.risk_score import calculate_risk


def test_probability_is_not_equivalent_to_severity():
    assessment = calculate_risk(probability=0.99)
    assert assessment.model_evidence == 54
    assert assessment.severity == Severity.medium


def test_risk_score_combines_bounded_evidence_components():
    assessment = calculate_risk(probability=0.90, rule_strength=25, asset_context=10, repeated_activity=10)
    assert assessment.score == 95
    assert assessment.severity == Severity.critical
    assert assessment.as_dict()["rule_evidence"] == 25
