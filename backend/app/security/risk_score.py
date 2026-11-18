from dataclasses import asdict, dataclass

from ..models import Severity


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    severity: Severity
    model_evidence: int
    rule_evidence: int
    asset_context: int
    repeated_activity: int

    def as_dict(self) -> dict:
        return {**asdict(self), "severity": self.severity.value}


def severity_for_score(score: int) -> Severity:
    if score >= 85:
        return Severity.critical
    if score >= 65:
        return Severity.high
    if score >= 40:
        return Severity.medium
    if score >= 20:
        return Severity.low
    return Severity.informational


def calculate_risk(
    *, probability: float | None = None, rule_strength: int = 0,
    asset_context: int = 0, repeated_activity: int = 0,
) -> RiskAssessment:
    """Add independent evidence components; probability alone cannot create Critical risk."""
    model_evidence = round(max(0.0, min(1.0, probability or 0.0)) * 55)
    components = {
        "model_evidence": model_evidence,
        "rule_evidence": max(0, min(25, rule_strength)),
        "asset_context": max(0, min(10, asset_context)),
        "repeated_activity": max(0, min(10, repeated_activity)),
    }
    score = min(100, sum(components.values()))
    return RiskAssessment(score=score, severity=severity_for_score(score), **components)
