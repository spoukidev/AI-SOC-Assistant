from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Alert, AlertAssessment, NetworkEvent, Prediction
from .risk_score import calculate_risk


def create_ml_alert(db: Session, event: NetworkEvent, prediction: Prediction, model_name: str, model_version: str) -> Alert | None:
    if prediction.predicted_label != "malicious":
        return None
    existing = db.scalar(select(Alert).where(Alert.event_id == event.id))
    if existing:
        return existing
    repeated = db.scalar(select(func.count(NetworkEvent.id)).where(
        NetworkEvent.src_ip == event.src_ip,
        NetworkEvent.timestamp <= event.timestamp,
    )) or 0
    assessment = calculate_risk(probability=prediction.probability, repeated_activity=min(10, max(0, repeated - 1) * 2))
    now = datetime.now(timezone.utc)
    alert = Alert(
        event_id=event.id,
        title=f"ML detection: {prediction.predicted_label}",
        severity=assessment.severity,
        prediction=prediction.predicted_label,
        model_probability=prediction.probability,
        evidence_type="ML prediction",
        evidence=f"{model_name} ({model_version}) classified this flow as malicious. This is model evidence, not proof of malicious activity.",
        status="New",
        created_at=now,
    )
    db.add(alert)
    db.flush()
    db.add(AlertAssessment(
        alert_id=alert.id, risk_score=assessment.score,
        model_evidence=assessment.model_evidence, rule_evidence=assessment.rule_evidence,
        asset_context=assessment.asset_context, repeated_activity=assessment.repeated_activity,
        updated_at=now,
    ))
    return alert
