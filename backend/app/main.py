from contextlib import asynccontextmanager
import math

import json
from pathlib import Path
from time import perf_counter
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload
from starlette.concurrency import run_in_threadpool

from .config import settings
from .auth import authenticate, create_access_token, get_auth_config, login_throttle, require_user
from .database import Base, SessionLocal, engine, ensure_schema, get_db
from .ml.detector import BaseDetector, DETECTORS, validate_parameters
from .ml.explain import safe_global_explanation, safe_local_explanation, unavailable
from .ml.preprocessing import MODEL_FEATURES, feature_frame
from .ml.training import train_experiment
from .models import Alert, AlertAssessment, DetectionRule, Experiment, FeatureVector, ImportBatch, Incident, ModelVersion, NetworkEvent, Prediction, Severity
from .security.alert_engine import create_ml_alert
from .security.risk_score import calculate_risk
from .seed import ensure_builtin_rules, seed_demo_data
from .services.csv_ingestion import read_csv_upload


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_schema(engine)
    get_auth_config()  # fail fast on a weak AUTH_SECRET_KEY and log generated credentials once
    with SessionLocal() as db:
        ensure_builtin_rules(db)
        if settings.seed_demo_data:
            seed_demo_data(db)
    yield


app = FastAPI(title=settings.app_name, version="0.5.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    # Only advertise the methods implemented by the API (reads, imports/training, triage, incident links).
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.middleware("http")
async def set_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


# Every data endpoint is registered on this router and requires a valid bearer token.
# Only /health and /api/auth/login stay open.
api = APIRouter(dependencies=[Depends(require_user)])


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "backend", "milestone": 5}


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


@app.post("/api/auth/login")
def login(credentials: LoginRequest, request: Request) -> dict:
    client = request.client.host if request.client else "unknown"
    if login_throttle.blocked(client):
        raise HTTPException(429, "Too many failed login attempts. Try again later.")
    if not authenticate(credentials.username, credentials.password):
        login_throttle.fail(client)
        raise HTTPException(401, "Invalid username or password", headers={"WWW-Authenticate": "Bearer"})
    login_throttle.reset(client)
    token, expires_in = create_access_token(credentials.username)
    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in, "username": credentials.username}


def serialize_event(event: NetworkEvent) -> dict:
    return {"id": event.id, "timestamp": event.timestamp, "src_ip": event.src_ip, "dst_ip": event.dst_ip,
            "src_port": event.src_port, "dst_port": event.dst_port, "protocol": event.protocol,
            "duration": event.duration, "packets": event.packets, "bytes": event.bytes,
            "tcp_flags": event.tcp_flags, "source": event.source, "raw_event": event.raw_event,
            "features": event.feature_vector.features if event.feature_vector else None}


def valid_model_probability(value: float | None) -> float | None:
    """Return only finite probabilities in the model's documented [0, 1] range."""
    if value is None or not math.isfinite(value) or not 0.0 <= value <= 1.0:
        return None
    return value


def serialize_alert(alert: Alert) -> dict:
    assessment = alert.assessment
    return {"id": alert.id, "timestamp": alert.created_at, "severity": alert.severity.value,
            "source": alert.event.src_ip, "destination": alert.event.dst_ip,
            "destination_port": alert.event.dst_port, "protocol": alert.event.protocol,
            "detection": alert.title, "prediction": alert.prediction,
            "model_probability": valid_model_probability(alert.model_probability), "evidence_type": alert.evidence_type,
            "evidence": alert.evidence, "status": alert.status,
            "risk_score": assessment.risk_score if assessment else None,
            "risk_components": {"model_evidence": assessment.model_evidence, "rule_evidence": assessment.rule_evidence,
                "asset_context": assessment.asset_context, "repeated_activity": assessment.repeated_activity} if assessment else None,
            "assigned_analyst": assessment.assigned_analyst if assessment else None,
            "updated_at": assessment.updated_at if assessment else alert.created_at,
            "synthetic": alert.event.source == "SYNTHETIC DEMO DATA",
            "rule_id": alert.rule_id, "incident_id": alert.incident_id}


@api.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db)) -> dict:
    alerts = list(db.scalars(select(Alert).options(joinedload(Alert.event), joinedload(Alert.assessment)).order_by(Alert.created_at.desc())).all())
    events_count = db.scalar(select(func.count(NetworkEvent.id))) or 0
    incidents_count = db.scalar(select(func.count(Incident.id)).where(Incident.status.not_in(CLOSED_INCIDENT_STATUSES))) or 0
    severity_counts = {severity.value: 0 for severity in Severity}
    protocol_counts: dict[str, int] = {}
    timeline: dict[str, int] = {}
    model_probabilities = [
        probability
        for alert in alerts
        if (probability := valid_model_probability(alert.model_probability)) is not None
    ]
    average_model_confidence = (
        round(sum(model_probabilities) / len(model_probabilities), 4)
        if model_probabilities
        else None
    )
    for alert in alerts:
        severity_counts[alert.severity.value] += 1
        protocol_counts[alert.event.protocol] = protocol_counts.get(alert.event.protocol, 0) + 1
        key = alert.created_at.strftime("%H:%M")
        timeline[key] = timeline.get(key, 0) + 1
    active = [item for item in alerts if item.status not in ("Resolved", "False Positive")]
    return {"data_label": "SYNTHETIC DEMO DATA + USER DATA", "metrics": {"active_alerts": len(active),
            "critical_alerts": severity_counts["Critical"], "high_alerts": severity_counts["High"],
            "open_incidents": incidents_count, "events_analyzed": events_count,
            "average_model_confidence": average_model_confidence}, "alerts_by_severity": severity_counts,
            "alerts_by_protocol": [{"name": k, "value": v} for k, v in protocol_counts.items()],
            "alerts_over_time": [{"time": k, "alerts": v} for k, v in sorted(timeline.items())],
            "recent_alerts": [serialize_alert(a) for a in alerts[:8]]}


@api.get("/api/events")
def events(
    protocol: str | None = Query(default=None, min_length=1, max_length=16),
    source: str | None = Query(default=None, min_length=1, max_length=300),
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
    db: Session = Depends(get_db),
) -> list[dict]:
    statement = select(NetworkEvent).options(joinedload(NetworkEvent.feature_vector))
    if protocol:
        statement = statement.where(NetworkEvent.protocol == protocol.upper())
    if source:
        statement = statement.where(NetworkEvent.source == source)
    statement = statement.order_by(NetworkEvent.timestamp.desc(), NetworkEvent.id.desc()).offset(offset).limit(limit)
    return [serialize_event(e) for e in db.scalars(statement).all()]


@api.get("/api/events/{event_id}")
def event(event_id: int, db: Session = Depends(get_db)) -> dict:
    item = db.scalar(select(NetworkEvent).where(NetworkEvent.id == event_id).options(joinedload(NetworkEvent.feature_vector)))
    if not item:
        raise HTTPException(404, "Event not found")
    return serialize_event(item)


@api.post("/api/events/import", status_code=201)
async def import_events(
    file: UploadFile = File(...),
    column_mapping: str | None = Form(None),
    db: Session = Depends(get_db),
) -> dict:
    parsed = await read_csv_upload(file, column_mapping)
    batch = ImportBatch(
        filename=parsed.filename,
        source_type="CSV",
        imported_at=datetime.now(timezone.utc),
        total_rows=parsed.total_rows,
        accepted_rows=len(parsed.events),
        rejected_rows=parsed.total_rows - len(parsed.events),
        column_mapping=parsed.mapping,
        errors=parsed.errors,
        synthetic=False,
    )
    db.add(batch)
    db.flush()
    for row in parsed.events:
        features = row.pop("features")
        event = NetworkEvent(
            timestamp=row["timestamp"], src_ip=row["src_ip"], dst_ip=row["dst_ip"],
            src_port=row["src_port"], dst_port=row["dst_port"], protocol=row["protocol"],
            duration=row["duration"], packets=row["packets"], bytes=row["bytes"],
            tcp_flags=row["tcp_flags"], source=f"CSV_IMPORT:{parsed.filename}", raw_event=row["raw_event"],
        )
        db.add(event)
        db.flush()
        db.add(FeatureVector(event_id=event.id, import_id=batch.id, schema_version="flow-v1", features=features))
    db.commit()
    return serialize_import(batch)


def serialize_import(batch: ImportBatch) -> dict:
    return {
        "id": batch.id, "filename": batch.filename, "source_type": batch.source_type,
        "imported_at": batch.imported_at, "total_rows": batch.total_rows,
        "accepted_rows": batch.accepted_rows, "rejected_rows": batch.rejected_rows,
        "column_mapping": batch.column_mapping, "errors": batch.errors, "synthetic": batch.synthetic,
    }


@api.get("/api/imports")
def imports(db: Session = Depends(get_db)) -> list[dict]:
    batches = db.scalars(select(ImportBatch).order_by(ImportBatch.imported_at.desc()).limit(50)).all()
    return [serialize_import(batch) for batch in batches]


@api.get("/api/research/dataset")
def dataset_profile(db: Session = Depends(get_db)) -> dict:
    event_count = db.scalar(select(func.count(NetworkEvent.id))) or 0
    imported_count = db.scalar(select(func.count(FeatureVector.id))) or 0
    protocols = db.execute(select(NetworkEvent.protocol, func.count(NetworkEvent.id)).group_by(NetworkEvent.protocol)).all()
    sources = db.execute(select(NetworkEvent.source, func.count(NetworkEvent.id)).group_by(NetworkEvent.source)).all()
    return {
        "name": "Current event store", "samples": event_count, "engineered_samples": imported_count,
        "feature_schema": "flow-v1", "feature_count": 12,
        "protocol_distribution": [{"name": name, "count": count} for name, count in protocols],
        "sources": [{"name": name, "count": count} for name, count in sources],
        "labels_available": False,
        "limitations": "Imported events are unlabeled. No train/test split or model metrics are available until a labeled experiment is run.",
    }


@api.get("/api/alerts")
def alerts(
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
    severity: Severity | None = Query(default=None),
    status: str | None = Query(default=None, min_length=1, max_length=32),
    db: Session = Depends(get_db),
) -> list[dict]:
    statement = select(Alert).options(joinedload(Alert.event), joinedload(Alert.assessment))
    if severity is not None:
        statement = statement.where(Alert.severity == severity)
    if status is not None:
        statement = statement.where(Alert.status == status)
    statement = statement.order_by(Alert.created_at.desc(), Alert.id.desc()).offset(offset).limit(limit)
    items = db.scalars(statement).all()
    return [serialize_alert(a) for a in items]


@api.get("/api/alerts/{alert_id}")
def alert(alert_id: int, db: Session = Depends(get_db)) -> dict:
    item = db.scalar(select(Alert).where(Alert.id == alert_id).options(
        joinedload(Alert.event).joinedload(NetworkEvent.feature_vector), joinedload(Alert.assessment),
        joinedload(Alert.rule), joinedload(Alert.incident)))
    if not item:
        raise HTTPException(404, "Alert not found")
    explanation = alert_explanation(db, item)
    return {**serialize_alert(item), "event": serialize_event(item.event), "mitre_mappings": [],
            "explanation": explanation, "explanation_status": explanation["status"],
            "rule": serialize_rule(item.rule) if item.rule else None,
            "incident": {"id": item.incident.id, "title": item.incident.title, "status": item.incident.status} if item.incident else None}


def alert_explanation(db: Session, item: Alert) -> dict:
    """Local SHAP explanation for ML alerts; an explicit not-applicable result for rule-only alerts."""
    if item.evidence_type != "ML prediction":
        return unavailable("Rule-based alert: no ML model scored this event, so there is no SHAP explanation. "
                           "Review the rule evidence instead.", status="not_applicable")
    prediction = db.scalar(select(Prediction).where(Prediction.event_id == item.event_id)
                           .order_by(Prediction.created_at.desc(), Prediction.id.desc()).limit(1))
    if prediction is None:
        return unavailable("No stored model prediction is linked to this alert.")
    model_version = db.get(ModelVersion, prediction.model_version_id)
    if model_version is None:
        return unavailable("The model version that produced this alert no longer exists.")
    features = item.event.feature_vector.features if item.event.feature_vector else None
    result = safe_local_explanation(model_version.artifact_path, settings.model_artifact_dir, features)
    return {**result, "model": serialize_model(model_version), "prediction_id": prediction.id}


class AlertUpdate(BaseModel):
    status: str | None = None
    assigned_analyst: str | None = Field(default=None, max_length=100)


@api.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: int, update: AlertUpdate, db: Session = Depends(get_db)) -> dict:
    item = db.scalar(select(Alert).where(Alert.id == alert_id).options(joinedload(Alert.event), joinedload(Alert.assessment)))
    if not item:
        raise HTTPException(404, "Alert not found")
    if update.status is not None:
        allowed = {"New", "Investigating", "Escalated", "Resolved", "False Positive"}
        if update.status not in allowed:
            raise HTTPException(422, f"status must be one of: {', '.join(sorted(allowed))}")
        item.status = update.status
    if not item.assessment:
        risk = calculate_risk(probability=item.model_probability, rule_strength=25 if "rule" in item.evidence_type.lower() else 0)
        item.assessment = AlertAssessment(alert_id=item.id, risk_score=risk.score,
            model_evidence=risk.model_evidence, rule_evidence=risk.rule_evidence,
            asset_context=risk.asset_context, repeated_activity=risk.repeated_activity,
            updated_at=datetime.now(timezone.utc))
    if "assigned_analyst" in update.model_fields_set:
        item.assessment.assigned_analyst = update.assigned_analyst.strip() if update.assigned_analyst else None
    item.assessment.updated_at = datetime.now(timezone.utc)
    db.commit()
    return serialize_alert(item)


def serialize_rule(rule: DetectionRule, alert_count: int | None = None) -> dict:
    data = {
        "id": rule.id, "key": rule.key, "name": rule.name, "description": rule.description,
        "logic": rule.logic, "scope": rule.scope, "risk_points": rule.risk_points, "enabled": rule.enabled,
        "version": rule.version, "limitations": rule.limitations, "built_in": rule.built_in,
        "created_at": rule.created_at, "updated_at": rule.updated_at,
    }
    if alert_count is not None:
        data["alert_count"] = alert_count
    return data


def rule_alert_counts(db: Session) -> dict[int, int]:
    rows = db.execute(select(Alert.rule_id, func.count(Alert.id)).where(Alert.rule_id.is_not(None)).group_by(Alert.rule_id)).all()
    return {rule_id: count for rule_id, count in rows}


@api.get("/api/detection-rules")
def detection_rules(db: Session = Depends(get_db)) -> list[dict]:
    counts = rule_alert_counts(db)
    rules = db.scalars(select(DetectionRule).order_by(DetectionRule.id)).all()
    return [serialize_rule(rule, counts.get(rule.id, 0)) for rule in rules]


@api.get("/api/detection-rules/{rule_id}")
def detection_rule(rule_id: int, db: Session = Depends(get_db)) -> dict:
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(404, "Detection rule not found")
    alerts = db.scalars(select(Alert).where(Alert.rule_id == rule_id).options(joinedload(Alert.event), joinedload(Alert.assessment))
                        .order_by(Alert.created_at.desc(), Alert.id.desc()).limit(50)).all()
    return {**serialize_rule(rule, rule_alert_counts(db).get(rule.id, 0)), "recent_alerts": [serialize_alert(a) for a in alerts]}


class DetectionRuleUpdate(BaseModel):
    enabled: bool | None = None
    risk_points: int | None = Field(default=None, ge=0, le=25)
    description: str | None = Field(default=None, min_length=1, max_length=2000)
    limitations: str | None = Field(default=None, min_length=1, max_length=2000)


@api.patch("/api/detection-rules/{rule_id}")
def update_detection_rule(rule_id: int, update: DetectionRuleUpdate, db: Session = Depends(get_db)) -> dict:
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(404, "Detection rule not found")
    changed = False
    for field in ("enabled", "risk_points", "description", "limitations"):
        value = getattr(update, field)
        if field in update.model_fields_set and value is not None and getattr(rule, field) != value:
            setattr(rule, field, value.strip() if isinstance(value, str) else value)
            changed = True
    if changed:
        # Existing alerts keep the evidence and risk they were created with; the version records the change.
        rule.version += 1
        rule.updated_at = datetime.now(timezone.utc)
    db.commit()
    return serialize_rule(rule, rule_alert_counts(db).get(rule.id, 0))


INCIDENT_STATUSES = ("Open", "Investigating", "Contained", "Resolved", "Closed")
CLOSED_INCIDENT_STATUSES = ("Resolved", "Closed")


def serialize_incident(incident: Incident, alert_count: int) -> dict:
    return {"id": incident.id, "title": incident.title, "severity": incident.severity.value, "status": incident.status,
            "summary": incident.summary, "first_seen": incident.first_seen, "last_seen": incident.last_seen,
            "synthetic": incident.synthetic, "alert_count": alert_count}


def incident_alert_counts(db: Session) -> dict[int, int]:
    rows = db.execute(select(Alert.incident_id, func.count(Alert.id)).where(Alert.incident_id.is_not(None)).group_by(Alert.incident_id)).all()
    return {incident_id: count for incident_id, count in rows}


def load_incident(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident


def incident_detail(db: Session, incident: Incident) -> dict:
    alerts = db.scalars(select(Alert).where(Alert.incident_id == incident.id)
                        .options(joinedload(Alert.event), joinedload(Alert.assessment))
                        .order_by(Alert.created_at, Alert.id)).all()
    return {**serialize_incident(incident, len(alerts)), "alerts": [serialize_alert(a) for a in alerts]}


def link_alerts(db: Session, incident: Incident, alert_ids: list[int]) -> None:
    unique_ids = list(dict.fromkeys(alert_ids))
    alerts = db.scalars(select(Alert).where(Alert.id.in_(unique_ids))).all() if unique_ids else []
    missing = sorted(set(unique_ids) - {a.id for a in alerts})
    if missing:
        raise HTTPException(404, f"Alerts not found: {', '.join(map(str, missing))}")
    for item in alerts:
        item.incident_id = incident.id
    db.flush()
    refresh_incident_window(db, incident)


def refresh_incident_window(db: Session, incident: Incident) -> None:
    first, last = db.execute(select(func.min(Alert.created_at), func.max(Alert.created_at))
                             .where(Alert.incident_id == incident.id)).one()
    if first is not None:
        incident.first_seen, incident.last_seen = first, last


@api.get("/api/incidents")
def incidents(
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
    status: str | None = Query(default=None, min_length=1, max_length=32),
    db: Session = Depends(get_db),
) -> list[dict]:
    statement = select(Incident)
    if status is not None:
        statement = statement.where(Incident.status == status)
    statement = statement.order_by(Incident.last_seen.desc(), Incident.id.desc()).offset(offset).limit(limit)
    counts = incident_alert_counts(db)
    return [serialize_incident(i, counts.get(i.id, 0)) for i in db.scalars(statement).all()]


@api.get("/api/incidents/{incident_id}")
def incident(incident_id: int, db: Session = Depends(get_db)) -> dict:
    return incident_detail(db, load_incident(db, incident_id))


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    severity: Severity = Severity.medium
    summary: str = Field(min_length=1, max_length=5000)
    alert_ids: list[int] = Field(default_factory=list, max_length=100)


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    severity: Severity | None = None
    status: str | None = None
    summary: str | None = Field(default=None, min_length=1, max_length=5000)


class IncidentAlertLink(BaseModel):
    alert_ids: list[int] = Field(min_length=1, max_length=100)


@api.post("/api/incidents", status_code=201)
def create_incident(payload: IncidentCreate, db: Session = Depends(get_db)) -> dict:
    now = datetime.now(timezone.utc)
    item = Incident(title=payload.title.strip(), severity=payload.severity, status="Open",
                    summary=payload.summary.strip(), first_seen=now, last_seen=now, synthetic=False)
    db.add(item)
    db.flush()
    link_alerts(db, item, payload.alert_ids)
    db.commit()
    return incident_detail(db, item)


@api.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: int, update: IncidentUpdate, db: Session = Depends(get_db)) -> dict:
    item = load_incident(db, incident_id)
    if update.status is not None:
        if update.status not in INCIDENT_STATUSES:
            raise HTTPException(422, f"status must be one of: {', '.join(INCIDENT_STATUSES)}")
        item.status = update.status
    if update.title is not None:
        item.title = update.title.strip()
    if update.summary is not None:
        item.summary = update.summary.strip()
    if update.severity is not None:
        item.severity = update.severity
    db.commit()
    return incident_detail(db, item)


@api.post("/api/incidents/{incident_id}/alerts")
def add_incident_alerts(incident_id: int, payload: IncidentAlertLink, db: Session = Depends(get_db)) -> dict:
    item = load_incident(db, incident_id)
    link_alerts(db, item, payload.alert_ids)
    db.commit()
    return incident_detail(db, item)


@api.delete("/api/incidents/{incident_id}/alerts/{alert_id}")
def remove_incident_alert(incident_id: int, alert_id: int, db: Session = Depends(get_db)) -> dict:
    item = load_incident(db, incident_id)
    linked = db.scalar(select(Alert).where(Alert.id == alert_id, Alert.incident_id == incident_id))
    if not linked:
        raise HTTPException(404, "Alert is not linked to this incident")
    linked.incident_id = None
    db.flush()
    refresh_incident_window(db, item)
    db.commit()
    return incident_detail(db, item)


@api.get("/api/research/metrics")
def research_metrics(db: Session = Depends(get_db)) -> dict:
    experiments = db.scalars(select(Experiment).order_by(Experiment.created_at.desc())).all()
    if not experiments:
        return {"available": False, "message": "No experiment results available."}
    return {"available": True, "experiments": [serialize_experiment(item) for item in experiments]}


def serialize_experiment(item: Experiment) -> dict:
    return {
        "id": item.id, "name": item.name, "dataset_name": item.dataset_name,
        "dataset_sha256": item.dataset_sha256, "model_name": item.model_name,
        "parameters": item.parameters, "features": item.features, "metrics": item.metrics,
        "split": item.split, "random_seed": item.random_seed,
        "training_time_ms": item.training_time_ms, "inference_time_ms": item.inference_time_ms,
        "created_at": item.created_at, "notes": item.notes,
    }


def serialize_model(item: ModelVersion) -> dict:
    return {
        "id": item.id, "experiment_id": item.experiment_id, "model_name": item.model_name,
        "version": item.version, "feature_schema": item.feature_schema,
        "positive_label": item.positive_label, "created_at": item.created_at, "active": item.active,
    }


@api.get("/api/experiments")
def experiments(db: Session = Depends(get_db)) -> list[dict]:
    items = db.scalars(select(Experiment).order_by(Experiment.created_at.desc())).all()
    return [serialize_experiment(item) for item in items]


@api.post("/api/experiments", status_code=201)
async def create_experiment(
    file: UploadFile = File(...),
    model_name: str = Form(...),
    name: str | None = Form(None),
    random_seed: int = Form(42),
    parameters: str | None = Form(None),
    notes: str | None = Form(None),
    db: Session = Depends(get_db),
) -> dict:
    if model_name not in DETECTORS:
        raise HTTPException(422, f"model_name must be one of: {', '.join(DETECTORS)}")
    filename = Path(file.filename or "labeled-dataset.csv").name
    if not filename.lower().endswith(".csv"):
        raise HTTPException(415, "Training datasets must be .csv files")
    content = await file.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(413, f"Dataset exceeds the {settings.max_upload_bytes // (1024 * 1024)} MB limit")
    try:
        parsed_parameters = json.loads(parameters) if parameters else {}
    except json.JSONDecodeError as exc:
        raise HTTPException(422, "parameters must be valid JSON") from exc
    if not isinstance(parsed_parameters, dict):
        raise HTTPException(422, "parameters must be a JSON object")
    try:
        parsed_parameters = validate_parameters(model_name, parsed_parameters)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    try:
        result = await run_in_threadpool(
            train_experiment, content, model_name, settings.model_artifact_dir, random_seed, parsed_parameters,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    created_at = datetime.now(timezone.utc)
    experiment = Experiment(
        name=(name or f"{model_name} baseline")[:200], dataset_name=filename[:255],
        dataset_sha256=result.dataset_metadata["sha256"], model_name=model_name,
        parameters=result.parameters, features=MODEL_FEATURES, metrics={**result.metrics, "validation": result.validation_metrics,
            "class_distribution": result.dataset_metadata["class_distribution"],
            "dataset_label": "SYNTHETIC DEMO DATA" if "synthetic" in filename.lower() else "USER-SUPPLIED LABELED DATASET"},
        split=result.split, random_seed=random_seed, training_time_ms=result.training_time_ms,
        inference_time_ms=result.inference_time_ms, created_at=created_at, notes=(notes or None),
    )
    db.add(experiment)
    db.flush()
    model = ModelVersion(
        experiment_id=experiment.id, model_name=model_name, version=result.version,
        artifact_path=result.artifact_path, feature_schema="flow-v1", positive_label="malicious",
        created_at=created_at, active=True,
    )
    db.add(model)
    db.commit()
    return {"experiment": serialize_experiment(experiment), "model": serialize_model(model)}


@api.get("/api/models")
def models(db: Session = Depends(get_db)) -> list[dict]:
    items = db.scalars(select(ModelVersion).order_by(ModelVersion.created_at.desc())).all()
    return [serialize_model(item) for item in items]


@api.get("/api/models/{model_id}")
def model(model_id: int, db: Session = Depends(get_db)) -> dict:
    item = db.get(ModelVersion, model_id)
    if not item:
        raise HTTPException(404, "Model version not found")
    experiment = db.get(Experiment, item.experiment_id)
    return {**serialize_model(item), "experiment": serialize_experiment(experiment)}


@api.post("/api/models/{model_id}/predict/{event_id}", status_code=201)
def predict_event(model_id: int, event_id: int, db: Session = Depends(get_db)) -> dict:
    model_version = db.get(ModelVersion, model_id)
    event = db.scalar(select(NetworkEvent).where(NetworkEvent.id == event_id).options(joinedload(NetworkEvent.feature_vector)))
    if not model_version:
        raise HTTPException(404, "Model version not found")
    if not event:
        raise HTTPException(404, "Event not found")
    if not event.feature_vector:
        raise HTTPException(422, "Event has no flow-v1 feature vector")
    artifact_path = Path(model_version.artifact_path).resolve()
    if not artifact_path.is_relative_to(Path(settings.model_artifact_dir).resolve()) or not artifact_path.is_file():
        raise HTTPException(503, "Model artifact is unavailable")
    artifact = BaseDetector.load_artifact(artifact_path, allowed_dir=settings.model_artifact_dir)
    pipeline = artifact["pipeline"]
    frame = feature_frame(event.feature_vector.features)
    started = perf_counter()
    predicted = int(pipeline.predict(frame)[0])
    probability = float(pipeline.predict_proba(frame)[0, 1])
    elapsed_ms = (perf_counter() - started) * 1000
    prediction = Prediction(
        event_id=event.id, model_version_id=model_version.id,
        predicted_label="malicious" if predicted == 1 else "benign",
        probability=probability, inference_time_ms=elapsed_ms, created_at=datetime.now(timezone.utc),
    )
    db.add(prediction)
    db.flush()
    generated_alert = create_ml_alert(db, event, prediction, model_version.model_name, model_version.version)
    db.commit()
    return {
        "id": prediction.id, "event_id": event.id, "model": serialize_model(model_version),
        "predicted_label": prediction.predicted_label, "probability": probability,
        "inference_time_ms": elapsed_ms, "evidence_type": "ML prediction",
        "severity": generated_alert.severity.value if generated_alert else None,
        "alert_id": generated_alert.id if generated_alert else None,
        "explanation": safe_local_explanation(model_version.artifact_path, settings.model_artifact_dir,
                                              event.feature_vector.features),
    }


@api.get("/api/predictions")
def predictions(db: Session = Depends(get_db)) -> list[dict]:
    items = db.scalars(select(Prediction).order_by(Prediction.created_at.desc()).limit(100)).all()
    return [{"id": item.id, "event_id": item.event_id, "model_version_id": item.model_version_id,
             "predicted_label": item.predicted_label, "probability": item.probability,
             "inference_time_ms": item.inference_time_ms, "created_at": item.created_at} for item in items]


@api.get("/api/models/{model_id}/explanation")
def model_explanation(model_id: int, db: Session = Depends(get_db)) -> dict:
    """Global SHAP feature importance over the model's stored training background sample."""
    item = db.get(ModelVersion, model_id)
    if not item:
        raise HTTPException(404, "Model version not found")
    return {**safe_global_explanation(item.artifact_path, settings.model_artifact_dir), "model": serialize_model(item)}


@api.get("/api/auth/me")
def me(request: Request) -> dict:
    return {"username": request.state.user}


app.include_router(api)
