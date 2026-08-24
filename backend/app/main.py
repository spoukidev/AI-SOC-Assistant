from contextlib import asynccontextmanager

import json
from pathlib import Path
from time import perf_counter
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload
from starlette.concurrency import run_in_threadpool

from .config import settings
from .database import Base, SessionLocal, engine, get_db
from .ml.detector import BaseDetector, DETECTORS
from .ml.preprocessing import MODEL_FEATURES, feature_frame
from .ml.training import train_experiment
from .models import Alert, AlertAssessment, Experiment, FeatureVector, ImportBatch, Incident, ModelVersion, NetworkEvent, Prediction, Severity
from .security.alert_engine import create_ml_alert
from .security.risk_score import calculate_risk
from .seed import seed_demo_data
from .services.csv_ingestion import read_csv_upload


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    if settings.seed_demo_data:
        with SessionLocal() as db:
            seed_demo_data(db)
    yield


app = FastAPI(title=settings.app_name, version="0.4.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PATCH"], allow_headers=["Content-Type", "Authorization"])


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "backend", "milestone": 4}


def serialize_event(event: NetworkEvent) -> dict:
    return {"id": event.id, "timestamp": event.timestamp, "src_ip": event.src_ip, "dst_ip": event.dst_ip,
            "src_port": event.src_port, "dst_port": event.dst_port, "protocol": event.protocol,
            "duration": event.duration, "packets": event.packets, "bytes": event.bytes,
            "tcp_flags": event.tcp_flags, "source": event.source, "raw_event": event.raw_event,
            "features": event.feature_vector.features if event.feature_vector else None}


def serialize_alert(alert: Alert) -> dict:
    assessment = alert.assessment
    return {"id": alert.id, "timestamp": alert.created_at, "severity": alert.severity.value,
            "source": alert.event.src_ip, "destination": alert.event.dst_ip,
            "destination_port": alert.event.dst_port, "protocol": alert.event.protocol,
            "detection": alert.title, "prediction": alert.prediction,
            "model_probability": alert.model_probability, "evidence_type": alert.evidence_type,
            "evidence": alert.evidence, "status": alert.status,
            "risk_score": assessment.risk_score if assessment else None,
            "risk_components": {"model_evidence": assessment.model_evidence, "rule_evidence": assessment.rule_evidence,
                "asset_context": assessment.asset_context, "repeated_activity": assessment.repeated_activity} if assessment else None,
            "assigned_analyst": assessment.assigned_analyst if assessment else None,
            "updated_at": assessment.updated_at if assessment else alert.created_at,
            "synthetic": alert.event.source == "SYNTHETIC DEMO DATA"}


@app.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db)) -> dict:
    alerts = list(db.scalars(select(Alert).options(joinedload(Alert.event), joinedload(Alert.assessment)).order_by(Alert.created_at.desc())).all())
    events_count = db.scalar(select(func.count(NetworkEvent.id))) or 0
    incidents_count = db.scalar(select(func.count(Incident.id)).where(Incident.status == "Open")) or 0
    severity_counts = {severity.value: 0 for severity in Severity}
    protocol_counts: dict[str, int] = {}
    timeline: dict[str, int] = {}
    for alert in alerts:
        severity_counts[alert.severity.value] += 1
        protocol_counts[alert.event.protocol] = protocol_counts.get(alert.event.protocol, 0) + 1
        key = alert.created_at.strftime("%H:%M")
        timeline[key] = timeline.get(key, 0) + 1
    active = [item for item in alerts if item.status not in ("Resolved", "False Positive")]
    confidences = [item.model_probability for item in alerts if item.model_probability is not None]
    return {"data_label": "SYNTHETIC DEMO DATA + USER DATA", "metrics": {"active_alerts": len(active),
            "critical_alerts": severity_counts["Critical"], "high_alerts": severity_counts["High"],
            "open_incidents": incidents_count, "events_analyzed": events_count,
            "average_model_confidence": sum(confidences) / len(confidences) if confidences else None}, "alerts_by_severity": severity_counts,
            "alerts_by_protocol": [{"name": k, "value": v} for k, v in protocol_counts.items()],
            "alerts_over_time": [{"time": k, "alerts": v} for k, v in sorted(timeline.items())],
            "recent_alerts": [serialize_alert(a) for a in alerts[:8]]}


@app.get("/api/events")
def events(
    protocol: str | None = None,
    source: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> list[dict]:
    statement = select(NetworkEvent).options(joinedload(NetworkEvent.feature_vector)).order_by(NetworkEvent.timestamp.desc())
    if protocol:
        statement = statement.where(NetworkEvent.protocol == protocol.upper())
    if source:
        statement = statement.where(NetworkEvent.source == source)
    return [serialize_event(e) for e in db.scalars(statement.offset(offset).limit(limit)).all()]


@app.get("/api/events/{event_id}")
def event(event_id: int, db: Session = Depends(get_db)) -> dict:
    item = db.scalar(select(NetworkEvent).where(NetworkEvent.id == event_id).options(joinedload(NetworkEvent.feature_vector)))
    if not item:
        raise HTTPException(404, "Event not found")
    return serialize_event(item)


@app.post("/api/events/import", status_code=201)
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


@app.get("/api/imports")
def imports(db: Session = Depends(get_db)) -> list[dict]:
    batches = db.scalars(select(ImportBatch).order_by(ImportBatch.imported_at.desc()).limit(50)).all()
    return [serialize_import(batch) for batch in batches]


@app.get("/api/research/dataset")
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


@app.get("/api/alerts")
def alerts(
    status: str | None = None, severity: Severity | None = None,
    limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db),
) -> list[dict]:
    statement = select(Alert).options(joinedload(Alert.event), joinedload(Alert.assessment)).order_by(Alert.created_at.desc())
    if status:
        statement = statement.where(Alert.status == status)
    if severity:
        statement = statement.where(Alert.severity == severity)
    items = db.scalars(statement.limit(limit)).all()
    return [serialize_alert(a) for a in items]


@app.get("/api/alerts/{alert_id}")
def alert(alert_id: int, db: Session = Depends(get_db)) -> dict:
    item = db.scalar(select(Alert).where(Alert.id == alert_id).options(
        joinedload(Alert.event).joinedload(NetworkEvent.feature_vector), joinedload(Alert.assessment)))
    if not item:
        raise HTTPException(404, "Alert not found")
    return {**serialize_alert(item), "event": serialize_event(item.event), "mitre_mappings": [],
            "explanation": None, "explanation_status": "Planned for Milestone 5"}


class AlertUpdate(BaseModel):
    status: str | None = None
    assigned_analyst: str | None = Field(default=None, max_length=100)


@app.patch("/api/alerts/{alert_id}")
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


@app.get("/api/detection-rules")
def detection_rules() -> list[dict]:
    return [{"id": "demo-unusual-connection-v1", "name": "Demo unusual connection behavior",
             "enabled": True, "scope": "SYNTHETIC DEMO DATA only", "evidence":
             "Seeded events explicitly marked with repeated attempts, sequential ports, or multiple destinations.",
             "risk_points": 25, "limitations": "This deterministic demo rule is not a production IDS signature."}]


@app.get("/api/incidents")
def incidents(db: Session = Depends(get_db)) -> list[dict]:
    return [{"id": i.id, "title": i.title, "severity": i.severity.value, "status": i.status,
             "summary": i.summary, "first_seen": i.first_seen, "last_seen": i.last_seen, "synthetic": True}
            for i in db.scalars(select(Incident).order_by(Incident.last_seen.desc())).all()]


@app.get("/api/research/metrics")
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


@app.get("/api/experiments")
def experiments(db: Session = Depends(get_db)) -> list[dict]:
    items = db.scalars(select(Experiment).order_by(Experiment.created_at.desc())).all()
    return [serialize_experiment(item) for item in items]


@app.post("/api/experiments", status_code=201)
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


@app.get("/api/models")
def models(db: Session = Depends(get_db)) -> list[dict]:
    items = db.scalars(select(ModelVersion).order_by(ModelVersion.created_at.desc())).all()
    return [serialize_model(item) for item in items]


@app.get("/api/models/{model_id}")
def model(model_id: int, db: Session = Depends(get_db)) -> dict:
    item = db.get(ModelVersion, model_id)
    if not item:
        raise HTTPException(404, "Model version not found")
    experiment = db.get(Experiment, item.experiment_id)
    return {**serialize_model(item), "experiment": serialize_experiment(experiment)}


@app.post("/api/models/{model_id}/predict/{event_id}", status_code=201)
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
    if not artifact_path.is_file():
        raise HTTPException(503, "Model artifact is unavailable")
    artifact = BaseDetector.load_artifact(artifact_path)
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
        "alert_id": generated_alert.id if generated_alert else None, "explanation": None,
    }


@app.get("/api/predictions")
def predictions(db: Session = Depends(get_db)) -> list[dict]:
    items = db.scalars(select(Prediction).order_by(Prediction.created_at.desc()).limit(100)).all()
    return [{"id": item.id, "event_id": item.event_id, "model_version_id": item.model_version_id,
             "predicted_label": item.predicted_label, "probability": item.probability,
             "inference_time_ms": item.inference_time_ms, "created_at": item.created_at} for item in items]
