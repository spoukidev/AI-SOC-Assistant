from contextlib import asynccontextmanager

from datetime import datetime, timezone

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from .config import settings
from .database import Base, SessionLocal, engine, get_db
from .models import Alert, FeatureVector, ImportBatch, Incident, NetworkEvent, Severity
from .seed import seed_demo_data
from .services.csv_ingestion import read_csv_upload


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    if settings.seed_demo_data:
        with SessionLocal() as db:
            seed_demo_data(db)
    yield


app = FastAPI(title=settings.app_name, version="0.2.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PATCH"], allow_headers=["Content-Type", "Authorization"])


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "backend", "milestone": 2}


def serialize_event(event: NetworkEvent) -> dict:
    return {"id": event.id, "timestamp": event.timestamp, "src_ip": event.src_ip, "dst_ip": event.dst_ip,
            "src_port": event.src_port, "dst_port": event.dst_port, "protocol": event.protocol,
            "duration": event.duration, "packets": event.packets, "bytes": event.bytes,
            "tcp_flags": event.tcp_flags, "source": event.source, "raw_event": event.raw_event,
            "features": event.feature_vector.features if event.feature_vector else None}


def serialize_alert(alert: Alert) -> dict:
    return {"id": alert.id, "timestamp": alert.created_at, "severity": alert.severity.value,
            "source": alert.event.src_ip, "destination": alert.event.dst_ip,
            "destination_port": alert.event.dst_port, "protocol": alert.event.protocol,
            "detection": alert.title, "prediction": alert.prediction,
            "model_probability": alert.model_probability, "evidence_type": alert.evidence_type,
            "evidence": alert.evidence, "status": alert.status, "synthetic": True}


@app.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db)) -> dict:
    alerts = list(db.scalars(select(Alert).options(joinedload(Alert.event)).order_by(Alert.created_at.desc())).all())
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
    return {"data_label": "SYNTHETIC DEMO DATA", "metrics": {"active_alerts": len(alerts),
            "critical_alerts": severity_counts["Critical"], "high_alerts": severity_counts["High"],
            "open_incidents": incidents_count, "events_analyzed": events_count,
            "average_model_confidence": None}, "alerts_by_severity": severity_counts,
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
def alerts(db: Session = Depends(get_db)) -> list[dict]:
    items = db.scalars(select(Alert).options(joinedload(Alert.event)).order_by(Alert.created_at.desc())).all()
    return [serialize_alert(a) for a in items]


@app.get("/api/alerts/{alert_id}")
def alert(alert_id: int, db: Session = Depends(get_db)) -> dict:
    item = db.scalar(select(Alert).where(Alert.id == alert_id).options(joinedload(Alert.event)))
    if not item:
        raise HTTPException(404, "Alert not found")
    return {**serialize_alert(item), "event": serialize_event(item.event), "mitre_mappings": []}


@app.get("/api/incidents")
def incidents(db: Session = Depends(get_db)) -> list[dict]:
    return [{"id": i.id, "title": i.title, "severity": i.severity.value, "status": i.status,
             "summary": i.summary, "first_seen": i.first_seen, "last_seen": i.last_seen, "synthetic": True}
            for i in db.scalars(select(Incident).order_by(Incident.last_seen.desc())).all()]


@app.get("/api/research/metrics")
def research_metrics() -> dict:
    return {"available": False, "message": "No experiment results available."}
