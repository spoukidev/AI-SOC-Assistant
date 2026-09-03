from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from .config import settings
from .database import Base, SessionLocal, engine, get_db
from .models import Alert, Incident, NetworkEvent, Severity
from .seed import seed_demo_data


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    if settings.seed_demo_data:
        with SessionLocal() as db:
            seed_demo_data(db)
    yield


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PATCH"], allow_headers=["Content-Type", "Authorization"])


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "backend", "milestone": 1}


def serialize_event(event: NetworkEvent) -> dict:
    return {"id": event.id, "timestamp": event.timestamp, "src_ip": event.src_ip, "dst_ip": event.dst_ip,
            "src_port": event.src_port, "dst_port": event.dst_port, "protocol": event.protocol,
            "duration": event.duration, "packets": event.packets, "bytes": event.bytes,
            "tcp_flags": event.tcp_flags, "source": event.source, "raw_event": event.raw_event}


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
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[dict]:
    statement = (
        select(NetworkEvent)
        .order_by(NetworkEvent.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )
    return [serialize_event(e) for e in db.scalars(statement).all()]


@app.get("/api/events/{event_id}")
def event(event_id: int, db: Session = Depends(get_db)) -> dict:
    item = db.get(NetworkEvent, event_id)
    if not item:
        raise HTTPException(404, "Event not found")
    return serialize_event(item)


@app.get("/api/alerts")
def alerts(
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    severity: Severity | None = Query(default=None),
    status: str | None = Query(default=None, min_length=1, max_length=32),
    db: Session = Depends(get_db),
) -> list[dict]:
    statement = select(Alert).options(joinedload(Alert.event))
    if severity is not None:
        statement = statement.where(Alert.severity == severity)
    if status is not None:
        statement = statement.where(Alert.status == status)
    statement = statement.order_by(Alert.created_at.desc()).offset(offset).limit(limit)
    items = db.scalars(statement).all()
    return [serialize_alert(a) for a in items]


@app.get("/api/alerts/{alert_id}")
def alert(alert_id: int, db: Session = Depends(get_db)) -> dict:
    item = db.scalar(select(Alert).where(Alert.id == alert_id).options(joinedload(Alert.event)))
    if not item:
        raise HTTPException(404, "Alert not found")
    return {**serialize_alert(item), "event": serialize_event(item.event), "mitre_mappings": []}


@app.get("/api/incidents")
def incidents(
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[dict]:
    statement = (
        select(Incident)
        .order_by(Incident.last_seen.desc())
        .offset(offset)
        .limit(limit)
    )
    return [{"id": i.id, "title": i.title, "severity": i.severity.value, "status": i.status,
             "summary": i.summary, "first_seen": i.first_seen, "last_seen": i.last_seen, "synthetic": True}
            for i in db.scalars(statement).all()]


@app.get("/api/research/metrics")
def research_metrics() -> dict:
    return {"available": False, "message": "No experiment results available."}
