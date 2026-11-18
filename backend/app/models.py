import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Severity(str, enum.Enum):
    informational = "Informational"
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"


class NetworkEvent(Base):
    __tablename__ = "network_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(16), index=True)
    duration: Mapped[float] = mapped_column(Float)
    packets: Mapped[int] = mapped_column(Integer)
    bytes: Mapped[int] = mapped_column(Integer)
    tcp_flags: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="SYNTHETIC DEMO DATA")
    raw_event: Mapped[dict] = mapped_column(JSON)
    alert: Mapped["Alert | None"] = relationship(back_populates="event")
    feature_vector: Mapped["FeatureVector | None"] = relationship(back_populates="event")


class ImportBatch(Base):
    __tablename__ = "import_batches"
    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    source_type: Mapped[str] = mapped_column(String(32), default="CSV")
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    total_rows: Mapped[int] = mapped_column(Integer)
    accepted_rows: Mapped[int] = mapped_column(Integer)
    rejected_rows: Mapped[int] = mapped_column(Integer)
    column_mapping: Mapped[dict] = mapped_column(JSON)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    feature_vectors: Mapped[list["FeatureVector"]] = relationship(back_populates="import_batch")


class FeatureVector(Base):
    __tablename__ = "feature_vectors"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("network_events.id"), unique=True, index=True)
    import_id: Mapped[int] = mapped_column(ForeignKey("import_batches.id"), index=True)
    schema_version: Mapped[str] = mapped_column(String(32), default="flow-v1")
    features: Mapped[dict] = mapped_column(JSON)
    event: Mapped[NetworkEvent] = relationship(back_populates="feature_vector")
    import_batch: Mapped[ImportBatch] = relationship(back_populates="feature_vectors")


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("network_events.id"), unique=True)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    prediction: Mapped[str] = mapped_column(String(32))
    model_probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence_type: Mapped[str] = mapped_column(String(64))
    evidence: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="New")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event: Mapped[NetworkEvent] = relationship(back_populates="alert")
    assessment: Mapped["AlertAssessment | None"] = relationship(back_populates="alert", uselist=False)


class AlertAssessment(Base):
    """Milestone 4 risk/workflow data kept separate for migration-safe upgrades."""
    __tablename__ = "alert_assessments"
    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), unique=True, index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    model_evidence: Mapped[int] = mapped_column(Integer, default=0)
    rule_evidence: Mapped[int] = mapped_column(Integer, default=0)
    asset_context: Mapped[int] = mapped_column(Integer, default=0)
    repeated_activity: Mapped[int] = mapped_column(Integer, default=0)
    assigned_analyst: Mapped[str | None] = mapped_column(String(100), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    alert: Mapped[Alert] = relationship(back_populates="assessment")


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    status: Mapped[str] = mapped_column(String(32), default="Open")
    summary: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Experiment(Base):
    __tablename__ = "experiments"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    dataset_name: Mapped[str] = mapped_column(String(255))
    dataset_sha256: Mapped[str] = mapped_column(String(64))
    model_name: Mapped[str] = mapped_column(String(64), index=True)
    parameters: Mapped[dict] = mapped_column(JSON)
    features: Mapped[list] = mapped_column(JSON)
    metrics: Mapped[dict] = mapped_column(JSON)
    split: Mapped[dict] = mapped_column(JSON)
    random_seed: Mapped[int] = mapped_column(Integer)
    training_time_ms: Mapped[float] = mapped_column(Float)
    inference_time_ms: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_versions: Mapped[list["ModelVersion"]] = relationship(back_populates="experiment")


class ModelVersion(Base):
    __tablename__ = "model_versions"
    id: Mapped[int] = mapped_column(primary_key=True)
    experiment_id: Mapped[int] = mapped_column(ForeignKey("experiments.id"), index=True)
    model_name: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    artifact_path: Mapped[str] = mapped_column(String(500))
    feature_schema: Mapped[str] = mapped_column(String(32), default="flow-v1")
    positive_label: Mapped[str] = mapped_column(String(64), default="malicious")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    experiment: Mapped[Experiment] = relationship(back_populates="model_versions")
    predictions: Mapped[list["Prediction"]] = relationship(back_populates="model_version")


class Prediction(Base):
    __tablename__ = "predictions"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("network_events.id"), index=True)
    model_version_id: Mapped[int] = mapped_column(ForeignKey("model_versions.id"), index=True)
    predicted_label: Mapped[str] = mapped_column(String(64))
    probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    inference_time_ms: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    model_version: Mapped[ModelVersion] = relationship(back_populates="predictions")
    event: Mapped[NetworkEvent] = relationship()
