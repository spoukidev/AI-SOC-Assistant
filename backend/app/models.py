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


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    status: Mapped[str] = mapped_column(String(32), default="Open")
    summary: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
