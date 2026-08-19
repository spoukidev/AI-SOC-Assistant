import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, JSON, String, Text
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
