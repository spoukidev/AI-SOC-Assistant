from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Alert, Incident, NetworkEvent, Severity


def seed_demo_data(db: Session) -> None:
    if db.scalar(select(func.count(NetworkEvent.id))):
        return

    now = datetime.now(timezone.utc).replace(microsecond=0)
    specifications = [
        ("10.20.4.18", "10.20.9.12", 51342, 443, "TCP", 4.8, 38, 48210, "SYN,ACK", None),
        ("10.20.7.44", "10.20.1.8", 60122, 53, "UDP", 0.09, 2, 198, None, None),
        ("10.20.3.91", "10.20.6.20", 49188, 22, "TCP", 0.17, 3, 180, "SYN", "Repeated short connection attempts"),
        ("10.20.3.91", "10.20.6.21", 49189, 23, "TCP", 0.13, 2, 120, "SYN", "Sequential destination-port activity"),
        ("10.20.3.91", "10.20.6.22", 49190, 445, "TCP", 0.15, 3, 192, "SYN", "Multiple destinations in a short time window"),
        ("10.20.8.16", "10.20.2.31", 58111, 8080, "TCP", 16.2, 122, 156700, "ACK,PSH", None),
        ("10.20.5.17", "10.20.1.10", 49901, 3389, "TCP", 0.22, 4, 244, "SYN", "Repeated connection attempt to monitored service"),
        ("10.20.6.55", "10.20.4.27", 52001, 123, "UDP", 0.04, 2, 152, None, None),
    ]

    alert_events: list[NetworkEvent] = []
    for index, (src, dst, sport, dport, proto, duration, packets, byte_count, flags, evidence) in enumerate(specifications):
        timestamp = now - timedelta(minutes=(len(specifications) - index) * 7)
        raw = {"timestamp": timestamp.isoformat(), "src_ip": src, "dst_ip": dst, "src_port": sport,
               "dst_port": dport, "protocol": proto, "duration": duration, "packets": packets,
               "bytes": byte_count, "tcp_flags": flags}
        event = NetworkEvent(timestamp=timestamp, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                             protocol=proto, duration=duration, packets=packets, bytes=byte_count,
                             tcp_flags=flags, source="SYNTHETIC DEMO DATA", raw_event=raw)
        db.add(event)
        if evidence:
            alert_events.append(event)
            db.flush()
            severity = Severity.high if dport in (22, 23, 445) else Severity.medium
            db.add(Alert(event_id=event.id, title="Demo rule: unusual connection behavior", severity=severity,
                         prediction="Rule match", model_probability=None, evidence_type="Synthetic deterministic rule",
                         evidence=evidence, status="New", created_at=timestamp))

    db.add(Incident(title="Synthetic reconnaissance-like activity", severity=Severity.high, status="Open",
                    summary="Three synthetic alerts share a source and occur within a short time window. This is demo correlation, not proof of malicious activity.",
                    first_seen=now - timedelta(minutes=42), last_seen=now - timedelta(minutes=28)))
    db.commit()
