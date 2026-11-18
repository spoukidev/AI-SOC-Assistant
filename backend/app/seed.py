from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Alert, AlertAssessment, DetectionRule, Incident, NetworkEvent, Severity
from .security.risk_score import calculate_risk, severity_for_score

DEMO_RULE_KEY = "demo-unusual-connection-v1"
# Remote-administration and file-sharing services get asset-context points from the demo rule.
SENSITIVE_SERVICE_PORTS = {22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP"}
DEMO_EVIDENCE_TYPE = "Synthetic deterministic rule"
RECON_SOURCE = "10.20.3.91"
RECON_INCIDENT = "Synthetic reconnaissance-like activity"
REMOTE_ACCESS_INCIDENT = "Synthetic remote-access probe"

BUILT_IN_RULES = [
    {
        "key": DEMO_RULE_KEY,
        "name": "Demo unusual connection behavior",
        "description": "Flags seeded flows that carry explicit reconnaissance-like annotations.",
        "logic": "Event source is SYNTHETIC DEMO DATA AND the seed annotated the flow with repeated short "
                 "connection attempts, sequential destination ports, or multiple destinations in a short window. "
                 f"Adds asset-context points when the destination port is a remote-access or file-sharing service "
                 f"({', '.join(f'{port}/{name}' for port, name in SENSITIVE_SERVICE_PORTS.items())}).",
        "scope": "SYNTHETIC DEMO DATA only",
        "risk_points": 25,
        "limitations": "This deterministic demo rule is not a production IDS signature. It is evaluated only when "
                       "demo data is seeded; there is no live rule engine for imported events yet.",
    },
]


def ensure_builtin_rules(db: Session) -> None:
    """Create built-in rule catalog entries once. Analyst edits to existing rules are preserved."""
    now = datetime.now(timezone.utc)
    for spec in BUILT_IN_RULES:
        if db.scalar(select(DetectionRule).where(DetectionRule.key == spec["key"])) is None:
            db.add(DetectionRule(**spec, enabled=True, version=1, built_in=True, created_at=now, updated_at=now))
    db.commit()


def demo_rule_assessment(dst_port: int, src_ip: str, rule_points: int):
    """Rule-only risk: no model probability is involved for seeded alerts."""
    return calculate_risk(
        probability=None, rule_strength=rule_points,
        asset_context=10 if dst_port in SENSITIVE_SERVICE_PORTS else 0,
        repeated_activity=8 if src_ip == RECON_SOURCE else 2,
    )


def _upgrade_existing_demo_alerts(db: Session, rule: DetectionRule | None) -> None:
    """Older seeds stored made-up model probabilities on rule alerts. Remove them and relink to the rule."""
    for alert in db.scalars(select(Alert)).all():
        is_demo_rule_alert = alert.event.source == "SYNTHETIC DEMO DATA" and alert.evidence_type == DEMO_EVIDENCE_TYPE
        if is_demo_rule_alert:
            if rule is not None and alert.rule_id is None:
                alert.rule_id = rule.id
            if alert.model_probability is not None:
                alert.model_probability = None
                risk = demo_rule_assessment(alert.event.dst_port, alert.event.src_ip, rule.risk_points if rule else 25)
                alert.severity = risk.severity
                if alert.assessment:
                    for field in ("model_evidence", "rule_evidence", "asset_context", "repeated_activity"):
                        setattr(alert.assessment, field, getattr(risk, field))
                    alert.assessment.risk_score = risk.score
                    continue
        if alert.assessment:
            alert.severity = severity_for_score(alert.assessment.risk_score)
            continue
        risk = calculate_risk(probability=alert.model_probability,
                              rule_strength=25 if "rule" in alert.evidence_type.lower() else 0,
                              repeated_activity=8 if "Repeated" in alert.evidence or "Multiple" in alert.evidence else 2)
        alert.severity = risk.severity
        db.add(AlertAssessment(alert_id=alert.id, risk_score=risk.score,
                               model_evidence=risk.model_evidence, rule_evidence=risk.rule_evidence,
                               asset_context=risk.asset_context, repeated_activity=risk.repeated_activity,
                               updated_at=alert.created_at))
    demo_incidents = {incident.title: incident for incident in
                      db.scalars(select(Incident).where(Incident.title.like("Synthetic %"))).all()}
    for incident in demo_incidents.values():
        incident.synthetic = True
    # Older seeds created the demo incidents without alert links; attach the matching demo alerts once.
    for alert in db.scalars(select(Alert).where(Alert.incident_id.is_(None), Alert.evidence_type == DEMO_EVIDENCE_TYPE)).all():
        if alert.event.source != "SYNTHETIC DEMO DATA":
            continue
        title = RECON_INCIDENT if alert.event.src_ip == RECON_SOURCE else REMOTE_ACCESS_INCIDENT
        if title in demo_incidents:
            alert.incident_id = demo_incidents[title].id


def seed_demo_data(db: Session) -> None:
    ensure_builtin_rules(db)
    rule = db.scalar(select(DetectionRule).where(DetectionRule.key == DEMO_RULE_KEY))
    if db.scalar(select(func.count(NetworkEvent.id))):
        _upgrade_existing_demo_alerts(db, rule)
        db.commit()
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

    recon_alerts: list[Alert] = []
    remote_access_alerts: list[Alert] = []
    for index, (src, dst, sport, dport, proto, duration, packets, byte_count, flags, evidence) in enumerate(specifications):
        timestamp = now - timedelta(minutes=(len(specifications) - index) * 7)
        raw = {"timestamp": timestamp.isoformat(), "src_ip": src, "dst_ip": dst, "src_port": sport,
               "dst_port": dport, "protocol": proto, "duration": duration, "packets": packets,
               "bytes": byte_count, "tcp_flags": flags}
        event = NetworkEvent(timestamp=timestamp, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                             protocol=proto, duration=duration, packets=packets, bytes=byte_count,
                             tcp_flags=flags, source="SYNTHETIC DEMO DATA", raw_event=raw)
        db.add(event)
        if evidence and rule is not None and rule.enabled:
            db.flush()
            # Rule-only evidence: no ML model scored these synthetic flows, so no probability is stored.
            assessment = demo_rule_assessment(dport, src, rule.risk_points)
            service = SENSITIVE_SERVICE_PORTS.get(dport)
            alert = Alert(event_id=event.id, title="Demo rule: unusual connection behavior", severity=assessment.severity,
                          prediction="Rule match", model_probability=None, evidence_type=DEMO_EVIDENCE_TYPE,
                          evidence=evidence + (f" (destination is a {service} service)" if service else ""),
                          status="New", created_at=timestamp, rule_id=rule.id)
            db.add(alert)
            db.flush()
            db.add(AlertAssessment(alert_id=alert.id, risk_score=assessment.score,
                                   model_evidence=assessment.model_evidence, rule_evidence=assessment.rule_evidence,
                                   asset_context=assessment.asset_context, repeated_activity=assessment.repeated_activity,
                                   updated_at=timestamp))
            (recon_alerts if src == RECON_SOURCE else remote_access_alerts).append(alert)

    incidents = [
        (Incident(title=RECON_INCIDENT, severity=Severity.high, status="Open", synthetic=True,
                  summary="Three synthetic alerts share a source and occur within a short time window. This is demo correlation, not proof of malicious activity.",
                  first_seen=now - timedelta(minutes=42), last_seen=now - timedelta(minutes=28)), recon_alerts),
        (Incident(title=REMOTE_ACCESS_INCIDENT, severity=Severity.medium, status="Open", synthetic=True,
                  summary="A later synthetic alert targets a remote-desktop service. This is demo data, not proof of malicious activity.",
                  first_seen=now - timedelta(minutes=21), last_seen=now - timedelta(minutes=14)), remote_access_alerts),
    ]
    for incident, linked in incidents:
        db.add(incident)
        db.flush()
        for alert in linked:
            alert.incident_id = incident.id
        if linked:
            incident.first_seen = min(alert.created_at for alert in linked)
            incident.last_seen = max(alert.created_at for alert in linked)
    db.commit()
