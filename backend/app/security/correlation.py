"""Automatic, transparent incident correlation (Milestone 5.1).

Policy (documented in the README):
* Correlation key: the alert's source IP (``src:<ip>``).
* A new alert joins an open, auto-correlated incident with the same key whose activity window
  (first_seen - W, last_seen + W) contains the alert time. W = CORRELATION_WINDOW_MINUTES.
* Otherwise, if at least CORRELATION_MIN_ALERTS alerts from that source (including the new one,
  not yet in any incident) fall within W of the new alert, a new incident is created for them.
* Incident first/last seen are recomputed from linked alerts; severity only ever escalates to the
  highest linked alert severity. Alerts an analyst linked or unlinked by hand are never moved.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Alert, Incident, NetworkEvent, Severity

SEVERITY_RANK = {Severity.informational: 0, Severity.low: 1, Severity.medium: 2, Severity.high: 3, Severity.critical: 4}
CLOSED_STATUSES = ("Resolved", "Closed")


def correlation_key(alert: Alert) -> str:
    return f"src:{alert.event.src_ip}"


def refresh_window_and_severity(db: Session, incident: Incident) -> None:
    db.flush()
    first, last = db.execute(select(func.min(Alert.created_at), func.max(Alert.created_at))
                             .where(Alert.incident_id == incident.id)).one()
    if first is not None:
        incident.first_seen, incident.last_seen = first, last
    severities = db.scalars(select(Alert.severity).where(Alert.incident_id == incident.id)).all()
    if severities:
        highest = max(severities, key=SEVERITY_RANK.get)
        if SEVERITY_RANK[highest] > SEVERITY_RANK[incident.severity]:
            incident.severity = highest


def _aware(value):
    # SQLite returns naive datetimes; treat them as UTC for comparisons.
    from datetime import timezone
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


def correlate_alert(db: Session, alert: Alert, window_minutes: int, min_alerts: int) -> Incident | None:
    if alert.incident_id is not None or alert.manual_correlation:
        return None
    window = timedelta(minutes=max(1, window_minutes))
    key = correlation_key(alert)
    moment = _aware(alert.created_at)
    candidates = db.scalars(select(Incident).where(
        Incident.correlation_key == key, Incident.status.not_in(CLOSED_STATUSES),
    ).order_by(Incident.last_seen.desc(), Incident.id.desc())).all()
    for incident in candidates:
        if _aware(incident.first_seen) - window <= moment <= _aware(incident.last_seen) + window:
            alert.incident_id = incident.id
            refresh_window_and_severity(db, incident)
            return incident

    peers = db.scalars(select(Alert).join(NetworkEvent, Alert.event_id == NetworkEvent.id).where(
        NetworkEvent.src_ip == alert.event.src_ip, Alert.incident_id.is_(None), Alert.manual_correlation.is_(False),
        Alert.id != alert.id, Alert.created_at >= moment - window, Alert.created_at <= moment + window,
    )).all()
    group = [alert, *peers]
    if len(group) < max(1, min_alerts):
        return None
    first = min(_aware(item.created_at) for item in group)
    incident = Incident(
        title=f"Correlated activity from {alert.event.src_ip}"[:200],
        severity=max((item.severity for item in group), key=SEVERITY_RANK.get), status="Open", synthetic=False,
        summary=(f"Auto-correlated: {len(group)} alerts from source {alert.event.src_ip} within "
                 f"{int(window.total_seconds() // 60)} minutes of each other. Correlation by shared source is a "
                 "triage aid, not proof that the alerts belong to one attack."),
        first_seen=first, last_seen=first, correlation_key=key,
    )
    db.add(incident)
    db.flush()
    for item in group:
        item.incident_id = incident.id
    refresh_window_and_severity(db, incident)
    return incident


def correlate_alerts(db: Session, alerts: list[Alert], window_minutes: int, min_alerts: int) -> set[int]:
    touched: set[int] = set()
    for alert in sorted(alerts, key=lambda item: (_aware(item.created_at), item.id)):
        incident = correlate_alert(db, alert, window_minutes, min_alerts)
        if incident is not None:
            touched.add(incident.id)
    return touched
