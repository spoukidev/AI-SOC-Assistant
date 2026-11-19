"""Live deterministic rule engine (Milestone 5.1).

A rule's ``conditions`` is a list of ``{"field", "op", "value"}`` checks that must ALL match.
Fields are normalized flow fields or flow-v1 features. Rules without conditions are catalog
entries only (for example the demo rule, which is applied by the seed) and are never evaluated.

When several rules match one event, a single alert is raised for the rule with the most risk
points (alerts are one-per-event) and the other matches are listed in its evidence. Each alert
stores the rule version and a dedup fingerprint (rule key + flow), so re-importing the same CSV
does not raise duplicate alerts.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Alert, AlertAssessment, DetectionRule, NetworkEvent
from .risk_score import calculate_risk

EVENT_FIELDS = {"protocol", "src_port", "dst_port", "duration", "packets", "bytes", "tcp_flags"}
FEATURE_FIELDS = {
    "bytes_per_packet", "packets_per_second", "bytes_per_second", "src_dst_byte_ratio",
    "src_dst_packet_ratio", "src_port_category", "dst_port_category", "has_tcp_flags",
}
ALLOWED_FIELDS = EVENT_FIELDS | FEATURE_FIELDS
NUMERIC_OPS = {"gt", "gte", "lt", "lte"}
ALLOWED_OPS = {"eq", "ne", "in", "not_in", "contains", "not_contains"} | NUMERIC_OPS
MAX_CONDITIONS = 10
MAX_LIST_VALUES = 100
SENSITIVE_SERVICE_PORTS = {21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900}
EVIDENCE_TYPE = "Deterministic rule"


def _flag_tokens(value) -> set[str]:
    return {token for token in str(value or "").upper().replace("|", ",").replace(" ", ",").split(",") if token}


def validate_conditions(conditions) -> list[dict]:
    """Validate rule conditions supplied through the API. Raises ValueError with a readable message."""
    if not isinstance(conditions, list) or not 1 <= len(conditions) <= MAX_CONDITIONS:
        raise ValueError(f"conditions must be a list of 1 to {MAX_CONDITIONS} checks")
    cleaned = []
    for index, condition in enumerate(conditions, start=1):
        if not isinstance(condition, dict) or set(condition) != {"field", "op", "value"}:
            raise ValueError(f"condition {index} must have exactly: field, op, value")
        field, op, value = condition["field"], condition["op"], condition["value"]
        if field not in ALLOWED_FIELDS:
            raise ValueError(f"condition {index}: unknown field {field!r}. Allowed: {', '.join(sorted(ALLOWED_FIELDS))}")
        if op not in ALLOWED_OPS:
            raise ValueError(f"condition {index}: unknown op {op!r}. Allowed: {', '.join(sorted(ALLOWED_OPS))}")
        scalar = (str, int, float, bool)
        if op in {"in", "not_in"}:
            if not isinstance(value, list) or not 1 <= len(value) <= MAX_LIST_VALUES or not all(isinstance(v, scalar) for v in value):
                raise ValueError(f"condition {index}: {op} needs a list of 1 to {MAX_LIST_VALUES} values")
        elif op in NUMERIC_OPS:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"condition {index}: {op} needs a number")
        elif not isinstance(value, scalar) or (isinstance(value, str) and len(value) > 100):
            raise ValueError(f"condition {index}: value must be a short scalar")
        cleaned.append({"field": field, "op": op, "value": value})
    return cleaned


def _normalize(field: str, value):
    if isinstance(value, str) and field in {"protocol", "tcp_flags", "src_port_category", "dst_port_category"}:
        return value.upper()
    return value


def condition_matches(condition: dict, flow: dict) -> bool:
    field, op, expected = condition["field"], condition["op"], condition["value"]
    actual = flow.get(field)
    if field == "tcp_flags" and op in {"contains", "not_contains"}:
        present = str(expected).upper() in _flag_tokens(actual)
        return present if op == "contains" else not present
    if actual is None:
        return False
    actual = _normalize(field, actual)
    if op in NUMERIC_OPS:
        if isinstance(actual, bool) or not isinstance(actual, (int, float)):
            return False
        return {"gt": actual > expected, "gte": actual >= expected, "lt": actual < expected, "lte": actual <= expected}[op]
    if op in {"in", "not_in"}:
        found = actual in {_normalize(field, item) for item in expected}
        return found if op == "in" else not found
    if op in {"contains", "not_contains"}:
        found = str(expected).upper() in str(actual).upper()
        return found if op == "contains" else not found
    equal = actual == _normalize(field, expected)
    return equal if op == "eq" else not equal


def rule_matches(rule: DetectionRule, flow: dict) -> bool:
    return bool(rule.conditions) and all(condition_matches(condition, flow) for condition in rule.conditions)


def flow_view(event: NetworkEvent, features: dict | None) -> dict:
    flow = {field: getattr(event, field) for field in EVENT_FIELDS}
    flow.update({name: value for name, value in (features or {}).items() if name in FEATURE_FIELDS})
    return flow


def dedup_key(rule_key: str, event: NetworkEvent) -> str:
    moment = event.timestamp
    if isinstance(moment, datetime):
        # SQLite hands back naive UTC datetimes; normalize so freshly imported and reloaded events hash alike.
        moment = moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)
        timestamp = moment.strftime("%Y-%m-%dT%H:%M:%S.%f")
    else:
        timestamp = str(moment)
    material = "|".join(str(part) for part in (
        rule_key, timestamp, event.src_ip, event.dst_ip, event.src_port, event.dst_port,
        event.protocol, event.packets, event.bytes, float(event.duration), event.tcp_flags or "",
    ))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def describe_condition(condition: dict) -> str:
    symbols = {"eq": "=", "ne": "≠", "gt": ">", "gte": "≥", "lt": "<", "lte": "≤", "in": "in", "not_in": "not in",
               "contains": "contains", "not_contains": "does not contain"}
    return f"{condition['field']} {symbols[condition['op']]} {condition['value']}"


@dataclass
class EngineResult:
    alerts: list[Alert]
    skipped_duplicates: int


def enabled_rules(db: Session) -> list[DetectionRule]:
    rules = db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True)).order_by(DetectionRule.id)).all()
    return [rule for rule in rules if rule.conditions]


def evaluate_events(db: Session, items: list[tuple[NetworkEvent, dict | None]], window_minutes: int = 60) -> EngineResult:
    """Evaluate enabled rules against (event, features) pairs and add alerts to the session."""
    rules = enabled_rules(db)
    created: list[Alert] = []
    duplicates = 0
    if not rules:
        return EngineResult(created, duplicates)
    for event, features in items:
        flow = flow_view(event, features)
        matched = sorted((rule for rule in rules if rule_matches(rule, flow)), key=lambda r: (-r.risk_points, r.id))
        if not matched:
            continue
        rule = matched[0]
        key = dedup_key(rule.key, event)
        if db.scalar(select(Alert.id).where(Alert.event_id == event.id)) is not None:
            continue  # one alert per event (e.g. already raised by a model)
        if db.scalar(select(Alert.id).where(Alert.dedup_key == key)) is not None or any(a.dedup_key == key for a in created):
            duplicates += 1
            continue
        window_start = event.timestamp - timedelta(minutes=window_minutes)
        prior = db.scalar(select(func.count(NetworkEvent.id)).where(
            NetworkEvent.src_ip == event.src_ip, NetworkEvent.timestamp >= window_start,
            NetworkEvent.timestamp <= event.timestamp, NetworkEvent.id != event.id)) or 0
        risk = calculate_risk(probability=None, rule_strength=rule.risk_points,
                              asset_context=10 if event.dst_port in SENSITIVE_SERVICE_PORTS else 0,
                              repeated_activity=min(10, prior * 2))
        evidence = f"Matched rule {rule.key} v{rule.version}: " + "; ".join(describe_condition(c) for c in rule.conditions) + "."
        if len(matched) > 1:
            evidence += " Also matched: " + ", ".join(f"{other.key} v{other.version}" for other in matched[1:]) + "."
        alert = Alert(event_id=event.id, title=f"Rule: {rule.name}"[:200], severity=risk.severity, prediction="Rule match",
                      model_probability=None, evidence_type=EVIDENCE_TYPE, evidence=evidence, status="New",
                      created_at=event.timestamp, rule_id=rule.id, rule_version=rule.version, dedup_key=key)
        db.add(alert)
        db.flush()
        db.add(AlertAssessment(alert_id=alert.id, risk_score=risk.score, model_evidence=risk.model_evidence,
                               rule_evidence=risk.rule_evidence, asset_context=risk.asset_context,
                               repeated_activity=risk.repeated_activity, updated_at=event.timestamp))
        alert.event = event
        created.append(alert)
    db.flush()
    return EngineResult(created, duplicates)
