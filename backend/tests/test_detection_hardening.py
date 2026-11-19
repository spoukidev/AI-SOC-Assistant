"""Milestone 5.1: live rule engine, auto-correlation and cookie/CSRF authentication."""
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SEED_DEMO_DATA"] = "true"

import pytest
from fastapi.testclient import TestClient

from app.auth import SESSION_COOKIE, login_throttle
from app.config import Settings, settings
from app.main import app
from app.security.rule_engine import condition_matches, validate_conditions
from conftest import TEST_ADMIN_PASSWORD, TEST_ADMIN_USERNAME, auth_headers

HEADER = "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,duration,packets,bytes,tcp_flags\n"
BASE = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)


def client() -> TestClient:
    return TestClient(app, headers=auth_headers())


def flow(src: str, minutes: float, dst_port: int = 22, flags: str = "SYN", packets: int = 2, protocol: str = "TCP") -> str:
    moment = (BASE + timedelta(minutes=minutes)).isoformat()
    return f"{moment},{src},198.51.100.7,50000,{dst_port},{protocol},0.05,{packets},{packets * 60},{flags}\n"


def import_csv(c: TestClient, name: str, rows: list[str]) -> dict:
    response = c.post("/api/events/import", files={"file": (name, HEADER + "".join(rows), "text/csv")})
    assert response.status_code == 201, response.text
    return response.json()


def rule_by_key(c: TestClient, key: str) -> dict:
    return next(rule for rule in c.get("/api/detection-rules").json() if rule["key"] == key)


# --- Rule engine --------------------------------------------------------------------------

def test_condition_dsl_validation_and_matching():
    with pytest.raises(ValueError):
        validate_conditions([])
    with pytest.raises(ValueError):
        validate_conditions([{"field": "src_ip", "op": "eq", "value": "10.0.0.1"}])  # identifiers are not rule inputs
    with pytest.raises(ValueError):
        validate_conditions([{"field": "packets", "op": "gt", "value": "5"}])
    with pytest.raises(ValueError):
        validate_conditions([{"field": "packets", "op": "exec", "value": 1}])
    flow_view = {"protocol": "TCP", "tcp_flags": "SYN,ACK", "dst_port": 22, "packets": 3, "dst_port_category": "well_known"}
    assert condition_matches({"field": "tcp_flags", "op": "contains", "value": "syn"}, flow_view)
    assert not condition_matches({"field": "tcp_flags", "op": "not_contains", "value": "ACK"}, flow_view)
    assert condition_matches({"field": "protocol", "op": "eq", "value": "tcp"}, flow_view)
    assert condition_matches({"field": "dst_port", "op": "in", "value": [21, 22]}, flow_view)
    assert condition_matches({"field": "packets", "op": "lte", "value": 3}, flow_view)
    assert not condition_matches({"field": "bytes", "op": "gt", "value": 1}, flow_view)  # missing field never matches
    assert condition_matches({"field": "tcp_flags", "op": "not_contains", "value": "SYN"}, {"tcp_flags": None})


def test_import_raises_rule_alerts_with_version_and_is_idempotent():
    rows = [flow("203.0.113.10", 0), flow("203.0.113.10", 2, dst_port=3389), flow("203.0.113.10", 4, flags="SYN,ACK", dst_port=443)]
    with client() as c:
        first = import_csv(c, "engine.csv", rows)
        assert first["alerts_created"] == 2 and first["duplicate_alerts_skipped"] == 0
        rule = rule_by_key(c, "syn-probe-sensitive-service-v1")
        alerts = [a for a in c.get("/api/alerts").json() if a["source"] == "203.0.113.10"]
        assert len(alerts) == 2
        assert all(a["rule_id"] == rule["id"] and a["rule_version"] == rule["version"] for a in alerts)
        assert all(a["model_probability"] is None and a["evidence_type"] == "Deterministic rule" for a in alerts)
        detail = c.get(f"/api/alerts/{alerts[0]['id']}").json()
        assert "syn-probe-sensitive-service-v1" in detail["evidence"]
        assert detail["explanation"]["status"] == "not_applicable"

        again = import_csv(c, "engine.csv", rows)
        assert again["alerts_created"] == 0 and again["duplicate_alerts_skipped"] == 2
        assert len([a for a in c.get("/api/alerts").json() if a["source"] == "203.0.113.10"]) == 2
        rerun = c.post("/api/detection-rules/evaluate").json()
        assert rerun["alerts_created"] == 0


def test_disabled_rules_do_not_fire_and_edits_record_new_version():
    with client() as c:
        rule = rule_by_key(c, "syn-probe-sensitive-service-v1")
        c.patch(f"/api/detection-rules/{rule['id']}", json={"enabled": False})
        assert import_csv(c, "disabled.csv", [flow("203.0.113.20", 0)])["alerts_created"] == 0
        enabled = c.patch(f"/api/detection-rules/{rule['id']}", json={"enabled": True}).json()
        assert enabled["version"] == rule["version"] + 2
        result = import_csv(c, "enabled.csv", [flow("203.0.113.21", 0)])
        assert result["alerts_created"] == 1
        alert = next(a for a in c.get("/api/alerts").json() if a["source"] == "203.0.113.21")
        assert alert["rule_version"] == enabled["version"]
        # The earlier, disabled-time event is picked up by an explicit re-evaluation.
        assert c.post("/api/detection-rules/evaluate").json()["alerts_created"] >= 1
        assert any(a["source"] == "203.0.113.20" for a in c.get("/api/alerts").json())


def test_custom_rules_are_validated_and_evaluated():
    with client() as c:
        bad = c.post("/api/detection-rules", json={"key": "bad-rule", "name": "Bad", "description": "x",
                                                   "conditions": [{"field": "dst_ip", "op": "eq", "value": "1.2.3.4"}]})
        assert bad.status_code == 422
        created = c.post("/api/detection-rules", json={
            "key": "large-dns-response-v1", "name": "Large DNS flow", "description": "Big UDP/53 flows.", "risk_points": 12,
            "conditions": [{"field": "protocol", "op": "eq", "value": "UDP"}, {"field": "dst_port", "op": "eq", "value": 53},
                           {"field": "bytes", "op": "gte", "value": 5000}]})
        assert created.status_code == 201
        assert created.json()["evaluated_live"] is True and "bytes ≥ 5000" in created.json()["logic"]
        assert c.post("/api/detection-rules", json={**created.json(), "conditions": created.json()["conditions"]}).status_code in (409, 422)
        result = import_csv(c, "dns.csv", [flow("203.0.113.30", 0, dst_port=53, protocol="UDP", flags="", packets=100)])
        assert result["alerts_created"] == 1
        updated = c.patch(f"/api/detection-rules/{created.json()['id']}",
                          json={"conditions": [{"field": "bytes", "op": "gte", "value": 9000}]}).json()
        assert updated["version"] == 2 and updated["logic"] == "bytes ≥ 9000"
        demo = rule_by_key(c, "demo-unusual-connection-v1")
        assert demo["evaluated_live"] is False
        assert c.patch(f"/api/detection-rules/{demo['id']}", json={"conditions": [{"field": "packets", "op": "gt", "value": 1}]}).status_code == 422


# --- Auto-correlation ----------------------------------------------------------------------

def incidents_for(c: TestClient, src: str) -> list[dict]:
    return [i for i in c.get("/api/incidents").json() if i["correlation_key"] == f"src:{src}"]


def test_alerts_from_one_source_are_auto_correlated():
    src = "203.0.113.40"
    with client() as c:
        assert import_csv(c, "solo.csv", [flow(src, 0)])["incidents_updated"] == []  # one alert is not a pattern
        result = import_csv(c, "corr.csv", [flow(src, 10, dst_port=445), flow(src, 20, dst_port=3389)])
        assert len(result["incidents_updated"]) == 1
        [incident] = incidents_for(c, src)
        assert incident["auto_correlated"] and incident["alert_count"] == 3 and incident["status"] == "Open"
        detail = c.get(f"/api/incidents/{incident['id']}").json()
        times = sorted(a["timestamp"] for a in detail["alerts"])
        assert detail["first_seen"] == times[0] and detail["last_seen"] == times[-1]

        # A later alert within the window joins the same incident and extends last_seen.
        import_csv(c, "corr-later.csv", [flow(src, 70, dst_port=23)])
        [incident] = incidents_for(c, src)
        assert incident["alert_count"] == 4
        # Far outside the window: not merged into the existing incident.
        import_csv(c, "corr-far.csv", [flow(src, 60 * 24, dst_port=22)])
        assert incidents_for(c, src)[0]["alert_count"] == 4


def test_auto_correlation_escalates_severity_and_respects_manual_unlink():
    src = "203.0.113.50"
    with client() as c:
        import_csv(c, "esc.csv", [flow(src, 0), flow(src, 1, dst_port=23)])
        [incident] = incidents_for(c, src)
        c.patch(f"/api/incidents/{incident['id']}", json={"severity": "Informational"})
        import_csv(c, "esc2.csv", [flow(src, 2, dst_port=445)])
        detail = c.get(f"/api/incidents/{incident['id']}").json()
        assert detail["alert_count"] == 3 and detail["severity"] != "Informational"

        removed = detail["alerts"][0]["id"]
        c.delete(f"/api/incidents/{incident['id']}/alerts/{removed}")
        import_csv(c, "esc3.csv", [flow(src, 3, dst_port=5900)])
        alert = c.get(f"/api/alerts/{removed}").json()
        assert alert["incident_id"] is None  # the analyst's unlink is respected

        c.patch(f"/api/incidents/{incident['id']}", json={"status": "Closed"})
        import_csv(c, "esc4.csv", [flow(src, 4, dst_port=5432), flow(src, 5, dst_port=1433)])
        open_incidents = [i for i in incidents_for(c, src) if i["status"] == "Open"]
        assert len(open_incidents) == 1 and open_incidents[0]["id"] != incident["id"]


def test_auto_correlation_can_be_disabled(monkeypatch):
    monkeypatch.setattr(settings, "auto_correlation_enabled", False)
    with client() as c:
        result = import_csv(c, "nocorr.csv", [flow("203.0.113.60", 0), flow("203.0.113.60", 1, dst_port=23)])
        assert result["alerts_created"] == 2 and result["incidents_updated"] == []


# --- Cookie sessions, CSRF and headers -----------------------------------------------------

def cookie_login(c: TestClient) -> dict:
    login_throttle.reset()
    response = c.post("/api/auth/login", json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD})
    assert response.status_code == 200
    return response


def test_login_sets_hardened_session_cookie():
    with TestClient(app, base_url="https://testserver") as c:
        response = cookie_login(c)
        cookie = response.headers["set-cookie"]
        assert cookie.startswith(f"{SESSION_COOKIE}=")
        for attribute in ("HttpOnly", "Secure", "SameSite=strict", "Path=/api"):
            assert attribute.lower() in cookie.lower()
        assert "access_token" not in response.json()
        assert c.get("/api/alerts").status_code == 200  # cookie alone authenticates reads
        me = c.get("/api/auth/me").json()
        assert me["csrf_token"] == response.json()["csrf_token"]


def test_cookie_writes_require_matching_csrf_token_and_allowed_origin():
    with TestClient(app, base_url="https://testserver") as c:
        csrf = cookie_login(c).json()["csrf_token"]
        body = {"title": "CSRF check", "summary": "x"}
        assert c.post("/api/incidents", json=body).status_code == 403
        assert c.post("/api/incidents", json=body, headers={"X-CSRF-Token": "forged"}).status_code == 403
        evil = c.post("/api/incidents", json=body, headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"})
        assert evil.status_code == 403
        ok = c.post("/api/incidents", json=body, headers={"X-CSRF-Token": csrf, "Origin": "http://localhost:5173"})
        assert ok.status_code == 201
        assert c.post("/api/auth/logout").status_code == 200
        assert c.get("/api/alerts").status_code == 401


def test_bearer_clients_do_not_need_csrf():
    with client() as c:
        assert c.post("/api/incidents", json={"title": "Script", "summary": "bearer"}).status_code == 201


def test_cookie_secure_flag_is_configurable(monkeypatch):
    monkeypatch.setattr(settings, "auth_cookie_secure", False)
    with TestClient(app) as c:
        cookie = cookie_login(c).headers["set-cookie"].lower()
        assert "httponly" in cookie and "secure" not in cookie.replace("httponly", "")


def test_api_security_headers():
    with TestClient(app) as c:
        for path in ("/health", "/api/alerts"):
            response = c.get(path)
            assert response.headers["x-frame-options"] == "DENY"
            assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
            assert "default-src 'none'" in response.headers["content-security-policy"]
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["referrer-policy"] == "no-referrer"
        docs = c.get("/docs")
        assert docs.headers["content-security-policy"] == "frame-ancestors 'none'"


def test_wildcard_cors_origin_is_rejected():
    with pytest.raises(ValueError):
        _ = Settings(_env_file=None, backend_cors_origins="*").cors_origins
