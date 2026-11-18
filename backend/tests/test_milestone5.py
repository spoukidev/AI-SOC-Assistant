"""Milestone 5: authentication, SHAP explanations, detection rules, incidents and honest demo data."""
import csv
import io
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SEED_DEMO_DATA"] = "true"

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, select, text

from app.auth import (
    LoginThrottle, build_auth_config, create_access_token, get_auth_config, hash_password, login_throttle,
    verify_password,
)
from app.config import Settings
from app.database import SessionLocal, ensure_schema
from app.main import app
from app.ml.demo_data import generate_labeled_demo_csv
from app.ml.explain import get_explainer
from app.models import Alert, DetectionRule, Incident
from conftest import TEST_ADMIN_PASSWORD, TEST_ADMIN_USERNAME, auth_headers

OPEN_ROUTES = {("/health", "GET"), ("/api/auth/login", "POST")}


def client() -> TestClient:
    return TestClient(app, headers=auth_headers())


def malicious_flow_csv(name_index: int = 0) -> str:
    """One malicious-pattern row from the synthetic generator, without its label."""
    rows = list(csv.DictReader(io.StringIO(generate_labeled_demo_csv(30).decode())))
    row = [r for r in rows if r["label"] == "malicious"][name_index]
    row.pop("label")
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(row))
    writer.writeheader()
    writer.writerow(row)
    return output.getvalue()


def train_and_predict(c: TestClient, model_name: str, filename: str) -> tuple[int, dict]:
    trained = c.post("/api/experiments", data={"model_name": model_name, "random_seed": "7"},
                     files={"file": ("synthetic-labeled-demo.csv", generate_labeled_demo_csv(40), "text/csv")})
    assert trained.status_code == 201, trained.text
    model_id = trained.json()["model"]["id"]
    assert c.post("/api/events/import", files={"file": (filename, malicious_flow_csv(), "text/csv")}).status_code == 201
    event_id = c.get("/api/events", params={"source": f"CSV_IMPORT:{filename}"}).json()[0]["id"]
    prediction = c.post(f"/api/models/{model_id}/predict/{event_id}")
    assert prediction.status_code == 201, prediction.text
    return model_id, prediction.json()


# --- Authentication -------------------------------------------------------------------------

def test_every_data_endpoint_rejects_missing_token():
    with TestClient(app) as anonymous:
        checked = 0
        for route_path, operations in app.openapi()["paths"].items():
            for method in (m.upper() for m in operations):
                if (route_path, method) in OPEN_ROUTES:
                    continue
                path = route_path.replace("{", "").replace("}", "")
                for name in ("alert_id", "event_id", "model_id", "rule_id", "incident_id"):
                    path = path.replace(name, "1")
                response = anonymous.request(method, path)
                assert response.status_code == 401, f"{method} {route_path} returned {response.status_code}"
                assert response.headers["www-authenticate"] == "Bearer"
                checked += 1
        assert checked >= 25
        assert anonymous.get("/health").status_code == 200


def test_invalid_expired_and_forged_tokens_are_rejected():
    config = get_auth_config()
    now = datetime.now(timezone.utc)
    expired = jwt.encode({"sub": TEST_ADMIN_USERNAME, "iss": "soc-xai", "iat": now - timedelta(hours=2),
                          "exp": now - timedelta(hours=1)}, config.secret_key, algorithm="HS256")
    forged = jwt.encode({"sub": TEST_ADMIN_USERNAME, "iss": "soc-xai", "iat": now, "exp": now + timedelta(hours=1)},
                        "a-different-secret-key-that-is-long-enough!!", algorithm="HS256")
    unsigned = jwt.encode({"sub": TEST_ADMIN_USERNAME, "iss": "soc-xai", "iat": now, "exp": now + timedelta(hours=1)},
                          None, algorithm="none")
    wrong_user, _ = create_access_token("someone-else")
    with TestClient(app) as c:
        for token in ("garbage", expired, forged, unsigned, wrong_user):
            assert c.get("/api/alerts", headers={"Authorization": f"Bearer {token}"}).status_code == 401
        assert c.get("/api/alerts", headers={"Authorization": "Basic YWRtaW46YWRtaW4="}).status_code == 401


def test_login_issues_working_token_and_rejects_bad_password():
    login_throttle.reset()
    with TestClient(app) as c:
        bad = c.post("/api/auth/login", json={"username": TEST_ADMIN_USERNAME, "password": "wrong"})
        assert bad.status_code == 401
        unknown = c.post("/api/auth/login", json={"username": "root", "password": TEST_ADMIN_PASSWORD})
        assert unknown.status_code == 401
        good = c.post("/api/auth/login", json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD})
        assert good.status_code == 200
        body = good.json()
        assert body["token_type"] == "bearer" and body["expires_in"] > 0
        me = c.get("/api/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
        assert me.status_code == 200 and me.json() == {"username": TEST_ADMIN_USERNAME}
    login_throttle.reset()


def test_repeated_failed_logins_are_throttled():
    login_throttle.reset()
    with TestClient(app) as c:
        for _ in range(5):
            assert c.post("/api/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401
        blocked = c.post("/api/auth/login", json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD})
        assert blocked.status_code == 429
    login_throttle.reset()


def test_password_hashing_and_auth_config(monkeypatch):
    encoded = hash_password("correct horse battery staple")
    assert encoded.startswith("pbkdf2_sha256:") and "correct" not in encoded
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong", encoded)
    assert not verify_password("anything", "not-a-hash")

    for name in ("AUTH_SECRET_KEY", "ADMIN_PASSWORD", "ADMIN_PASSWORD_HASH"):
        monkeypatch.delenv(name, raising=False)
    generated = build_auth_config(Settings(_env_file=None))
    assert generated.generated_password and generated.generated_secret
    assert len(generated.secret_key) >= 32

    with pytest.raises(RuntimeError):
        build_auth_config(Settings(_env_file=None, auth_secret_key="short", admin_password="x" * 12))
    hashed = build_auth_config(Settings(_env_file=None, auth_secret_key="k" * 40, admin_password_hash=encoded))
    assert hashed.password_hash == encoded and not hashed.generated_password


def test_login_throttle_window_expires():
    throttle = LoginThrottle(max_failures=2, window_seconds=0)
    throttle.fail("x")
    throttle.fail("x")
    assert not throttle.blocked("x")


# --- Honest demo data, detection rules and incidents ---------------------------------------

def test_seeded_alerts_are_rule_only_without_fake_probabilities():
    with client() as c:
        with SessionLocal() as db:
            seeded = db.scalars(select(Alert).where(Alert.evidence_type == "Synthetic deterministic rule")).all()
            assert seeded
            assert all(alert.model_probability is None and alert.rule_id is not None for alert in seeded)
        alert_id = seeded[0].id
        detail = c.get(f"/api/alerts/{alert_id}").json()
        assert detail["model_probability"] is None
        assert detail["explanation"]["status"] == "not_applicable"
        assert detail["rule"]["key"] == "demo-unusual-connection-v1"
        assert detail["risk_components"]["model_evidence"] == 0


def test_detection_rules_are_stored_and_editable():
    with client() as c:
        rules = c.get("/api/detection-rules").json()
        demo = next(rule for rule in rules if rule["key"] == "demo-unusual-connection-v1")
        assert demo["built_in"] is True and demo["alert_count"] >= 4
        detail = c.get(f"/api/detection-rules/{demo['id']}").json()
        assert len(detail["recent_alerts"]) == demo["alert_count"]

        assert c.patch(f"/api/detection-rules/{demo['id']}", json={"risk_points": 30}).status_code == 422
        updated = c.patch(f"/api/detection-rules/{demo['id']}", json={"enabled": False, "risk_points": 20})
        assert updated.status_code == 200
        assert updated.json()["enabled"] is False and updated.json()["risk_points"] == 20
        assert updated.json()["version"] == demo["version"] + 1
        unchanged = c.patch(f"/api/detection-rules/{demo['id']}", json={"enabled": False})
        assert unchanged.json()["version"] == demo["version"] + 1
        c.patch(f"/api/detection-rules/{demo['id']}", json={"enabled": True, "risk_points": 25})
        assert c.get("/api/detection-rules/999999").status_code == 404


def test_seeded_incidents_link_their_alerts():
    with client() as c:
        incidents = c.get("/api/incidents").json()
        synthetic = [item for item in incidents if item["synthetic"]]
        assert len(synthetic) >= 2
        detail = c.get(f"/api/incidents/{synthetic[0]['id']}").json()
        assert detail["alert_count"] == len(detail["alerts"]) >= 1
        alert_detail = c.get(f"/api/alerts/{detail['alerts'][0]['id']}").json()
        assert alert_detail["incident"]["id"] == synthetic[0]["id"]


def test_incident_crud_and_alert_linking():
    with client() as c:
        alerts = c.get("/api/alerts").json()
        first, second = alerts[0]["id"], alerts[1]["id"]
        created = c.post("/api/incidents", json={"title": "Analyst case", "severity": "High",
                                                 "summary": "Grouped for review.", "alert_ids": [first]})
        assert created.status_code == 201
        incident = created.json()
        assert incident["synthetic"] is False and incident["status"] == "Open"
        assert [a["id"] for a in incident["alerts"]] == [first]

        linked = c.post(f"/api/incidents/{incident['id']}/alerts", json={"alert_ids": [second, first]}).json()
        assert sorted(a["id"] for a in linked["alerts"]) == sorted([first, second])
        times = sorted(a["timestamp"] for a in linked["alerts"])
        assert linked["first_seen"] == times[0] and linked["last_seen"] == times[-1]

        assert c.patch(f"/api/incidents/{incident['id']}", json={"status": "Deleted"}).status_code == 422
        patched = c.patch(f"/api/incidents/{incident['id']}", json={"status": "Contained", "severity": "Critical"}).json()
        assert patched["status"] == "Contained" and patched["severity"] == "Critical"

        unlinked = c.delete(f"/api/incidents/{incident['id']}/alerts/{second}").json()
        assert [a["id"] for a in unlinked["alerts"]] == [first]
        assert c.delete(f"/api/incidents/{incident['id']}/alerts/{second}").status_code == 404
        assert c.post(f"/api/incidents/{incident['id']}/alerts", json={"alert_ids": [999999]}).status_code == 404
        assert c.post("/api/incidents", json={"title": "", "summary": "x"}).status_code == 422
        assert c.get("/api/incidents", params={"status": "Contained"}).json()[0]["id"] == incident["id"]


# --- SHAP explainability ----------------------------------------------------------------

@pytest.mark.parametrize("model_name", ["logistic_regression", "random_forest", "xgboost"])
def test_global_explanation_covers_all_flow_features(model_name):
    with client() as c:
        model_id, _ = train_and_predict(c, model_name, f"global-{model_name}.csv")
        explanation = c.get(f"/api/models/{model_id}/explanation")
        assert explanation.status_code == 200
        body = explanation.json()
        assert body["status"] == "available"
        assert len(body["importance"]) == 12
        assert body["importance"] == sorted(body["importance"], key=lambda item: item["mean_abs_shap"], reverse=True)
        assert body["output_space"] == ("log_odds" if model_name == "logistic_regression" else "probability")
        assert c.get("/api/models/999999/explanation").status_code == 404


@pytest.mark.parametrize("model_name", ["logistic_regression", "random_forest", "xgboost"])
def test_ml_alert_has_additive_local_explanation(model_name):
    with client() as c:
        _, prediction = train_and_predict(c, model_name, f"local-{model_name}.csv")
        assert prediction["predicted_label"] == "malicious"
        assert prediction["explanation"]["status"] == "available"
        detail = c.get(f"/api/alerts/{prediction['alert_id']}").json()
        explanation = detail["explanation"]
        assert detail["explanation_status"] == "available"
        assert explanation["model"]["model_name"] == model_name
        assert 1 <= len(explanation["contributions"]) <= 8
        total = explanation["base_value"] + sum(item["shap_value"] for item in explanation["contributions"]) \
            + explanation["other_features_total"]
        # SHAP additivity: base value + contributions reproduce the model output being explained.
        assert total == pytest.approx(explanation["model_output"], abs=1e-3)
        for item in explanation["contributions"]:
            assert item["direction"] in {"increases_malicious_score", "decreases_malicious_score", "neutral"}


def test_pre_milestone5_artifact_is_reported_as_unavailable(tmp_path):
    import joblib

    from app.ml.detector import create_detector
    from app.ml.preprocessing import load_labeled_csv

    features, labels, _ = load_labeled_csv(generate_labeled_demo_csv(20))
    detector = create_detector("logistic_regression").train(features, labels)
    legacy = tmp_path / "legacy.joblib"
    joblib.dump({"name": "logistic_regression", "random_seed": 42, "parameters": {}, "pipeline": detector.pipeline}, legacy)
    from app.ml.explain import ExplanationUnavailable, safe_global_explanation

    with pytest.raises(ExplanationUnavailable):
        get_explainer(legacy, tmp_path)
    assert safe_global_explanation(legacy, tmp_path)["status"] == "unavailable"
    assert safe_global_explanation(legacy, tmp_path / "elsewhere")["status"] == "unavailable"


# --- Schema upgrade -----------------------------------------------------------------------

def test_ensure_schema_adds_milestone5_columns_to_legacy_database(tmp_path):
    legacy = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with legacy.begin() as connection:
        connection.execute(text("CREATE TABLE incidents (id INTEGER PRIMARY KEY, title VARCHAR(200))"))
        connection.execute(text("CREATE TABLE alerts (id INTEGER PRIMARY KEY, title VARCHAR(200))"))
        connection.execute(text("INSERT INTO incidents (id, title) VALUES (1, 'old')"))
    added = ensure_schema(legacy)
    assert set(added) == {"alerts.rule_id", "alerts.incident_id", "incidents.synthetic"}
    columns = {column["name"] for column in inspect(legacy).get_columns("alerts")}
    assert {"rule_id", "incident_id"} <= columns
    with legacy.connect() as connection:
        assert connection.execute(text("SELECT synthetic FROM incidents")).scalar() == 0
    assert ensure_schema(legacy) == []
