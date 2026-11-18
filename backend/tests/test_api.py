import os
from datetime import datetime, timezone

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SEED_DEMO_DATA"] = "true"

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import SessionLocal
from app.main import app
from app.models import Alert, Incident
from conftest import auth_headers


SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
}


def assert_security_headers(response):
    for header, value in SECURITY_HEADERS.items():
        assert response.headers[header] == value


def test_health_and_demo_dashboard():
    with TestClient(app, headers=auth_headers()) as client:
        assert client.get("/health").status_code == 200
        response = client.get("/api/dashboard")
        assert response.status_code == 200
        data = response.json()
        assert data["data_label"] == "SYNTHETIC DEMO DATA + USER DATA"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"
        assert_security_headers(response)

        with SessionLocal() as db:
            probabilities = [
                probability
                for probability in db.scalars(select(Alert.model_probability)).all()
                if probability is not None
            ]
        expected_average = round(sum(probabilities) / len(probabilities), 4) if probabilities else None
        assert data["metrics"]["average_model_confidence"] == expected_average


def test_non_api_health_endpoint_is_not_marked_as_api_data():
    with TestClient(app, headers=auth_headers()) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert "cache-control" not in response.headers
        assert "pragma" not in response.headers
        assert_security_headers(response)


def test_security_headers_are_present_on_api_error_responses():
    with TestClient(app, headers=auth_headers()) as client:
        not_found = client.get("/api/events/999999")
        invalid_query = client.get("/api/events", params={"limit": 101})

        assert not_found.status_code == 404
        assert invalid_query.status_code == 422
        assert_security_headers(not_found)
        assert_security_headers(invalid_query)
        assert not_found.headers["cache-control"] == "no-store"
        assert invalid_query.headers["cache-control"] == "no-store"
        assert not_found.headers["pragma"] == "no-cache"
        assert invalid_query.headers["pragma"] == "no-cache"


def test_dashboard_ignores_invalid_model_probabilities():
    with TestClient(app, headers=auth_headers()) as client:
        with SessionLocal() as db:
            alerts = list(db.scalars(select(Alert).order_by(Alert.id).limit(2)).all())
            assert len(alerts) == 2
            alerts[0].model_probability = -0.25
            alerts[1].model_probability = 1.25
            invalid_ids = {alert.id for alert in alerts}
            db.commit()

            valid_probabilities = [
                probability
                for probability in db.scalars(select(Alert.model_probability)).all()
                if probability is not None and 0.0 <= probability <= 1.0
            ]

        dashboard = client.get("/api/dashboard")
        assert dashboard.status_code == 200
        expected_average = round(sum(valid_probabilities) / len(valid_probabilities), 4) if valid_probabilities else None
        assert dashboard.json()["metrics"]["average_model_confidence"] == expected_average

        for alert_id in invalid_ids:
            response = client.get(f"/api/alerts/{alert_id}")
            assert response.status_code == 200
            assert response.json()["model_probability"] is None


def test_research_metrics_are_not_fabricated():
    with TestClient(app, headers=auth_headers()) as client:
        data = client.get("/api/research/metrics").json()
        assert data == {"available": False, "message": "No experiment results available."}


def test_csv_import_persists_event_and_features():
    csv_data = (
        "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,duration,packets,bytes\n"
        "2026-08-21T12:00:00Z,192.0.2.10,198.51.100.20,52000,443,tcp,1.5,12,2400\n"
    )
    with TestClient(app, headers=auth_headers()) as client:
        response = client.post("/api/events/import", files={"file": ("flows.csv", csv_data, "text/csv")})
        assert response.status_code == 201
        result = response.json()
        assert result["accepted_rows"] == 1
        assert result["rejected_rows"] == 0
        imported = client.get("/api/events", params={"source": "CSV_IMPORT:flows.csv"}).json()
        assert len(imported) == 1
        assert imported[0]["features"]["bytes_per_packet"] == 200.0


def test_csv_upload_rejects_wrong_extension():
    with TestClient(app, headers=auth_headers()) as client:
        response = client.post("/api/events/import", files={"file": ("flows.exe", b"not csv", "application/octet-stream")})
        assert response.status_code == 415


def test_experiment_training_stores_real_metrics_and_model():
    from app.ml.demo_data import generate_labeled_demo_csv

    with TestClient(app, headers=auth_headers()) as client:
        response = client.post(
            "/api/experiments",
            data={"model_name": "logistic_regression", "name": "Synthetic API smoke test", "random_seed": "23"},
            files={"file": ("synthetic-labeled-demo.csv", generate_labeled_demo_csv(20), "text/csv")},
        )
        assert response.status_code == 201
        payload = response.json()
        metrics = payload["experiment"]["metrics"]
        assert "precision" in metrics and "false_positive" in metrics
        assert payload["model"]["feature_schema"] == "flow-v1"
        research = client.get("/api/research/metrics").json()
        assert research["available"] is True


def test_alert_detail_and_workflow_update_preserve_evidence():
    with TestClient(app, headers=auth_headers()) as client:
        alerts = client.get("/api/alerts").json()
        assert alerts and alerts[0]["risk_score"] is not None
        alert_id = next(a["id"] for a in alerts if a["evidence_type"] == "Synthetic deterministic rule")
        before = client.get(f"/api/alerts/{alert_id}").json()
        assert before["event"]["raw_event"]
        # Seeded alerts are rule-only, so the explanation is explicitly not applicable (no fake SHAP).
        assert before["explanation"]["status"] == "not_applicable"
        response = client.patch(f"/api/alerts/{alert_id}", json={"status": "Investigating", "assigned_analyst": "Analyst One"})
        assert response.status_code == 200
        updated = response.json()
        assert updated["status"] == "Investigating"
        assert updated["assigned_analyst"] == "Analyst One"
        assert updated["evidence"] == before["evidence"]


def test_alert_workflow_rejects_unknown_status():
    with TestClient(app, headers=auth_headers()) as client:
        alert_id = client.get("/api/alerts").json()[0]["id"]
        assert client.patch(f"/api/alerts/{alert_id}", json={"status": "Deleted"}).status_code == 422


def test_event_listing_is_bounded_and_pageable():
    with TestClient(app, headers=auth_headers()) as client:
        first_page = client.get("/api/events", params={"limit": 1})
        second_page = client.get("/api/events", params={"limit": 1, "offset": 1})

        assert first_page.status_code == 200
        assert second_page.status_code == 200
        assert len(first_page.json()) == 1
        assert len(second_page.json()) == 1
        assert first_page.json()[0]["id"] != second_page.json()[0]["id"]

        assert client.get("/api/events", params={"limit": 101}).status_code == 422
        assert client.get("/api/events", params={"offset": -1}).status_code == 422
        assert client.get("/api/events", params={"offset": 100001}).status_code == 422


def test_alert_listing_is_bounded_and_pageable():
    with TestClient(app, headers=auth_headers()) as client:
        first_page = client.get("/api/alerts", params={"limit": 1})
        second_page = client.get("/api/alerts", params={"limit": 1, "offset": 1})

        assert first_page.status_code == 200
        assert second_page.status_code == 200
        assert len(first_page.json()) == 1
        assert len(second_page.json()) == 1
        assert first_page.json()[0]["id"] != second_page.json()[0]["id"]

        assert client.get("/api/alerts", params={"limit": 101}).status_code == 422
        assert client.get("/api/alerts", params={"offset": -1}).status_code == 422
        assert client.get("/api/alerts", params={"offset": 100001}).status_code == 422


def test_alert_pagination_is_stable_when_timestamps_tie():
    with TestClient(app, headers=auth_headers()) as client:
        with SessionLocal() as db:
            tied_alerts = list(db.scalars(select(Alert).order_by(Alert.id.desc()).limit(2)).all())
            assert len(tied_alerts) == 2
            tied_time = datetime(2100, 1, 1, tzinfo=timezone.utc)
            expected_ids = sorted((item.id for item in tied_alerts), reverse=True)
            for item in tied_alerts:
                item.created_at = tied_time
            db.commit()

        first_page = client.get("/api/alerts", params={"limit": 1})
        second_page = client.get("/api/alerts", params={"limit": 1, "offset": 1})

        assert first_page.status_code == 200
        assert second_page.status_code == 200
        assert first_page.json()[0]["id"] == expected_ids[0]
        assert second_page.json()[0]["id"] == expected_ids[1]


def test_alert_listing_supports_triage_filters():
    with TestClient(app, headers=auth_headers()) as client:
        all_alerts = client.get("/api/alerts")
        assert all_alerts.status_code == 200
        alerts = all_alerts.json()
        assert alerts

        severity = alerts[0]["severity"]
        status = alerts[0]["status"]

        by_severity = client.get("/api/alerts", params={"severity": severity})
        assert by_severity.status_code == 200
        assert by_severity.json()
        assert all(item["severity"] == severity for item in by_severity.json())

        by_status = client.get("/api/alerts", params={"status": status})
        assert by_status.status_code == 200
        assert by_status.json()
        assert all(item["status"] == status for item in by_status.json())

        combined = client.get("/api/alerts", params={"severity": severity, "status": status})
        assert combined.status_code == 200
        assert all(
            item["severity"] == severity and item["status"] == status
            for item in combined.json()
        )

        assert client.get("/api/alerts", params={"severity": "NotASeverity"}).status_code == 422
        assert client.get("/api/alerts", params={"status": ""}).status_code == 422


def test_incident_listing_is_bounded_and_pageable():
    with TestClient(app, headers=auth_headers()) as client:
        all_incidents = client.get("/api/incidents")
        assert all_incidents.status_code == 200
        assert len(all_incidents.json()) >= 2

        first_page = client.get("/api/incidents", params={"limit": 1})
        second_page = client.get("/api/incidents", params={"limit": 1, "offset": 1})

        assert first_page.status_code == 200
        assert second_page.status_code == 200
        assert len(first_page.json()) == 1
        assert len(second_page.json()) == 1
        assert first_page.json()[0]["id"] != second_page.json()[0]["id"]

        assert client.get("/api/incidents", params={"limit": 101}).status_code == 422
        assert client.get("/api/incidents", params={"offset": -1}).status_code == 422
        assert client.get("/api/incidents", params={"offset": 100001}).status_code == 422


def test_incident_pagination_is_stable_when_last_seen_ties():
    with TestClient(app, headers=auth_headers()) as client:
        with SessionLocal() as db:
            tied_incidents = list(db.scalars(select(Incident).order_by(Incident.id.desc()).limit(2)).all())
            assert len(tied_incidents) == 2
            tied_time = datetime(2100, 1, 1, tzinfo=timezone.utc)
            expected_ids = sorted((item.id for item in tied_incidents), reverse=True)
            for item in tied_incidents:
                item.last_seen = tied_time
            db.commit()

        first_page = client.get("/api/incidents", params={"limit": 1})
        second_page = client.get("/api/incidents", params={"limit": 1, "offset": 1})

        assert first_page.status_code == 200
        assert second_page.status_code == 200
        assert first_page.json()[0]["id"] == expected_ids[0]
        assert second_page.json()[0]["id"] == expected_ids[1]


def test_experiment_rejects_unbounded_or_unknown_hyperparameters():
    from app.ml.demo_data import generate_labeled_demo_csv

    with TestClient(app, headers=auth_headers()) as client:
        for parameters in ('{"n_estimators": 1000000000}', '{"n_jobs": 64}'):
            response = client.post(
                "/api/experiments",
                data={"model_name": "random_forest", "parameters": parameters},
                files={"file": ("synthetic-labeled-demo.csv", generate_labeled_demo_csv(20), "text/csv")},
            )
            assert response.status_code == 422


def test_experiment_rejects_empty_dataset():
    with TestClient(app, headers=auth_headers()) as client:
        response = client.post(
            "/api/experiments",
            data={"model_name": "logistic_regression"},
            files={"file": ("empty.csv", b"", "text/csv")},
        )
        assert response.status_code == 422


def test_trained_model_predicts_imported_event():
    from app.ml.demo_data import generate_labeled_demo_csv

    csv_data = (
        "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,duration,packets,bytes\n"
        "2026-08-21T12:00:00Z,192.0.2.30,198.51.100.40,52000,22,tcp,0.1,2,120\n"
    )
    with TestClient(app, headers=auth_headers()) as client:
        trained = client.post(
            "/api/experiments",
            data={"model_name": "logistic_regression"},
            files={"file": ("synthetic-labeled-demo.csv", generate_labeled_demo_csv(20), "text/csv")},
        )
        assert trained.status_code == 201
        model_id = trained.json()["model"]["id"]
        assert client.post("/api/events/import", files={"file": ("predict.csv", csv_data, "text/csv")}).status_code == 201
        event_id = client.get("/api/events", params={"source": "CSV_IMPORT:predict.csv"}).json()[0]["id"]
        response = client.post(f"/api/models/{model_id}/predict/{event_id}")
        assert response.status_code == 201
        result = response.json()
        assert result["predicted_label"] in {"benign", "malicious"}
        assert 0.0 <= result["probability"] <= 1.0
