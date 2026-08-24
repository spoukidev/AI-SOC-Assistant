import os

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SEED_DEMO_DATA"] = "true"

from fastapi.testclient import TestClient
from app.main import app


def test_health_and_demo_dashboard():
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        response = client.get("/api/dashboard")
        assert response.status_code == 200
        data = response.json()
        assert data["data_label"] == "SYNTHETIC DEMO DATA + USER DATA"
        assert data["metrics"]["average_model_confidence"] is None


def test_research_metrics_are_not_fabricated():
    with TestClient(app) as client:
        data = client.get("/api/research/metrics").json()
        assert data == {"available": False, "message": "No experiment results available."}


def test_csv_import_persists_event_and_features():
    csv_data = (
        "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,duration,packets,bytes\n"
        "2026-08-21T12:00:00Z,192.0.2.10,198.51.100.20,52000,443,tcp,1.5,12,2400\n"
    )
    with TestClient(app) as client:
        response = client.post("/api/events/import", files={"file": ("flows.csv", csv_data, "text/csv")})
        assert response.status_code == 201
        result = response.json()
        assert result["accepted_rows"] == 1
        assert result["rejected_rows"] == 0
        imported = client.get("/api/events", params={"source": "CSV_IMPORT:flows.csv"}).json()
        assert len(imported) == 1
        assert imported[0]["features"]["bytes_per_packet"] == 200.0


def test_csv_upload_rejects_wrong_extension():
    with TestClient(app) as client:
        response = client.post("/api/events/import", files={"file": ("flows.exe", b"not csv", "application/octet-stream")})
        assert response.status_code == 415


def test_experiment_training_stores_real_metrics_and_model():
    from app.ml.demo_data import generate_labeled_demo_csv

    with TestClient(app) as client:
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
    with TestClient(app) as client:
        alerts = client.get("/api/alerts").json()
        assert alerts and alerts[0]["risk_score"] is not None
        alert_id = alerts[0]["id"]
        before = client.get(f"/api/alerts/{alert_id}").json()
        assert before["event"]["raw_event"]
        assert before["explanation"] is None
        response = client.patch(f"/api/alerts/{alert_id}", json={"status": "Investigating", "assigned_analyst": "Analyst One"})
        assert response.status_code == 200
        updated = response.json()
        assert updated["status"] == "Investigating"
        assert updated["assigned_analyst"] == "Analyst One"
        assert updated["evidence"] == before["evidence"]


def test_alert_workflow_rejects_unknown_status():
    with TestClient(app) as client:
        alert_id = client.get("/api/alerts").json()[0]["id"]
        assert client.patch(f"/api/alerts/{alert_id}", json={"status": "Deleted"}).status_code == 422
