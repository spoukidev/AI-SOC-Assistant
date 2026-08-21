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
        assert data["data_label"] == "SYNTHETIC DEMO DATA"
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
