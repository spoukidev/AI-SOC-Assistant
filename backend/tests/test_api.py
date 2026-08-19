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
