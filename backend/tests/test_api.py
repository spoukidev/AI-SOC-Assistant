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


def test_event_listing_is_bounded_and_pageable():
    with TestClient(app) as client:
        first_page = client.get("/api/events", params={"limit": 1})
        second_page = client.get("/api/events", params={"limit": 1, "offset": 1})

        assert first_page.status_code == 200
        assert second_page.status_code == 200
        assert len(first_page.json()) == 1
        assert len(second_page.json()) == 1
        assert first_page.json()[0]["id"] != second_page.json()[0]["id"]

        assert client.get("/api/events", params={"limit": 101}).status_code == 422
        assert client.get("/api/events", params={"offset": -1}).status_code == 422


def test_alert_listing_is_bounded_and_pageable():
    with TestClient(app) as client:
        first_page = client.get("/api/alerts", params={"limit": 1})
        second_page = client.get("/api/alerts", params={"limit": 1, "offset": 1})

        assert first_page.status_code == 200
        assert second_page.status_code == 200
        assert len(first_page.json()) == 1
        assert len(second_page.json()) == 1
        assert first_page.json()[0]["id"] != second_page.json()[0]["id"]

        assert client.get("/api/alerts", params={"limit": 101}).status_code == 422
        assert client.get("/api/alerts", params={"offset": -1}).status_code == 422
