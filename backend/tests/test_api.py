import os
from datetime import datetime, timezone

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SEED_DEMO_DATA"] = "true"

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import SessionLocal
from app.main import app
from app.models import Alert


def test_health_and_demo_dashboard():
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        response = client.get("/api/dashboard")
        assert response.status_code == 200
        data = response.json()
        assert data["data_label"] == "SYNTHETIC DEMO DATA"

        with SessionLocal() as db:
            probabilities = [
                probability
                for probability in db.scalars(select(Alert.model_probability)).all()
                if probability is not None
            ]
        expected_average = round(sum(probabilities) / len(probabilities), 4)
        assert data["metrics"]["average_model_confidence"] == expected_average


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


def test_alert_pagination_is_stable_when_timestamps_tie():
    with TestClient(app) as client:
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
    with TestClient(app) as client:
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
    with TestClient(app) as client:
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
