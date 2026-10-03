from app.config import Settings


def test_demo_seeding_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SEED_DEMO_DATA", raising=False)

    settings = Settings(_env_file=None)

    assert settings.seed_demo_data is False


def test_demo_seeding_can_be_enabled_explicitly(monkeypatch):
    monkeypatch.setenv("SEED_DEMO_DATA", "true")

    settings = Settings(_env_file=None)

    assert settings.seed_demo_data is True
