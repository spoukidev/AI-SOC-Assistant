from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Explainable AI SOC Assistant"
    database_url: str = "sqlite:///./soc_xai.db"
    backend_cors_origins: str = "http://localhost:5173"
    # Demo data must be explicitly enabled so a deployment cannot silently seed fixtures.
    seed_demo_data: bool = False
    max_upload_bytes: int = 5 * 1024 * 1024
    max_import_rows: int = 10_000
    model_artifact_dir: str = "./artifacts/models"
    # Authentication (Milestone 5). No working default credentials are shipped:
    # unset secrets are generated at startup (see app/auth.py) and logged as warnings.
    auth_secret_key: str | None = None
    admin_username: str = "admin"
    admin_password: str | None = None
    admin_password_hash: str | None = None
    access_token_ttl_minutes: int = 60

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]


settings = Settings()
