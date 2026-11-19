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
    # Browser sessions use an HttpOnly cookie. Secure by default; set AUTH_COOKIE_SECURE=false only for
    # plain-http local setups whose browser refuses Secure cookies.
    auth_cookie_secure: bool = True
    # Live rule engine and auto-correlation (see README "Detection and correlation").
    rule_engine_enabled: bool = True
    auto_correlation_enabled: bool = True
    correlation_window_minutes: int = 60
    correlation_min_alerts: int = 2

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origins(self) -> list[str]:
        origins = [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]
        if "*" in origins:
            # Credentialed (cookie) requests must never be allowed from any origin.
            raise ValueError("BACKEND_CORS_ORIGINS cannot contain '*'; list the frontend origins explicitly")
        return origins


settings = Settings()
