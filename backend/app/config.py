from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Explainable AI SOC Assistant"
    database_url: str = "sqlite:///./soc_xai.db"
    backend_cors_origins: str = "http://localhost:5173"
    seed_demo_data: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]


settings = Settings()
