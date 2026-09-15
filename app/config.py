"""Environment configuration, loaded once and shared.

Everything that varies between machines (DB location, API keys) lives in .env
and is read here. No other module reads os.environ directly.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # SQLAlchemy connection string, e.g.
    # postgresql+psycopg2://user:pass@localhost:5432/cyber_risk
    database_url: str

    # Optional. Without it NVD allows 5 requests/30s; with it, 50.
    nvd_api_key: str | None = None


@lru_cache
def get_settings() -> Settings:
    """Cached so the .env file is parsed once per process."""
    return Settings()
