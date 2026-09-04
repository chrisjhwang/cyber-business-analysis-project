"""Environment configuration.

Loaded once at import time so every module (app, ingestion scripts, Alembic)
reads the same settings instead of calling os.getenv() ad hoc.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    database_url: str = (
        "postgresql+psycopg2://postgres:postgres@localhost:5432/cyber_risk"
    )
    # Optional: raises the NVD rate limit from 5 to 50 requests per 30s.
    nvd_api_key: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
