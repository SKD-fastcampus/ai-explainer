from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_ignore_empty=True)

    database_url: str
    firebase_credentials_path: str | None = None
    firebase_credentials_json: str | None = None


settings = Settings()
