"""
Centralized application configuration using pydantic-settings.

Loads configuration from environment variables (and an optional `.env` file),
following the Twelve-Factor App methodology: config that varies between
deployments (dev/staging/prod) lives in the environment, NOT hardcoded in
source code. This is standard practice for production-grade services.

Usage:
    from config import settings
    settings.CLOUD_API_KEY
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings, sourced from environment variables / `.env` file.

    Attributes:
        APP_NAME: Human-readable service name (used in logs/OpenAPI docs).
        ENVIRONMENT: Deployment environment ("development", "staging", "production").
        LOG_LEVEL: Python logging level name (e.g., "INFO", "DEBUG").
        HOST / PORT: Bind address for uvicorn.
        MOCK_DB_PATH: Filesystem path of the JSON mock persistence layer.
        CLOUD_API_KEY: Shared-secret API key required (via `X-API-Key` header)
                        to call the ingestion and authorize-decrypt endpoints.
                        The public "stored-ciphertexts" endpoint deliberately
                        does NOT require it (see main_server.py docstring).
        MAX_PACKET_AGE_SECONDS: Default freshness window for authorize-decrypt
                                 replay-protection, if the caller doesn't specify one.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "Athlete Biometrics Secure Cloud Server"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"

    HOST: str = "0.0.0.0"
    PORT: int = 8000

    MOCK_DB_PATH: str = "mock_db.json"

    CLOUD_API_KEY: str = "dev-only-insecure-change-me"

    MAX_PACKET_AGE_SECONDS: Optional[float] = 300.0


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton `Settings` instance (loaded once per process)."""
    return Settings()


settings = get_settings()
