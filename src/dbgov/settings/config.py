from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DBGOV_",
        case_sensitive=False,
    )

    engine: str
    host: str
    port: int = 5432
    name: str
    user: str
    password: str
    options: str = ""
    sslmode: str = ""
