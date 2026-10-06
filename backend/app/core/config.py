"""AEGIS Core Configuration.

Defines runtime environment configurations using Pydantic v2 settings.
"""

from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "AEGIS"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"

    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@postgres:5432/aegis"
    SECRET_KEY: str = "super_secret_jwt_key_phase_0"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    CORS_ORIGINS: Union[List[str], str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.strip().startswith("["):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, list):
            return v
        return ["http://localhost:3000", "http://127.0.0.1:3000"]


settings = Settings()
