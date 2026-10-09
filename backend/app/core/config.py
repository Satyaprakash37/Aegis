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
    SECRET_KEY: str = "tt7pxPBH6vBi5h43PuoZiU4RajuKFqEXBPHc_4TCXCOvTxvC488kembI2TlWENTr"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    CORS_ORIGINS: Union[List[str], str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    NVD_API_KEY: Union[str, None] = ""
    ENABLE_SSRF_PROTECTION: bool = False
    BLOCK_METADATA_IPS: bool = True
    SUBFINDER_VIRUSTOTAL_KEY: str = ""
    SUBFINDER_SECURITYTRAILS_KEY: str = ""
    MSF_RPC_HOST: str = "metasploit"
    MSF_RPC_PORT: int = 55553
    MSF_RPC_PASSWORD: str = "aegis_lab_msf_rpc_secret_55553"
    MSF_RPC_SSL: bool = False

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.strip().startswith("["):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, list):
            return v
        return ["http://localhost:3000", "http://127.0.0.1:3000"]


settings = Settings()
