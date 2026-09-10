from typing import List, Optional
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    BOT_TOKEN: str = ""
    ADMIN_TELEGRAM_IDS: List[int] = []

    WEB_ADMIN_USERNAME: str = "admin"
    WEB_ADMIN_PASSWORD: str = "admin"
    SECRET_KEY: str = "super_secret_awg_manager_key_change_me"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7

    WEB_HOST: str = "0.0.0.0"
    WEB_PORT: int = 8080

    AWG_CONFIG_DIR: str = "/etc/amnezia/amneziawg"
    SERVER_PUBLIC_IP: Optional[str] = None
    DEFAULT_DNS: Optional[str] = None

    DATABASE_URL: str = "sqlite+aiosqlite:///data/awg_manager.db"

    @field_validator("ADMIN_TELEGRAM_IDS", mode="before")
    @classmethod
    def parse_admin_ids(cls, v):
        if isinstance(v, (int, float)):
            return [int(v)]
        if isinstance(v, str):
            if not v.strip():
                return []
            return [int(x.strip()) for x in v.split(",") if x.strip().isdigit()]
        if isinstance(v, (list, tuple)):
            return [int(x) for x in v if str(x).strip().isdigit()]
        return []

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
