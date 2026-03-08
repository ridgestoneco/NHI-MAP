from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    database_url: str = "postgresql://nhi_user:changeme@localhost:5432/nhi_map"
    api_key: str = "changeme-generate-a-real-key"
    rate_limit: str = "30/minute"

    model_config = {"env_file": ".env"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
