from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file='.env',
        case_sensitive=False,
        extra='ignore'
    )

    app_name: str
    debug: bool
    async_postgresql_url: str
    sync_postgresql_url: str
    celery_broker: str
    mysql_url: str
    llm_base_url: str
    llm_api_key: str
    model_name: str
    translate_llm_base_url: str
    translate_llm_api_key: str = 'EMPTY'
    translate_model_name: str = 'translategemma'
    qdrant_url: str
    qdrant_collection_name: str = 'Cyber-Threat-Intelligence'
    embedding_base_url: str
    embedding_api_key: str = 'EMPTY'
    embedding_model_name: str = 'bge-m3'
    reports_dir: str = 'reports'


# 프로세스 생애주기 동안 .env 를 한 번만 읽도록 캐시한다(FastAPI/Celery 양쪽에서 재사용).
@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()