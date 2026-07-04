"""
담당: 이용욱 (게이트웨이 & 트래픽 컨트롤러)

.env 파일에서 값을 읽어오는 전역 설정.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    rate_limit_window_seconds: float = 10.0
    rate_limit_max_requests: int = 50
    blacklist_path: str = "app/storage/blacklist.json"


settings = Settings()
