"""
프로젝트 전역 설정을 관리하는 파일.
.env 파일의 값을 자동으로 읽어와서 Settings 객체로 만들어준다.
다른 파일에서는 `from app.config import settings` 로 가져다 쓰면 됨.
"""
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # 담당: 이용욱 (게이트웨이)
    # 정상 트래픽을 최종적으로 전달할 실제 서비스 주소
    target_service_url: str = "http://localhost:8080"
    elasticsearch_url: str = "http://elasticsearch:9200"

    # Rate Limiting 설정 (담당: 이용욱)
    rate_limit_window_seconds: int = 60
    rate_limit_max_requests: int = 30

    # app/config.py의 Settings 클래스 안에 아래 필드를 추가하세요.
    # (기존 target_service_url, rate_limit_* 등 필드들 밑에 이어서 넣으면 됩니다)
 
    # PostgreSQL 접속 정보 (담당: 이용욱)
    # k8s 안에서는 서비스 이름(postgres)으로 접근 - docker-compose 로컬 실행 시에도 동일하게 동작하도록
    # 서비스 이름을 그대로 씀 (k8s DNS가 이 이름을 postgres pod의 ClusterIP로 해석해줌)
    database_url: str = "postgresql://ids_admin:devpassword123@postgres:5432/ids_platform"
 
    # Redis 접속 정보 (담당: 이용욱)
    redis_url: str = "redis://redis:6379/0"
 

    # Brute Force 탐지 설정 (담당: 이용욱 / 하지환)
    brute_force_max_failures: int = 5
    brute_force_window_seconds: int = 300

    # CORS 허용 도메인 (담당: 이용욱)
    # 콤마로 구분해서 .env에 넣으면 됨 (예: "http://localhost:5173,https://우리도메인.com")
    # 절대 "*"로 두지 말 것 — 인증정보(쿠키/토큰)를 쓰는 API에서 와일드카드는
    # "아무 사이트나 이 API를 대신 호출해도 된다"는 뜻이 되어버림
    allowed_origins_raw: str = "http://localhost:5173,http://localhost:3000"

    # 우리가 실제로 운영하는 리버스 프록시(Traefik 등)의 IP 목록 (담당: 이용욱)
    # 이 목록에 있는 IP에서 직접 연결된 요청만 X-Forwarded-For 헤더를 신뢰한다.
    # 비워두면(로컬 개발 등) X-Forwarded-For를 아예 무시하고 직접 연결 IP만 사용.
    trusted_proxies_raw: str = ""

    # 로그/블랙리스트 저장 경로 (담당: 윤재영)
    attack_log_path: str = "./data/attack_log.jsonl"
    blacklist_path: str = "./data/blacklist.json"

    class Config:
        env_file = ".env"

    @property
    def allowed_origins(self) -> List[str]:
        """콤마로 구분된 문자열을 리스트로 변환해서 사용하기 편하게 제공."""
        return [origin.strip() for origin in self.allowed_origins_raw.split(",") if origin.strip()]

    @property
    def trusted_proxies(self) -> List[str]:
        """콤마로 구분된 신뢰 프록시 IP 목록을 리스트로 변환."""
        return [ip.strip() for ip in self.trusted_proxies_raw.split(",") if ip.strip()]


# 앱 전체에서 공유하는 설정 인스턴스 (싱글턴처럼 사용)
settings = Settings()