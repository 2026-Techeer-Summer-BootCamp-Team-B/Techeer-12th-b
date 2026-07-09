"""
프로젝트 전역 설정을 관리하는 파일.
.env 파일의 값을 자동으로 읽어와서 Settings 객체로 만들어준다.
다른 파일에서는 `from app.config import settings` 로 가져다 쓰면 됨.
"""
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # 담당: 이용욱 (게이트웨이)
    # 정상 트래픽을 최종적으로 전달할 실제 서비스 주소.
    # 이제 백엔드 자체가 k3d 클러스터 안에 Pod로 떠서, k8s DNS로 juice-shop 서비스에 접근한다.
    target_service_url: str = "http://juice-shop:3000"

    # Rate Limiting 설정 (담당: 이용욱)
    rate_limit_window_seconds: int = 60
    rate_limit_max_requests: int = 30

    # Redis 접속 정보 (담당: 이용욱) - k8s DNS로 redis 서비스에 접근
    redis_url: str = "redis://redis:6379/0"

    # OTel Collector 접속 정보 (담당: 심다움) - 탐지된 AttackLog를 여기로 OTLP(HTTP) push.
    # otel-collector-deployment.yaml이 만드는 클러스터 내부 Service 이름을 그대로 씀.
    # 필드명을 OTel 표준 환경변수(OTEL_EXPORTER_OTLP_ENDPOINT)에 그대로 맞춰서
    # pydantic-settings가 별도 alias 없이 자동으로 매핑하게 함.
    otel_exporter_otlp_endpoint: str = "http://otel-collector:4318"

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