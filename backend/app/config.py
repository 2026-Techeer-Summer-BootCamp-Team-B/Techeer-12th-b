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

    # 이 WAF backend 인스턴스가 보호하는 타깃의 이름 - IDS-COLLECTOR의 `targets`
    # 테이블(POST /targets로 등록하는 name)과 같은 값으로 맞춰야 한다. 여러 타깃을
    # 보호하려면 WAF backend+WAS 사이드카 한 세트를 타깃마다 통째로 복제 배포하고
    # (juice-shop-with-nginx-sidecar.yaml/backend-deployment.yaml 참고) 이 값과
    # TARGET_SERVICE_URL만 그 타깃에 맞게 바꾼다 - 하나의 프로세스가 여러 타깃을
    # 동시에 처리하는 라우팅은 하지 않는다(Traefik이 원래 담당하는 역할이라
    # 여기서 다시 만들 필요 없음). WafAlert.target_name(schemas.py)에 실어서
    # IDS-COLLECTOR까지 전파된다(app/proxy/proxy.py 참고).
    target_name: str = "juice-shop"

    # Rate Limiting 설정 (담당: 이용욱)
    rate_limit_window_seconds: int = 60
    rate_limit_max_requests: int = 30

    # OTel Collector 접속 정보 (담당: 심다움) - 탐지된 WafAlert를 여기로 OTLP(HTTP) push.
    # otel-collector-deployment.yaml이 만드는 클러스터 내부 Service 이름을 그대로 씀.
    # 필드명을 OTel 표준 환경변수(OTEL_EXPORTER_OTLP_ENDPOINT)에 그대로 맞춰서
    # pydantic-settings가 별도 alias 없이 자동으로 매핑하게 함.
    otel_exporter_otlp_endpoint: str = "http://otel-collector:4318"

    # otel-collector가 죽어있는 동안 export가 실패한 배치를 로컬에 남기는 fallback
    # 파일 경로 (담당: 심다움) - BatchLogRecordProcessor는 export() 실패를 감지해도
    # 재시도/알림 없이 그 배치를 버리는 게 기본 동작이라(실측 확인), 완전 유실을
    # 막기 위한 최소한의 장치. 파드 재시작 전까지만 버텨주는 임시 방편이라
    # (emptyDir 등 별도 볼륨을 안 붙이면 파드가 죽으면 이것도 같이 사라짐), 근본
    # 해결은 아니고 "조용히 사라지진 않게" 하는 수준.
    otel_export_fallback_path: str = "/tmp/waf-otel-export-fallback.jsonl"

    # Brute Force 탐지 설정 (담당: 이용욱 / 하지환)
    brute_force_max_failures: int = 5
    brute_force_window_seconds: int = 300

    # User-Agent 로테이션 탐지 설정 (2026-07-18, S28 보강 재료)
    # 근거: OWASP ZAP의 실제 active scan을 돌려서 확인한 결과, ZAP은 매 요청마다
    # Chrome/Firefox/Yahoo Slurp/msnbot 등으로 User-Agent를 계속 바꿔가며 자신을
    # 숨긴다 - BAD_BOT_USER_AGENTS 문자열 매칭(S28)은 sqlmap/nikto처럼 "정직하게
    # 자기 정체를 밝히는" 구식 CLI 툴만 잡을 수 있고, 이런 회피형 스캐너는
    # 원천적으로 못 잡는 구조적 한계가 있었다. "짧은 시간에 같은 IP가 서로 다른
    # User-Agent를 여러 개 쓴다"는 행위 자체(정상 브라우저는 세션 내내 UA가
    # 고정됨)를 신호로 삼아 UA 문자열 내용과 무관하게 탐지한다.
    ua_rotation_window_seconds: int = 60
    ua_rotation_distinct_threshold: int = 4

    # CORS 허용 도메인 (담당: 이용욱)
    # 콤마로 구분해서 .env에 넣으면 됨 (예: "http://localhost:5173,https://우리도메인.com")
    # 절대 "*"로 두지 말 것 — 인증정보(쿠키/토큰)를 쓰는 API에서 와일드카드는
    # "아무 사이트나 이 API를 대신 호출해도 된다"는 뜻이 되어버림
    allowed_origins_raw: str = "http://localhost:5173,http://localhost:3000"

    # 우리가 실제로 운영하는 리버스 프록시(Traefik 등)의 IP 목록 (담당: 이용욱)
    # 이 목록에 있는 IP에서 직접 연결된 요청만 X-Forwarded-For 헤더를 신뢰한다.
    # 비워두면(로컬 개발 등) X-Forwarded-For를 아예 무시하고 직접 연결 IP만 사용.
    trusted_proxies_raw: str = ""

    # WAF 운영 모드 (담당: 심다움) — 분석 서버가 규격화하는 events.normalized 스키마의
    # waf.mode/waf.blocked 값을 여기서 채운다.
    # "detection"(기본값): 탐지만 하고 로그만 남김. "prevention": 시연용으로 blocked=True를
    # 로그에 표시. 실제 요청 차단(403 응답)은 여전히 WAS 책임이라 이 모드가 트래픽을
    # 막지는 않는다 — 어디까지나 로그에 남는 표시값이다.
    waf_mode: str = "detection"

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