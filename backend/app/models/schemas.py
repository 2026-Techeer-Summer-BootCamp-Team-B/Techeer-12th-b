"""
노션 ERD 초안(WafAlert / IPBlacklist)을 그대로 코드로 옮긴 파일.
API 요청/응답과 저장 형식 모두 여기 정의된 모델을 기준으로 맞춘다.

DetectionRule(정규식을 DB로 관리)은 Postgres 제거와 함께 삭제됨 - 실제로도 탐지 엔진은
signatures.py에 하드코딩된 SIGNATURES만 참조하고 있어 연결된 적이 없었다.
"""
from datetime import datetime
from enum import Enum
from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from app.config import settings


def _new_internal_ref() -> str:
    """이 프로세스 안에서만 쓰는 상관용 참조값 — event.id 아님.

    파이프라인 계약 v1.0 기준 event.id = sha256_hex(observedTimeUnixNano + "|" + body)이고,
    이 계산은 SIEM 정규화 워커가 이 서비스가 내보내는 OTLP 레코드의 observed_timestamp/body를
    가지고 수행한다 (app/otel/logger.py 참고). 여기서는 그 값을 복제하지 않는다 — 애초에
    body(=model_dump_json() 결과)에 이 필드가 포함되므로 "자기 자신을 포함한 body의 해시"는
    성립할 수 없다.
    """
    return str(uuid4())


class AttackType(str, Enum):
    """공격 유형. 새 탐지 로직을 추가하면 여기에도 반드시 추가할 것.

    22종 공격 목록 기준으로 정리 (팀 문서 "WAF 방어 대상 공격 유형" 참고).
    IDOR와 GraphQL 공격은 팀 문서에서 취소선 처리(보류)되어 있어 일단 주석 처리함 —
    필요해지면 주석만 풀면 됨.
    """
    SQLI = "sqli"
    XSS = "xss"
    OS_COMMAND_INJECTION = "os_command_injection"
    PATH_TRAVERSAL = "path_traversal"          # LFI / Directory Traversal
    RFI = "rfi"                                # Remote File Inclusion
    FILE_UPLOAD = "file_upload"                # Web Shell Upload
    SSTI = "ssti"                              # Server-Side Template Injection
    XXE = "xxe"                                # XML External Entity
    SSRF = "ssrf"                              # Server-Side Request Forgery
    HPP = "hpp"                                # HTTP Parameter Pollution
    CSRF = "csrf"                              # Cross-Site Request Forgery
    # IDOR = "idor"                            # 보류 (팀 문서에서 취소선 처리됨)
    NOSQLI = "nosqli"                          # NoSQL Injection
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    OPEN_REDIRECT = "open_redirect"
    CRLF_INJECTION = "crlf_injection"
    # GRAPHQL_ATTACK = "graphql_attack"         # 보류 (팀 문서에서 취소선 처리됨)
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    CORS_ABUSE = "cors_abuse"                  # CORS Misconfiguration 악용
    JWT_FORGERY = "jwt_forgery"
    BRUTE_FORCE = "brute_force"
    BAD_BOT = "bad_bot"                        # 알려진 해킹 툴/스캐너 User-Agent
    RATE_LIMIT_ABUSE = "rate_limit_abuse"       # 짧은 시간 내 과다 요청
    UA_ROTATION = "ua_rotation"                 # 짧은 시간에 같은 IP가 User-Agent를 여러 개 바꿔씀(핑거프린팅 회피 정황)


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    CRITICAL = "CRITICAL"


class WafAlert(BaseModel):
    """
    담당: 심다움 (로그 마스터)
    탐지 엔진(윤재영: 서버·DB / 심다움: 클라이언트)이 공격을 잡아내면
    이 형태로 만들어서 log_store에 저장한다.
    """
    # 내부 상관/디버깅용 참조값일 뿐 event.id가 아님 — 자세한 이유는 _new_internal_ref() 참고.
    internal_ref: str = Field(default_factory=_new_internal_ref)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: str
    attack_type: AttackType
    target_endpoint: str
    http_method: str
    # 페이로드 전체가 아니라 일부만 저장 (로그 자체가 공격 벡터가 되는 것 방지)
    payload_snippet: str = Field(max_length=200)
    user_agent: Optional[str] = None
    matched_rule_id: Optional[str] = None
    # matched_rule_id는 조회용 슬러그(예: sqli_union_select), 이건 사람이 읽는 표시용
    # 이름(예: "SQL Injection: UNION SELECT") - 예전엔 이 필드가 없어서 정규화 단계가
    # rule.name에 rule.id를 그대로 재사용해야 했다(2026-07-14 분리).
    matched_rule_name: Optional[str] = None
    # WAF는 더 이상 요청을 차단하지 않는다 (실제 차단은 WAS 책임) — mode가 "detection"이면
    # 항상 False. mode가 "prevention"이면 시연용으로 True가 채워지지만, 이 값 자체가
    # 실제 요청을 막지는 않는다 (분석 서버의 waf.blocked 필드용 표시값).
    blocked: bool = Field(default_factory=lambda: settings.waf_mode == "prevention")
    target_name: Optional[str] = None
    # Juice Shop의 nginx-was-logger 사이드카가 응답에 실어주는 X-Served-By-Pod/
    # X-Served-By-Namespace 헤더를 그대로 옮겨 담은 값(app/proxy/proxy.py 참고) -
    # 정적으로 하드코딩하지 않고 "이 요청을 실제로 처리한 pod"를 매번 정확히 가리킨다.
    # prevention 모드로 차단된 요청은 Juice Shop까지 안 가서 응답 자체가 없으므로
    # None으로 남는다.
    target_namespace: Optional[str] = None
    target_pod_name: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.LOW
    # 분석 서버의 waf.mode 필드로 그대로 매핑됨. 기본은 탐지 전용("detection")이고,
    # 시연 때만 .env의 WAF_MODE=prevention으로 바꿔서 로그에 "차단한 것처럼" 표시한다.
    mode: Literal["detection", "prevention"] = Field(default_factory=lambda: settings.waf_mode)