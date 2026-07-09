"""
노션 ERD 초안(AttackLog / IPBlacklist)을 그대로 코드로 옮긴 파일.
API 요청/응답과 저장 형식 모두 여기 정의된 모델을 기준으로 맞춘다.

DetectionRule(정규식을 DB로 관리)은 Postgres 제거와 함께 삭제됨 - 실제로도 탐지 엔진은
signatures.py에 하드코딩된 SIGNATURES만 참조하고 있어 연결된 적이 없었다.
"""
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


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


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    CRITICAL = "CRITICAL"


class AttackLog(BaseModel):
    """
    담당: 심다움 (로그 마스터)
    탐지 엔진(윤재영: 서버·DB / 심다움: 클라이언트)이 공격을 잡아내면
    이 형태로 만들어서 log_store에 저장한다.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: str
    attack_type: AttackType
    target_endpoint: str
    http_method: str
    # 페이로드 전체가 아니라 일부만 저장 (로그 자체가 공격 벡터가 되는 것 방지)
    payload_snippet: str = Field(max_length=200)
    user_agent: Optional[str] = None
    matched_rule_id: Optional[str] = None
    blocked: bool = True
    target_name: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.LOW


class IPBlacklistEntry(BaseModel):
    """담당: 이용욱 (게이트웨이) — Rate Limiting/Brute Force 결과로 자동 등록됨"""
    ip: str
    reason: str
    hit_count: int = 1
    blocked_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    is_manual: bool = False