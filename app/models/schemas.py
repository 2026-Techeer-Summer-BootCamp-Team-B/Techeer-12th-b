"""
노션 ERD 초안(AttackLog / IPBlacklist / DetectionRule)을 그대로 코드로 옮긴 파일.
API 요청/응답과 저장 형식 모두 여기 정의된 모델을 기준으로 맞춘다.
"""
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class AttackType(str, Enum):
    """공격 유형. 새 탐지 로직을 추가하면 여기에도 반드시 추가할 것."""
    SQLI = "sqli"
    XSS = "xss"
    JWT_FORGERY = "jwt_forgery"
    OS_COMMAND_INJECTION = "os_command_injection"
    PATH_TRAVERSAL = "path_traversal"
    FILE_UPLOAD = "file_upload"
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
    risk_level: RiskLevel = RiskLevel.LOW


class IPBlacklistEntry(BaseModel):
    """담당: 이용욱 (게이트웨이) — Rate Limiting/Brute Force 결과로 자동 등록됨"""
    ip: str
    reason: str
    hit_count: int = 1
    blocked_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    is_manual: bool = False


class DetectionRule(BaseModel):
    """
    담당: 윤재영 (서버·DB 룰) / 심다움 (클라이언트 룰)
    정규식을 코드에 하드코딩하지 않고 데이터로 관리해서
    코드 수정 없이 룰만 추가/비활성화할 수 있게 함.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    attack_type: AttackType
    pattern: str  # 정규표현식 패턴
    severity: RiskLevel = RiskLevel.MEDIUM
    enabled: bool = True
    created_by: Optional[str] = None