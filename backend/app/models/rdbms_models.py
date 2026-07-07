"""
담당: 이용욱 (게이트웨이) / 하지환·윤재영 (DetectionRule)

RDBMS(PostgreSQL)에 저장되는 테이블들. ERD 초안 기준으로 작성.
AttackLog(Elasticsearch), IPBanList/SessionStore(Redis)는 여기 포함되지 않음 -
그 둘은 관계형 조인이 필요 없는 데이터라 별도 저장소를 쓰기 때문.
"""
import uuid
from datetime import datetime

from sqlalchemy import Column, String, Boolean, DateTime, Text, ForeignKey, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.schemas import AttackType, RiskLevel


class User(Base):
    """대시보드에 로그인하는 관리자 계정."""
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="viewer")  # admin / viewer
    created_at = Column(DateTime, default=datetime.utcnow)

    rules = relationship("DetectionRule", back_populates="created_by_user")


class Target(Base):
    """우리 WAF가 지키는 실제 백엔드 서비스 목록."""
    __tablename__ = "targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    base_url = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    allow_list_entries = relationship("AllowList", back_populates="target")


class DetectionRule(Base):
    """정규식 시그니처를 코드가 아니라 데이터로 관리하기 위한 룰 테이블."""
    __tablename__ = "detection_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False, unique=True)
    attack_type = Column(SAEnum(AttackType), nullable=False)
    pattern = Column(Text, nullable=False)
    severity = Column(SAEnum(RiskLevel), nullable=False, default=RiskLevel.MEDIUM)
    enabled = Column(Boolean, default=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    mitre_technique_id = Column(String, nullable=True)

    created_by_user = relationship("User", back_populates="rules")


class AllowList(Base):
    """오탐(False Positive) 방지용 허용 IP/대역 목록."""
    __tablename__ = "allow_list"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip_or_cidr = Column(String, nullable=False)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id"), nullable=True)
    reason = Column(String, nullable=True)
    expires_at = Column(DateTime, nullable=True)

    target = relationship("Target", back_populates="allow_list_entries")


class AuditLog(Base):
    """관리자 행위 감사 로그. Rules/Target/AllowList/Blacklist의 쓰기 API가 호출될 때마다 자동 기록."""
    __tablename__ = "audit_logs"
 
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)  # 예: RULE_CREATED, RULE_DELETED, IP_UNBANNED 등
    target_table = Column(String, nullable=False)  # 어떤 테이블을 건드렸는지
    detail = Column(String, nullable=True)  # 부가 정보 (예: 삭제된 룰 이름)
    ip_address = Column(String, nullable=True)  # 관리자 접속 IP
    created_at = Column(DateTime, default=datetime.utcnow)
