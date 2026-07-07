"""
담당: 하지환/윤재영 (각자 담당 공격 유형의 룰 등록) / 이용욱 (API 뼈대)

DetectionRule(PostgreSQL) CRUD API. 정규식 패턴을 코드가 아니라 데이터로
관리해서, 새 시그니처를 추가할 때 코드 배포 없이 이 API로 등록할 수 있게 한다.

쓰기 작업(생성/수정/삭제)은 AuditLog에 자동 기록된다.
"""
import re
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, require_admin
from app.models.rdbms_models import DetectionRule
from app.models.schemas import AttackType, RiskLevel
from app.services.audit_logger import log_action

router = APIRouter(prefix="/api/rules", tags=["rules"])


class RuleCreate(BaseModel):
    name: str
    attack_type: AttackType
    pattern: str
    severity: RiskLevel = RiskLevel.MEDIUM
    mitre_technique_id: Optional[str] = None

    @field_validator("pattern")
    @classmethod
    def validate_regex(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"정규식 패턴 오류: {e}")
        return v


class RuleUpdate(BaseModel):
    pattern: Optional[str] = None
    severity: Optional[RiskLevel] = None
    enabled: Optional[bool] = None

    @field_validator("pattern")
    @classmethod
    def validate_regex(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"정규식 패턴 오류: {e}")
        return v


class RuleResponse(BaseModel):
    id: str
    name: str
    attack_type: AttackType
    pattern: str
    severity: RiskLevel
    enabled: bool
    created_by: Optional[str] = None
    mitre_technique_id: Optional[str] = None

    @classmethod
    def from_orm_rule(cls, rule: DetectionRule) -> "RuleResponse":
        return cls(
            id=str(rule.id),
            name=rule.name,
            attack_type=rule.attack_type,
            pattern=rule.pattern,
            severity=rule.severity,
            enabled=rule.enabled,
            created_by=str(rule.created_by) if rule.created_by else None,
            mitre_technique_id=rule.mitre_technique_id,
        )


class RuleListResponse(BaseModel):
    items: List[RuleResponse]
    total: int


@router.get("", response_model=RuleListResponse)
def list_rules(
    attack_type: Optional[AttackType] = None,
    enabled: Optional[bool] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = db.query(DetectionRule)
    if attack_type is not None:
        query = query.filter(DetectionRule.attack_type == attack_type)
    if enabled is not None:
        query = query.filter(DetectionRule.enabled == enabled)

    total = query.count()
    rules = query.offset((page - 1) * page_size).limit(page_size).all()
    return RuleListResponse(items=[RuleResponse.from_orm_rule(r) for r in rules], total=total)


@router.get("/{rule_id}", response_model=RuleResponse)
def get_rule(
    rule_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return RuleResponse.from_orm_rule(rule)


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
def create_rule(
    payload: RuleCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    existing = db.query(DetectionRule).filter(DetectionRule.name == payload.name).first()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="이미 존재하는 룰 이름")

    rule = DetectionRule(
        name=payload.name,
        attack_type=payload.attack_type,
        pattern=payload.pattern,
        severity=payload.severity,
        mitre_technique_id=payload.mitre_technique_id,
        created_by=current_user["user_id"],
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    log_action(
        db,
        user_id=current_user["user_id"],
        action="RULE_CREATED",
        target_table="detection_rules",
        detail=f"name={rule.name}",
        ip_address=request.client.host if request.client else None,
    )
    return RuleResponse.from_orm_rule(rule)


@router.put("/{rule_id}", response_model=RuleResponse)
def update_rule(
    rule_id: uuid.UUID,
    payload: RuleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(rule, field, value)

    db.commit()
    db.refresh(rule)

    log_action(
        db,
        user_id=current_user["user_id"],
        action="RULE_UPDATED",
        target_table="detection_rules",
        detail=f"name={rule.name}, fields={list(update_data.keys())}",
        ip_address=request.client.host if request.client else None,
    )
    return RuleResponse.from_orm_rule(rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    rule_name = rule.name
    db.delete(rule)
    db.commit()

    log_action(
        db,
        user_id=current_user["user_id"],
        action="RULE_DELETED",
        target_table="detection_rules",
        detail=f"name={rule_name}",
        ip_address=request.client.host if request.client else None,
    )
    return None