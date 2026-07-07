"""
담당: 서동영 (대시보드)

AuditLog 조회 API. 쓰기 기능은 없음 (다른 API들이 log_action()으로 자동 기록).
admin 권한만 조회 가능 - 감사 로그 자체가 민감한 정보라 일반 viewer에게는 안 보여줌.
"""
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models.rdbms_models import AuditLog

router = APIRouter(prefix="/api/audit-logs", tags=["audit-logs"])


class AuditLogResponse(BaseModel):
    id: str
    user_id: Optional[str] = None
    action: str
    target_table: str
    detail: Optional[str] = None
    ip_address: Optional[str] = None
    created_at: datetime

    @classmethod
    def from_orm_entry(cls, e: AuditLog) -> "AuditLogResponse":
        return cls(
            id=str(e.id),
            user_id=str(e.user_id) if e.user_id else None,
            action=e.action,
            target_table=e.target_table,
            detail=e.detail,
            ip_address=e.ip_address,
            created_at=e.created_at,
        )


class AuditLogListResponse(BaseModel):
    items: List[AuditLogResponse]
    total: int


@router.get("", response_model=AuditLogListResponse)
def list_audit_logs(
    user_id: Optional[UUID] = None,
    action: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    query = db.query(AuditLog)
    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)
    if action is not None:
        query = query.filter(AuditLog.action == action)
    if start_date is not None:
        query = query.filter(AuditLog.created_at >= start_date)
    if end_date is not None:
        query = query.filter(AuditLog.created_at <= end_date)

    total = query.count()
    entries = (
        query.order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return AuditLogListResponse(items=[AuditLogResponse.from_orm_entry(e) for e in entries], total=total)