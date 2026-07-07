"""
담당: 서동영 (대시보드) / 이용욱 (연동)

관리자의 쓰기 작업(생성/수정/삭제)을 AuditLog 테이블에 기록하는 공용 헬퍼.
Rules API, Target API, AllowList API 등에서 쓰기 작업 성공 직후에 호출한다.
"""
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.rdbms_models import AuditLog


def log_action(
    db: Session,
    *,
    user_id: Optional[UUID],
    action: str,
    target_table: str,
    detail: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> None:
    """호출부에서 db.commit()을 이미 했든 안 했든 상관없이, 이 함수 자체가 commit까지 책임진다."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        target_table=target_table,
        detail=detail,
        ip_address=ip_address,
    )
    db.add(entry)
    db.commit()