"""
담당: 이용욱 (게이트웨이)

AllowList(PostgreSQL) CRUD API. 쓰기 작업은 AuditLog에 자동 기록된다.
"""
import ipaddress
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, require_admin
from app.models.rdbms_models import AllowList
from app.services.audit_logger import log_action

router = APIRouter(prefix="/api/allowlist", tags=["allowlist"])


class AllowListCreate(BaseModel):
    ip_or_cidr: str
    target_id: Optional[uuid.UUID] = None
    reason: Optional[str] = None
    expires_at: Optional[datetime] = None

    @field_validator("ip_or_cidr")
    @classmethod
    def validate_ip_or_cidr(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError("올바른 IP 또는 CIDR 형식이 아님 (예: 192.168.0.1 또는 192.168.0.0/24)")
        return v


class AllowListResponse(BaseModel):
    id: str
    ip_or_cidr: str
    target_id: Optional[str] = None
    reason: Optional[str] = None
    expires_at: Optional[datetime] = None

    @classmethod
    def from_orm_entry(cls, e: AllowList) -> "AllowListResponse":
        return cls(
            id=str(e.id),
            ip_or_cidr=e.ip_or_cidr,
            target_id=str(e.target_id) if e.target_id else None,
            reason=e.reason,
            expires_at=e.expires_at,
        )


class AllowListListResponse(BaseModel):
    items: List[AllowListResponse]
    total: int


@router.get("", response_model=AllowListListResponse)
def list_allowlist(
    target_id: Optional[uuid.UUID] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = db.query(AllowList)
    if target_id is not None:
        query = query.filter(AllowList.target_id == target_id)
    total = query.count()
    entries = query.offset((page - 1) * page_size).limit(page_size).all()
    return AllowListListResponse(items=[AllowListResponse.from_orm_entry(e) for e in entries], total=total)


@router.post("", response_model=AllowListResponse, status_code=status.HTTP_201_CREATED)
def create_allowlist_entry(
    payload: AllowListCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    entry = AllowList(
        ip_or_cidr=payload.ip_or_cidr,
        target_id=payload.target_id,
        reason=payload.reason,
        expires_at=payload.expires_at,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    log_action(
        db,
        user_id=current_user["user_id"],
        action="ALLOWLIST_CREATED",
        target_table="allow_list",
        detail=f"ip_or_cidr={entry.ip_or_cidr}",
        ip_address=request.client.host if request.client else None,
    )
    return AllowListResponse.from_orm_entry(entry)


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_allowlist_entry(
    entry_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    entry = db.query(AllowList).filter(AllowList.id == entry_id).first()
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="항목 없음")

    ip_or_cidr = entry.ip_or_cidr
    db.delete(entry)
    db.commit()

    log_action(
        db,
        user_id=current_user["user_id"],
        action="ALLOWLIST_DELETED",
        target_table="allow_list",
        detail=f"ip_or_cidr={ip_or_cidr}",
        ip_address=request.client.host if request.client else None,
    )
    return None