"""
담당: 이용욱 (게이트웨이)

Target(PostgreSQL) CRUD API. 쓰기 작업은 AuditLog에 자동 기록된다.
"""
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, require_admin
from app.models.rdbms_models import Target
from app.services.audit_logger import log_action

router = APIRouter(prefix="/api/targets", tags=["targets"])


class TargetCreate(BaseModel):
    name: str
    base_url: HttpUrl


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    base_url: Optional[HttpUrl] = None
    is_active: Optional[bool] = None


class TargetResponse(BaseModel):
    id: str
    name: str
    base_url: str
    is_active: bool

    @classmethod
    def from_orm_target(cls, t: Target) -> "TargetResponse":
        return cls(id=str(t.id), name=t.name, base_url=t.base_url, is_active=t.is_active)


class TargetListResponse(BaseModel):
    items: List[TargetResponse]
    total: int


@router.get("", response_model=TargetListResponse)
def list_targets(
    is_active: Optional[bool] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = db.query(Target)
    if is_active is not None:
        query = query.filter(Target.is_active == is_active)
    total = query.count()
    targets = query.offset((page - 1) * page_size).limit(page_size).all()
    return TargetListResponse(items=[TargetResponse.from_orm_target(t) for t in targets], total=total)


@router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(
    payload: TargetCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    target = Target(name=payload.name, base_url=str(payload.base_url))
    db.add(target)
    db.commit()
    db.refresh(target)

    log_action(
        db,
        user_id=current_user["user_id"],
        action="TARGET_CREATED",
        target_table="targets",
        detail=f"name={target.name}",
        ip_address=request.client.host if request.client else None,
    )
    return TargetResponse.from_orm_target(target)


@router.put("/{target_id}", response_model=TargetResponse)
def update_target(
    target_id: uuid.UUID,
    payload: TargetUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    target = db.query(Target).filter(Target.id == target_id).first()
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(target, field, str(value) if field == "base_url" else value)

    db.commit()
    db.refresh(target)

    log_action(
        db,
        user_id=current_user["user_id"],
        action="TARGET_UPDATED",
        target_table="targets",
        detail=f"name={target.name}, fields={list(update_data.keys())}",
        ip_address=request.client.host if request.client else None,
    )
    return TargetResponse.from_orm_target(target)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    target_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    target = db.query(Target).filter(Target.id == target_id).first()
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    target_name = target.name
    db.delete(target)
    db.commit()

    log_action(
        db,
        user_id=current_user["user_id"],
        action="TARGET_DELETED",
        target_table="targets",
        detail=f"name={target_name}",
        ip_address=request.client.host if request.client else None,
    )
    return None