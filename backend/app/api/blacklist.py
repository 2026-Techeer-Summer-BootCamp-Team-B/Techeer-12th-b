"""
담당: 이용욱 (게이트웨이)

Rate Limiting / Brute Force 탐지 결과로 자동 등록되거나,
관리자가 수동으로 추가하는 IP 블랙리스트를 조회/관리하는 API.
실제 저장 로직은 app/storage/blacklist_store.py에 있다.

다른 관리 API(rules.py, targets.py, allowlist.py)와 동일하게 조회는 로그인만,
쓰기(생성/삭제)는 admin 권한을 요구하고 AuditLog에 기록한다.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, require_admin
from app.models.schemas import IPBlacklistEntry
from app.services.audit_logger import log_action
from app.storage import blacklist_store

router = APIRouter(prefix="/api/blacklist", tags=["blacklist"])


@router.get("")
def list_blacklist(current_user: dict = Depends(get_current_user)):
    return blacklist_store.list_blocked()


@router.post("")
def create_blacklist_entry(
    entry: IPBlacklistEntry,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    blacklist_store.add_or_update(entry)
    log_action(
        db,
        user_id=current_user["user_id"],
        action="BLACKLIST_CREATED",
        target_table="blacklist",
        detail=f"ip={entry.ip}, reason={entry.reason}",
        ip_address=request.client.host if request.client else None,
    )
    return {"detail": "created", "ip": entry.ip}


@router.delete("/{ip}")
def delete_blacklist_entry(
    ip: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    removed = blacklist_store.remove(ip)
    if not removed:
        raise HTTPException(status_code=404, detail="IP not found in blacklist")

    log_action(
        db,
        user_id=current_user["user_id"],
        action="BLACKLIST_DELETED",
        target_table="blacklist",
        detail=f"ip={ip}",
        ip_address=request.client.host if request.client else None,
    )
    return {"detail": "removed", "ip": ip}
