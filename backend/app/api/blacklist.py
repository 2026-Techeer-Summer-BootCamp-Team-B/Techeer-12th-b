"""
담당: 이용욱 (게이트웨이)

Rate Limiting / Brute Force 탐지 결과로 자동 등록되거나,
관리자가 수동으로 추가하는 IP 블랙리스트를 조회/관리하는 API.
실제 저장 로직은 app/storage/blacklist_store.py에 있다.
"""
from fastapi import APIRouter, HTTPException

from app.models.schemas import IPBlacklistEntry
from app.storage import blacklist_store

router = APIRouter(prefix="/api/blacklist", tags=["blacklist"])


@router.get("")
def list_blacklist():
    return blacklist_store.list_blocked()


@router.post("")
def create_blacklist_entry(entry: IPBlacklistEntry):
    blacklist_store.add_or_update(entry)
    return {"detail": "created", "ip": entry.ip}


@router.delete("/{ip}")
def delete_blacklist_entry(ip: str):
    removed = blacklist_store.remove(ip)
    if not removed:
        raise HTTPException(status_code=404, detail="IP not found in blacklist")
    return {"detail": "removed", "ip": ip}
