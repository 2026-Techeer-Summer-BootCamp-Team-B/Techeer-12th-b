"""
담당: 이용욱 (게이트웨이)
Rate Limiting / Brute Force 탐지 결과로 자동 등록되거나,
관리자가 수동으로 추가하는 IP 블랙리스트를 조회/관리하는 API.
실제 저장 로직은 app/storage/blacklist_store.py에 있다.

수정: 윤재영 (WAF 로직 복구)
LEGACY / 보류 — (차단 로직 복구 W2-4와 세트로 재검토).
main.py에 등록돼 있지 않아 지금은 호출되지 않는다. app/storage/blacklist_store.py와
app/models/schemas.py의 IPBlacklistEntry가 아직 없어서 이 파일은 import 시점에
깨진다 — W2-4 착수 시 두 모듈을 함께 설계할 것.
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
