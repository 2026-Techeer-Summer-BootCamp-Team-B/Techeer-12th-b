"""
담당: 이용욱 (게이트웨이)

Rate Limiting / Brute Force 탐지 결과로 자동 등록되거나,
관리자가 수동으로 추가하는 IP 블랙리스트를 관리한다.
blacklist.json 파일 하나에 { ip: entry } 형태로 통째로 저장하는 단순한 구조.
"""
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from app.config import settings
from app.models.schemas import IPBlacklistEntry


def _load() -> Dict[str, dict]:
    if not os.path.exists(settings.blacklist_path):
        return {}
    with open(settings.blacklist_path, "r", encoding="utf-8") as f:
        content = f.read().strip()
        return json.loads(content) if content else {}


def _save(data: Dict[str, dict]) -> None:
    blacklist_dir = os.path.dirname(settings.blacklist_path)
    if blacklist_dir and not os.path.exists(blacklist_dir):
        os.makedirs(blacklist_dir, exist_ok=True)
    with open(settings.blacklist_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)


def is_blocked(ip: str) -> bool:
    """
    게이트웨이 미들웨어(app/middleware/gateway.py)가 요청마다 이걸 호출해서
    차단 여부를 즉시 확인한다. 만료 시간이 지난 항목은 자동으로 무시.
    """
    data = _load()
    entry = data.get(ip)
    if not entry:
        return False
    expires_at = entry.get("expires_at")
    if expires_at and datetime.fromisoformat(expires_at) < datetime.utcnow():
        return False  # 만료됨 — 아직 목록에서 지우진 않고 통과만 시켜줌
    return True


def add_or_update(entry: IPBlacklistEntry) -> None:
    """자동 차단(Rate Limit 초과 등)과 수동 차단(관리자) 둘 다 이 함수를 통해 등록."""
    data = _load()
    existing = data.get(entry.ip)
    if existing:
        existing["hit_count"] = existing.get("hit_count", 0) + 1
        data[entry.ip] = existing
    else:
        data[entry.ip] = entry.model_dump()
    _save(data)


def remove(ip: str) -> bool:
    data = _load()
    if ip in data:
        del data[ip]
        _save(data)
        return True
    return False


def list_all() -> List[dict]:
    data = _load()
    return list(data.values())