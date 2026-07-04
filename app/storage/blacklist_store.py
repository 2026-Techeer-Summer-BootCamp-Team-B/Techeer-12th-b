"""
담당: 이용욱 (게이트웨이 & 트래픽 컨트롤러)

IPBlacklistEntry 저장소. 초기 뼈대는 인메모리 dict로 구현.
서버 인스턴스가 여러 개로 늘어나면 Redis 등 공유 저장소로 교체 필요.
"""
from typing import Dict, List, Optional

from app.models.schemas import IPBlacklistEntry

_blacklist: Dict[str, IPBlacklistEntry] = {}


def is_blocked(ip: str) -> bool:
    return ip in _blacklist


def add_or_update(entry: IPBlacklistEntry) -> None:
    existing = _blacklist.get(entry.ip)
    if existing:
        existing.hit_count += 1
        existing.reason = entry.reason
    else:
        _blacklist[entry.ip] = entry


def remove(ip: str) -> bool:
    return _blacklist.pop(ip, None) is not None


def list_entries() -> List[IPBlacklistEntry]:
    return list(_blacklist.values())


def get_entry(ip: str) -> Optional[IPBlacklistEntry]:
    return _blacklist.get(ip)
