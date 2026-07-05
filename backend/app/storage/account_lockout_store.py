"""
담당: 이용욱 (게이트웨이)

IP 기준 블랙리스트(blacklist_store)만으로는 "공격자가 IP를 계속 바꿔가며
같은 계정을 노리는" 브루트포스를 못 막는다 (IP당 실패 횟수가 임계치 밑으로
분산되기 때문). 그래서 "어떤 계정이 공격받고 있는지" 기준으로 별도 잠금을 건다.

blacklist_store와 구조는 비슷하지만 키가 IP가 아니라 계정 식별자(이메일/아이디)라는
점이 다르다. 이 저장소에 잠긴 계정은, 실제 백엔드로 요청을 넘기지도 않고
게이트웨이 단계에서 바로 403을 돌려준다 (불필요한 백엔드 부하도 줄임).
"""
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Optional

_LOCKOUT_PATH = "./data/account_lockout.json"


def _load() -> Dict[str, dict]:
    if not os.path.exists(_LOCKOUT_PATH):
        return {}
    with open(_LOCKOUT_PATH, "r", encoding="utf-8") as f:
        content = f.read().strip()
        return json.loads(content) if content else {}


def _save(data: Dict[str, dict]) -> None:
    lockout_dir = os.path.dirname(_LOCKOUT_PATH)
    if lockout_dir and not os.path.exists(lockout_dir):
        os.makedirs(lockout_dir, exist_ok=True)
    with open(_LOCKOUT_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)


def is_locked(identifier: str) -> bool:
    """게이트웨이가 요청마다 호출해서, 이 계정이 지금 잠겨 있는지 확인."""
    data = _load()
    entry = data.get(identifier.lower())
    if not entry:
        return False
    locked_until = datetime.fromisoformat(entry["locked_until"])
    return datetime.utcnow() < locked_until


def lock_account(identifier: str, duration_seconds: int, reason: str = "brute_force_login") -> None:
    """지정된 시간(duration_seconds) 동안 해당 계정으로의 로그인 시도를 게이트웨이에서 차단."""
    data = _load()
    key = identifier.lower()
    data[key] = {
        "identifier": key,
        "reason": reason,
        "locked_at": datetime.utcnow().isoformat(),
        "locked_until": (datetime.utcnow() + timedelta(seconds=duration_seconds)).isoformat(),
    }
    _save(data)


def list_locked() -> list:
    return list(_load().values())
