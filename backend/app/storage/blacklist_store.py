"""
담당: 이용욱 (게이트웨이)

Rate Limiting/Brute Force(IP 기준)에 걸린 IP를 등록해두는 저장소.
기존에는 JSON 파일(./data/blacklist.json)로 저장했지만, 이제 Redis로 전환했다.

왜 Redis로 바꿨나:
- pod가 재시작되면 JSON 파일은 사라지는데(emptyDir 등), 이제 Redis가 별도 pod로 떠 있어서
  security-proxy가 재시작돼도 차단 목록이 유지된다.
- TTL(자동 만료)을 Redis 네이티브 기능으로 처리할 수 있어서, 우리가 직접 만료 시각을
  계산하고 비교하는 로직이 필요 없어졌다 (EXPIRE 하나면 끝).

함수 시그니처(is_blocked, add_or_update, remove, list_blocked)는 이전 버전과 동일하게 유지했다.
그래서 이 파일을 호출하는 gateway.py, proxy.py는 전혀 수정할 필요가 없다.
"""
from datetime import datetime
from typing import List

from app.models.schemas import IPBlacklistEntry
from app.storage.redis_client import redis_client

_KEY_PREFIX = "blacklist:"


def _key(ip: str) -> str:
    return f"{_KEY_PREFIX}{ip}"


def is_blocked(ip: str) -> bool:
    """게이트웨이가 요청마다 호출. Redis 키가 존재하면 차단 상태 (TTL 지나면 Redis가 알아서 삭제)."""
    return redis_client.exists(_key(ip)) == 1


def add_or_update(entry: IPBlacklistEntry) -> None:
    """이미 등록된 IP면 hit_count를 올리고, 처음이면 새로 등록."""
    key = _key(entry.ip)

    if redis_client.exists(key):
        redis_client.hincrby(key, "hit_count", 1)
        redis_client.hset(key, "reason", entry.reason)
    else:
        mapping = {
            "ip": entry.ip,
            "reason": entry.reason,
            "hit_count": entry.hit_count,
            "blocked_at": entry.blocked_at.isoformat(),
            "is_manual": str(entry.is_manual),
        }
        redis_client.hset(key, mapping=mapping)

    # expires_at이 있으면 그 시각까지 남은 초를 계산해서 TTL로 설정 (없으면 영구 차단, TTL 없음)
    if entry.expires_at is not None:
        ttl_seconds = int((entry.expires_at - datetime.utcnow()).total_seconds())
        if ttl_seconds > 0:
            redis_client.expire(key, ttl_seconds)


def remove(ip: str) -> bool:
    """수동으로 특정 IP를 블랙리스트에서 제거 (관리 API용)."""
    deleted_count = redis_client.delete(_key(ip))
    return deleted_count > 0


def list_blocked() -> List[dict]:
    """현재 차단된 모든 IP 목록 조회. Redis SCAN으로 blacklist:* 키를 순회."""
    result = []
    for key in redis_client.scan_iter(match=f"{_KEY_PREFIX}*"):
        entry = redis_client.hgetall(key)
        if entry:
            ttl = redis_client.ttl(key)
            entry["ttl_seconds"] = ttl if ttl > 0 else None
            result.append(entry)
    return result