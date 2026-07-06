"""
담당: 이용욱 (게이트웨이)

계정 기준 잠금(IP 로테이션 대응) 저장소. JSON 파일 대신 Redis로 전환.
잠금 지속시간(duration_seconds)을 Redis TTL로 그대로 매핑해서,
"잠금이 풀렸는지" 계산 로직 없이 키 존재 여부만 보면 된다.

함수 시그니처(is_locked, lock_account, list_locked)는 이전 버전과 동일하게 유지.
"""
from typing import List

from app.storage.redis_client import redis_client

_KEY_PREFIX = "lockout:"


def _key(identifier: str) -> str:
    return f"{_KEY_PREFIX}{identifier.lower()}"


def is_locked(identifier: str) -> bool:
    """게이트웨이가 요청마다 호출해서, 이 계정이 지금 잠겨 있는지 확인."""
    return redis_client.exists(_key(identifier)) == 1


def lock_account(identifier: str, duration_seconds: int, reason: str = "brute_force_login") -> None:
    """지정된 시간(duration_seconds) 동안 해당 계정으로의 로그인 시도를 게이트웨이에서 차단."""
    key = _key(identifier)
    redis_client.hset(key, mapping={"identifier": identifier.lower(), "reason": reason})
    redis_client.expire(key, duration_seconds)


def list_locked() -> List[dict]:
    result = []
    for key in redis_client.scan_iter(match=f"{_KEY_PREFIX}*"):
        entry = redis_client.hgetall(key)
        if entry:
            ttl = redis_client.ttl(key)
            entry["ttl_seconds"] = ttl if ttl > 0 else None
            result.append(entry)
    return result