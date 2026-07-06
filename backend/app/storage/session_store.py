"""
담당: 이용욱 (게이트웨이)

관리자 로그인 세션을 Redis에 저장. JWT 대신 랜덤 토큰 방식을 쓰는 이유:
로그아웃 시 Redis 키 하나만 지우면 즉시 무효화되고, 토큰 자체에 정보를 담지 않아서
탈취당해도 서버에서 강제로 무효화할 수 있다 (JWT는 만료 전까지 서버가 막을 방법이 마땅치 않음).
"""
import secrets
from typing import Optional
from uuid import UUID

from app.storage.redis_client import redis_client

_KEY_PREFIX = "session:"
_DEFAULT_TTL_SECONDS = 3600 * 8  # 8시간


def _key(token: str) -> str:
    return f"{_KEY_PREFIX}{token}"


def create_session(user_id: UUID, role: str, ttl_seconds: int = _DEFAULT_TTL_SECONDS) -> str:
    """새 세션 토큰을 발급하고 Redis에 저장. 발급된 토큰 문자열을 반환."""
    token = secrets.token_urlsafe(32)
    key = _key(token)
    redis_client.hset(key, mapping={"user_id": str(user_id), "role": role})
    redis_client.expire(key, ttl_seconds)
    return token


def get_session(token: str) -> Optional[dict]:
    """토큰으로 세션 정보(user_id, role) 조회. 없거나 만료됐으면 None."""
    data = redis_client.hgetall(_key(token))
    return data if data else None


def delete_session(token: str) -> None:
    """로그아웃 - 세션 즉시 무효화."""
    redis_client.delete(_key(token))
