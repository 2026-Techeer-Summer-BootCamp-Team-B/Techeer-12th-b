"""
담당: 이용욱 (게이트웨이)

Redis 연결을 앱 전체에서 하나만 만들어서 재사용하기 위한 모듈.
IPBanList, SessionStore 둘 다 이 클라이언트를 통해 접근한다.
"""
import redis

from app.config import settings

# decode_responses=True로 설정해서, get() 결과가 bytes가 아니라 str로 바로 나오게 함
redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
