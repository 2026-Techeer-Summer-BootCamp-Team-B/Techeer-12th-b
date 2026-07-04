"""
담당: 이용욱 (게이트웨이 & 트래픽 컨트롤러)

시스템의 입구를 담당하는 미들웨어.
1) 블랙리스트 IP 즉시 차단
2) Rate Limiting (짧은 시간에 너무 많은 요청 차단)
3) Bad Bot 차단 (알려진 해킹 툴 User-Agent 차단)
4) 에러 마스킹 (서버 내부 에러 메시지가 그대로 노출되지 않도록)

FastAPI의 미들웨어 체인에서 가장 먼저 실행되어,
여기서 걸러지지 않은 요청만 디코더(app/middleware/decoder.py)와
탐지 엔진(app/detection/engine.py)으로 넘어간다.
"""
import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.storage import blacklist_store

# 알려진 해킹 툴 / 스캐너의 User-Agent 키워드 (필요시 계속 추가)
BAD_BOT_USER_AGENTS = ["sqlmap", "nikto", "nmap", "masscan", "acunetix", "curl/7.0"]

# IP별 최근 요청 시각을 저장하는 메모리 저장소
# 실제 운영에서는 여러 서버 인스턴스가 있을 수 있으므로 Redis 등으로 교체 권장
_request_history: Dict[str, Deque[float]] = defaultdict(deque)


def _is_rate_limited(ip: str) -> bool:
    """최근 rate_limit_window_seconds 안에 rate_limit_max_requests 넘게 요청했는지 확인."""
    now = time.time()
    history = _request_history[ip]

    # 윈도우 밖으로 벗어난 오래된 기록은 제거
    while history and now - history[0] > settings.rate_limit_window_seconds:
        history.popleft()

    history.append(now)
    return len(history) > settings.rate_limit_max_requests


def _is_bad_bot(user_agent: str) -> bool:
    ua_lower = (user_agent or "").lower()
    return any(bad_ua in ua_lower for bad_ua in BAD_BOT_USER_AGENTS)


class GatewayMiddleware(BaseHTTPMiddleware):
    """main.py에서 app.add_middleware(GatewayMiddleware) 형태로 등록해서 사용."""

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")

        # 1) 블랙리스트 확인 — 이미 차단된 IP는 바로 튕겨냄
        if blacklist_store.is_blocked(client_ip):
            return JSONResponse(status_code=403, content={"detail": "Access denied"})

        # 2) Bad Bot 차단
        if _is_bad_bot(user_agent):
            return JSONResponse(status_code=403, content={"detail": "Access denied"})

        # 3) Rate Limiting — 초과 시 블랙리스트에도 자동 등록
        if _is_rate_limited(client_ip):
            from app.models.schemas import IPBlacklistEntry  # 순환 import 방지용 지연 임포트

            blacklist_store.add_or_update(
                IPBlacklistEntry(ip=client_ip, reason="rate_limit_exceeded")
            )
            return JSONResponse(status_code=429, content={"detail": "Too many requests"})

        # 4) 에러 마스킹 — 하위 로직에서 예외가 터져도 상세 스택트레이스를 노출하지 않음
        try:
            response = await call_next(request)
            return response
        except Exception:
            # 실제 에러는 서버 로그에만 남기고(print는 예시일 뿐, 실제로는 logging 모듈 사용 권장)
            print(f"[Gateway] Unhandled error while processing request from {client_ip}")
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"},  # 상세 내용 숨김
            )