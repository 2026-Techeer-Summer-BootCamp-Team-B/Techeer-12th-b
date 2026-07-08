"""
실시간 침입 탐지 플랫폼 — FastAPI 진입점

실행 방법:
    uvicorn main:app --reload
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import allowlist, audit_logs, auth, blacklist, logs, rules, stats, targets, ws, alerts
from app.config import settings
from app.middleware.gateway import GatewayMiddleware
from app.proxy.proxy import router as proxy_router
from app.storage.es_client import ensure_index_exists

app = FastAPI(
    title="실시간 침입 탐지 플랫폼",
    description="동적 웹 요청 중 비정상 트래픽을 실시간으로 탐지·차단하고 SIEM 대시보드로 시각화",
    version="0.1.0",
)

@app.on_event("startup")
def on_startup():
    ensure_index_exists()

# 💡 [코드 해결 - 중요] 
# FastAPI의 미들웨어는 나중에 추가된 것(아래에 있는 것)이 가장 먼저 실행됩니다.
# 따라서 모든 보안/비정상 트래픽을 필터링하는 GatewayMiddleware를 먼저 적재하고,
# 표준 브라우저 교차 출처를 처리하는 CORSMiddleware를 가장 아래에 적재해야 합니다.
# 이렇게 해야 브라우저 preflight 및 웹소켓 핸드셰이크 시 CORS 헤더가 유실되지 않습니다.

# 1. 먼저 게이트웨이 미들웨어를 장착합니다. (나중에 실행됨)
app.add_middleware(GatewayMiddleware)

# 2. CORS 미들웨어를 가장 마지막에 장착합니다. (가장 먼저 실행되어 모든 요청에 CORS 헤더 보장)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True, # 💡 웹소켓 및 인증 정보 통신을 위해 True로 확보하는 것이 안정적입니다.
    allow_methods=["*"],
    allow_headers=["*"],
)

# 라우터 등록
app.include_router(proxy_router, prefix="/proxy")
app.include_router(auth.router)
app.include_router(logs.router)
app.include_router(stats.router)
app.include_router(blacklist.router)
app.include_router(rules.router)
app.include_router(targets.router)
app.include_router(allowlist.router)
app.include_router(audit_logs.router)
app.include_router(ws.router)
app.include_router(alerts.router, prefix="/api/alerts")


@app.get("/health")
def health_check():
    """서버가 살아있는지 확인용. 배포/모니터링 시스템에서 주기적으로 호출."""
    return {"status": "ok"}