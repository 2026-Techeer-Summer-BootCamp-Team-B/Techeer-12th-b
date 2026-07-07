"""
실시간 침입 탐지 플랫폼 — FastAPI 진입점

실행 방법:
    uvicorn main:app --reload

구조:
    클라이언트 요청
        -> GatewayMiddleware (이용욱: 블랙리스트/Rate Limit/Bad Bot/에러마스킹)
        -> /proxy/{path} (이용욱: 디코더+탐지엔진 거쳐서 실제 서비스로 전달)
        -> /api/logs, /api/stats, /api/blacklist, /api/rules (조회/관리 API)
        -> /ws/alerts (대시보드 실시간 알림)
"""
import sys

# Windows 콘솔의 기본 코드페이지(cp949 등)는 로그 곳곳에 쓰인 이모지(✅🚨❌ 등)를 인코딩하지 못해
# print() 호출 자체가 UnicodeEncodeError로 죽는다. 예를 들어 app/api/ws.py는 인증 성공 직후
# print에서 죽어서 WebSocket이 열리자마자 서버 쪽 예외로 끊기는 문제가 있었다.
# stdout/stderr를 UTF-8로 강제해서 어떤 콘솔 코드페이지에서도 안전하게 만든다.
if sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

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
# 대시보드(프론트엔드)가 다른 포트/도메인에서 API를 호출할 수 있도록 허용.
#
# allow_origins는 반드시 화이트리스트(settings.allowed_origins, .env에서 설정)로 관리한다.
# "*"(전체 허용)로 두면, 인증정보를 쓰는 API가 생겼을 때 아무 외부 사이트에서나
# 우리 API를 대신 호출해서 사용자 데이터를 읽어갈 수 있는 CORS Misconfiguration 취약점이 된다.
# (자세한 시나리오는 app/middleware/gateway.py의 check_cors_violation 주석 참고)
#
# 참고: 여기 CORSMiddleware는 "정상적인 브라우저 preflight 요청"을 처리해주는 표준 기능이고,
# 화이트리스트에 없는 Origin이 악의적으로 계속 시도하는 것을 "탐지해서 로그로 남기는" 건
# GatewayMiddleware의 check_cors_violation()이 담당한다 — 둘이 하는 일이 달라서 같이 필요하다.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 게이트웨이 미들웨어 등록 (모든 요청이 가장 먼저 여기를 통과)
app.add_middleware(GatewayMiddleware)

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