"""
Target 서버(WAF 게이트웨이) — FastAPI 진입점

실행 방법:
    uvicorn main:app --reload

구조:
    클라이언트 요청
        -> GatewayMiddleware (이용욱: Rate Limit/Bad Bot/Brute Force/CORS 위반 — 탐지 후 로그만 남기고 통과)
        -> /proxy/{path} (이용욱: 디코더+탐지엔진 거쳐서 실제 서비스로 항상 전달)

WAF는 아무것도 차단하지 않는다 — 실제 접근 제어(차단)는 WAS(보호 대상 서비스) 책임이고,
이 앱은 의심스러운 트래픽을 탐지해서 로그로만 남긴다. 그래서 차단 상태를 들고 있던 Redis
(블랙리스트/계정 잠금)도 더 이상 쓰지 않는다.

탐지된 공격 로그는 app/otel/logger.py를 통해 OTel(OTLP)로 otel-collector에 실시간
전송된다. Falco(런타임)/K8s Audit(제어판) 로그도 같은 Collector가 모아서 Central SIEM으로
넘기므로, 이 앱은 대시보드/DB 없이 ① 관문(WAF) 계층의 로그 발생지 역할만 한다.
"""
import asyncio
import sys

# Windows 콘솔의 기본 코드페이지(cp949 등)는 로그 곳곳에 쓰인 이모지(✅🚨❌ 등)를 인코딩하지 못해
# print() 호출 자체가 UnicodeEncodeError로 죽는다. stdout/stderr를 UTF-8로 강제해서
# 어떤 콘솔 코드페이지에서도 안전하게 만든다.
if sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.middleware.gateway import GatewayMiddleware
from app.otel import logger as otel_logger
from app.proxy.proxy import router as proxy_router

app = FastAPI(
    title="Target 서버 - WAF 게이트웨이",
    description="동적 웹 요청 중 비정상 트래픽을 실시간으로 탐지하고, 탐지 로그를 OTel로 중앙 수집 전송 (차단은 하지 않음)",
    version="0.2.0",
)

_otel_retry_task = None


@app.on_event("startup")
async def on_startup():
    global _otel_retry_task
    # otel-collector가 다운돼 있는 동안 실패해서 로컬 fallback 파일에 쌓인
    # AttackLog를 주기적으로 자동 재전송한다 (app/otel/logger.py 참고) - 사람이
    # fallback 파일을 보고 수동으로 재적재하지 않아도 되게 한다.
    _otel_retry_task = asyncio.create_task(otel_logger.retry_fallback_loop())


@app.on_event("shutdown")
async def on_shutdown():
    if _otel_retry_task:
        _otel_retry_task.cancel()
    otel_logger.shutdown()


# 이 서비스를 다른 포트/도메인에서 호출할 수 있도록 허용.
#
# allow_origins는 반드시 화이트리스트(settings.allowed_origins, .env에서 설정)로 관리한다.
# "*"(전체 허용)로 두면, 인증정보를 쓰는 API가 생겼을 때 아무 외부 사이트에서나
# 우리 API를 대신 호출해서 사용자 데이터를 읽어갈 수 있는 CORS Misconfiguration 취약점이 된다.
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


@app.get("/health")
def health_check():
    """서버가 살아있는지 확인용. 배포/모니터링 시스템에서 주기적으로 호출."""
    return {"status": "ok"}
