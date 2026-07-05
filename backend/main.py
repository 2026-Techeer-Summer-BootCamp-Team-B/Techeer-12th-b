"""
담당: 이용욱 — FastAPI 앱 엔트리포인트.

게이트웨이 미들웨어를 등록하고, 구현이 끝난 API 라우터만 연결한다.
app/proxy/proxy.py는 아직 뼈대만 있으므로 구현이 끝나는 대로 연결할 것.
(app/api/blacklist.py는 API 라우터가 아니라 블랙리스트 저장소 모듈)
"""
from fastapi import FastAPI

from app.api import logs, rules, stats, ws
from app.middleware.gateway import GatewayMiddleware

app = FastAPI(title="Security Blue")

app.add_middleware(GatewayMiddleware)

app.include_router(logs.router)
app.include_router(rules.router)
app.include_router(stats.router)
app.include_router(ws.router)


@app.get("/health")
def health_check():
    return {"status": "ok"}
