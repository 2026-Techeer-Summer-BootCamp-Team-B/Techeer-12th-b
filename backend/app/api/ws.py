"""
담당: 서동영 (대시보드)

/ws/alerts - 대시보드가 이 엔드포인트에 WebSocket으로 접속해두면,
공격이 탐지될 때마다(app/proxy/proxy.py에서 호출) 실시간으로 이벤트를 받는다.

인증: 연결 시 쿼리 파라미터로 세션 토큰을 넘겨야 한다.
예: ws://<host>:8000/ws/alerts?token=<session_token>
(WebSocket은 커스텀 헤더를 브라우저에서 자유롭게 못 붙이는 경우가 많아 쿼리 파라미터 방식을 사용)
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from app.storage.session_store import get_session
from app.websocket.manager import manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket, token: str = ""):
    session = get_session(token) if token else None
    if session is None:
        # 인증 실패 - 연결을 받아들이지 않고 바로 종료
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket)
    try:
        while True:
            # 클라이언트가 뭘 보내든 딱히 처리할 건 없지만,
            # 연결이 끊겼는지 감지하기 위해 계속 받아만 둔다.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)