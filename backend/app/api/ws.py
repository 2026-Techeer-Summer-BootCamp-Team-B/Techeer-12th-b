"""
담당: 서동영 (대시보드)

/ws/alerts - 대시보드가 이 엔드포인트에 WebSocket으로 접속해두면,
공격이 탐지될 때마다(app/proxy/proxy.py에서 호출) 실시간으로 이벤트를 받는다.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.storage.session_store import get_session
from app.websocket.manager import manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket, token: str = ""):
    # 💡 [조치] manager.connect() 안에서 어차피 websocket.accept()를 수행하므로 
    # 여기서는 따로 accept()를 호출하지 않고, 토큰 유효성 검사 후 바로 매니저에게 위임합니다.
    
    session = get_session(token) if token else None
    if session is None:
        print(f"⚠️ [WebSocket 인증 실패] 유효하지 않거나 만료된 토큰입니다. 토큰: {token}")
        
        # 아직 accept()가 안 된 상태이므로, close()를 호출하기 전에 accept()를 살짝 해주고 닫는 것이
        # 브라우저 단의 'before the connection is established' 에러를 막는 표준 규격입니다.
        # 💡 4001은 프론트(useWebSocket.js)가 "인증 실패 → 재연결 시도 안 함"으로 처리하는 코드입니다.
        # 표준 1008(정책 위반)을 쓰면 프론트가 일반 연결 끊김으로 오인해 계속 재시도하게 됩니다.
        await websocket.accept()
        await websocket.close(code=4001)
        return

    # 💡 manager.connect 내부에서 await websocket.accept()가 안전하게 실행됩니다.
    await manager.connect(websocket)
    print(f"✅ [WebSocket 인증 성공] 관리자 세션 실시간 관제 연결 완료 (ID: {session.get('username', 'Unknown')})")

    try:
        while True:
            # 연결 상태 유지 및 단선 감지를 위한 루프
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        print("ℹ️ [WebSocket] 관리자가 대시보드를 이탈하여 연결이 해제되었습니다.")