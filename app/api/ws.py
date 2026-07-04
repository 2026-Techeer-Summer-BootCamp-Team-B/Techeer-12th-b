"""
담당: 서동영 (대시보드) + 심다움 (알림 트리거 - 로그 마스터)

대시보드가 이 WebSocket에 연결해두면, CRITICAL 등급 공격이 탐지될 때마다
서버가 즉시 push 해준다. (노션 API 명세의 WS /ws/alerts 구현체)

구현이 부담스러우면 이 파일은 나중으로 미루고,
대신 프론트에서 GET /api/logs를 5~10초 간격으로 폴링하는 방식으로 시작해도 된다.
"""
from typing import List

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["ws"])
bl

class ConnectionManager:
    def __init__(self) -> None:
        self._connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self._connections:
            self._connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        # 연결이 끊긴 소켓에 보내다 에러 나는 경우를 대비해 하나씩 try 처리
        for connection in list(self._connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


# 다른 모듈(예: app/proxy/proxy.py)에서 import해서 broadcast 호출
manager = ConnectionManager()


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # 클라이언트로부터 오는 메시지는 지금은 사용하지 않지만,
            # 연결 유지를 위해 계속 받아만 둔다.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)