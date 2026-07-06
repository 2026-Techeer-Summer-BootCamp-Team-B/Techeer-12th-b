"""
담당: 서동영 (대시보드)

여러 대시보드 탭/사용자가 동시에 접속할 수 있으므로, 연결된 WebSocket들을
리스트로 관리하면서 공격 탐지 시 전체에게 동시에 쏴주는 매니저.
"""
from typing import List

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        """연결된 모든 클라이언트에게 동시에 전송. 끊어진 연결은 조용히 정리."""
        stale_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                stale_connections.append(connection)

        for connection in stale_connections:
            self.disconnect(connection)


# 앱 전체에서 공유하는 싱글턴 인스턴스
manager = ConnectionManager()