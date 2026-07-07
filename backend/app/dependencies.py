"""
담당: 이용욱 (게이트웨이)

다른 관리 API(Rules API, Target API, Blacklist API 등)들이 공통으로 쓰는
인증 의존성. FastAPI의 Depends()로 라우터 함수에 주입해서 쓴다.

사용 예:
    @router.get("/api/rules")
    def list_rules(current_user: dict = Depends(get_current_user)):
        ...  # 로그인만 하면 누구나 조회 가능

    @router.post("/api/rules")
    def create_rule(payload: ..., current_user: dict = Depends(require_admin)):
        ...  # admin 권한만 쓰기 가능
"""
from fastapi import Depends, Header, HTTPException, status

from app.storage.session_store import get_session


def get_current_user(authorization: str = Header(default=None)) -> dict:
    """Authorization: Bearer <token> 헤더를 검증하고 세션 정보를 반환.
    유효하지 않으면 401을 던진다."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="인증 필요")

    token = authorization.removeprefix("Bearer ").strip()
    session = get_session(token)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="유효하지 않은 세션")

    return {"user_id": session["user_id"], "role": session["role"], "token": token}


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """get_current_user를 통과한 뒤, role이 admin인지 추가로 검사."""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin 권한이 필요합니다")
    return current_user
