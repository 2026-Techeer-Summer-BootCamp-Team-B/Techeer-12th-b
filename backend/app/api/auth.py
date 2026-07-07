"""
담당: 이용욱 (게이트웨이)

관리자 로그인/로그아웃/세션 조회 API.
User(PostgreSQL) + SessionStore(Redis) 조합으로 동작.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models.rdbms_models import User
from app.storage.session_store import create_session, delete_session

router = APIRouter(prefix="/api/auth", tags=["auth"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_in: int
    role: str


class MeResponse(BaseModel):
    id: str
    username: str
    role: str


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()

    # 사용자 없음과 비밀번호 틀림을 같은 메시지로 응답 - 계정 존재 여부를 외부에 노출하지 않기 위함
    if user is None or not pwd_context.verify(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="아이디 또는 비밀번호가 올바르지 않음",
        )

    token = create_session(user_id=user.id, role=user.role)
    return LoginResponse(token=token, expires_in=3600 * 8, role=user.role)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(current_user: dict = Depends(get_current_user)):
    delete_session(current_user["token"])
    return None


@router.get("/me", response_model=MeResponse)
def me(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="사용자를 찾을 수 없음")
    return MeResponse(id=str(user.id), username=user.username, role=user.role)
