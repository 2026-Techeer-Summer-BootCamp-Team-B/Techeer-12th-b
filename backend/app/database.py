"""
담당: 이용욱 (게이트웨이)

PostgreSQL(RDBMS) 연결 설정. User/Target/DetectionRule/AllowList가 여기 붙는다.
Redis(IPBanList, SessionStore)는 별도로 app/storage/redis_client.py에서 관리.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI Depends()로 주입해서 쓰는 DB 세션. 요청 끝나면 자동으로 닫힘."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
