"""
담당: 이용욱 (게이트웨이)

최초 1회 실행용 스크립트:
1) database.py의 Base.metadata를 기준으로 PostgreSQL에 테이블 생성
2) 기본 관리자 계정(admin) 시딩

실행 방법:
    python -m app.init_db

주의: 이건 학습/MVP 단계에서 빠르게 테이블을 만들기 위한 방식이고,
팀 규모가 커지거나 스키마가 자주 바뀌면 Alembic 같은 마이그레이션 도구로
전환하는 걸 권장합니다 (지금은 create_all()로 충분).
"""
from passlib.context import CryptContext

from app.database import Base, engine, SessionLocal
from app.models.rdbms_models import User, Target, DetectionRule, AllowList, AuditLog  # noqa: F401 (create_all이 인식하도록 import)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def main():
    print("테이블 생성 중...")
    Base.metadata.create_all(bind=engine)
    print("테이블 생성 완료.")

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == "admin").first()
        if existing:
            print("admin 계정이 이미 존재합니다. 시딩을 건너뜁니다.")
            return

        admin = User(
            username="admin",
            password_hash=pwd_context.hash("changeme123"),  # 최초 로그인 후 반드시 변경할 것
            role="admin",
        )
        db.add(admin)

        # 기본 보호 대상(Juice Shop)도 함께 등록
        default_target = Target(
            name="Juice Shop",
            base_url="http://juice-shop:3000",
            is_active=True,
        )
        db.add(default_target)

        db.commit()
        print("admin 계정 생성 완료 (username=admin, password=changeme123)")
        print("Target 'Juice Shop' 등록 완료")
    finally:
        db.close()


if __name__ == "__main__":
    main()
