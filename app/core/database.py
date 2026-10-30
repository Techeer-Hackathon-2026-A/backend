from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings

engine = create_engine(get_settings().database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI 의존성: 요청마다 DB 세션을 열고 닫는다."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """해커톤용: 마이그레이션 도구 없이 테이블을 생성한다."""
    from app import models  # noqa: F401  모델 등록용 import

    Base.metadata.create_all(bind=engine)
