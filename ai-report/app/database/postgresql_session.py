from collections.abc import AsyncGenerator
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.config import settings


# SQLAlchemy ORM 모델들의 공통 부모 클래스로 사용
class Base(DeclarativeBase):
    pass


# 엔진이 async/sync 두 벌인 이유: FastAPI 요청 핸들러(app/api/jobs.py)는 async라
# AsyncSessionLocal을 쓰고, Celery 워커 태스크(app/workers/tasks.py)는 동기 함수라
# SyncSessionLocal을 쓴다. 둘 다 같은 Postgres jobs 테이블을 본다.


async_engine = create_async_engine(
    settings.async_postgresql_url,
    echo=settings.debug,
    pool_pre_ping=True
)


AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


sync_engine = create_engine(
    settings.sync_postgresql_url,
    echo=settings.debug,
    pool_pre_ping=True,
)


SyncSessionLocal = sessionmaker(
    bind=sync_engine,
    autoflush=False,
    expire_on_commit=False,
)