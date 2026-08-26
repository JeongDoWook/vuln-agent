from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from app.database.postgresql_session import Base


class Job(Base):
    __tablename__ = 'jobs'

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    host_uuid: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
    )

    # DB 제약 없는 자유 문자열로 둔다 — PENDING/PROCESSING/SUCCESS/FAILED 외에 새 상태값이
    # 필요해져도(예: 보고서 자체검증 실패) 스키마 마이그레이션 없이 app/services/job_services.py
    # 쪽 코드만 바꾸면 된다.
    status: Mapped[str] = mapped_column(
        String(20),
        default='PENDING',
        nullable=False,
    )

    result: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )