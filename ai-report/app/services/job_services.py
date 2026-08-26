from sqlalchemy.orm import Session
from app.database.models import Job
from datetime import datetime, timezone


# 작업 조회
def get_job(db: Session, job_id: int) -> Job | None:
    return db.get(Job, job_id)


# 작업 시작 상태로 변경
def mark_processing(db: Session, job: Job) -> None:
    job.status = 'PROCESSING'
    job.started_at = datetime.now(timezone.utc)
    db.commit()


# 작업 성공 결과 저장
def mark_success(db: Session, job: Job, result: str) -> None:
    job.status = 'SUCCESS'
    job.result = result
    job.error_message = None
    job.finished_at = datetime.now(timezone.utc)
    db.commit()


# 작업 실패 정보 저장
def mark_failed(db: Session, job: Job, error_message: str) -> None:
    job.status = 'FAILED'
    job.error_message = error_message
    job.result = None
    job.finished_at = datetime.now(timezone.utc)
    db.commit()