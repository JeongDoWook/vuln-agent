from app.agent.graph import run_vuln_agent
from app.database.postgresql_session import SyncSessionLocal
from app.services.job_services import (
    get_job,
    mark_processing,
    mark_success,
    mark_failed
)
from app.workers.celery_app import celery_app


@celery_app.task
def process_job(job_id: int):
    db = SyncSessionLocal()

    job = None

    try:
        job = get_job(db, job_id)

        if job is None:
            return

        mark_processing(db, job)

        pdf_path = run_vuln_agent(host_uuid=str(job.host_uuid), job_id=job.id)

        mark_success(db, job, pdf_path)

    except Exception as exc:
        db.rollback()

        if job is not None:
            mark_failed(db, job, str(exc))

        raise

    finally:
        db.close()