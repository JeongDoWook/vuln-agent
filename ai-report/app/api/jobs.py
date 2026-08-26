from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.postgresql_session import get_db
from app.database.models import Job
from app.schemas.job import JobCreate, JobResponse
from app.workers.tasks import process_job


router = APIRouter()


@router.post('/', response_model=JobResponse, status_code=status.HTTP_201_CREATED)
async def create_job(request: JobCreate, db: AsyncSession=Depends(get_db)):
    job = Job(host_uuid=request.host_uuid)
    db.add(job)

    await db.commit()
    await db.refresh(job)

    process_job.delay(job.id)

    return job


@router.get('/{job_id}', response_model=JobResponse)
async def get_job(job_id: int, db: AsyncSession=Depends(get_db)):
    job = await db.get(Job, job_id)

    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='Job not found',
        )

    return job


@router.get('/{job_id}/report')
async def get_job_report(job_id: int, db: AsyncSession=Depends(get_db)):
    job = await db.get(Job, job_id)

    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='Job not found',
        )

    if job.status != 'SUCCESS' or not job.result:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='Report is not ready for this job',
        )

    pdf_path = Path(job.result)
    if not pdf_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='Report file not found',
        )

    return FileResponse(
        path=pdf_path,
        media_type='application/pdf',
        filename=pdf_path.name,
    )