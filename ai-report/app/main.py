from fastapi import FastAPI
from app.api.jobs import router as jobs_router
from app.config import settings


app = FastAPI(
    title=settings.app_name,
    debug=settings.debug,
)


app.include_router(
    jobs_router,
    prefix='/jobs',
    tags=['jobs'],
)


@app.get('/health')
async def health():
    return {
        'status': 'ok',
    }