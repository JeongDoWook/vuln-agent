좋아요. `jobs.py`는 **Job 관련 HTTP 요청을 받는 API 라우터**입니다.

지금 설계에서는 크게 두 가지 역할부터 만들면 됩니다.

```text
POST /jobs
→ 새로운 작업 생성
→ DB에 PENDING 상태로 저장
→ Celery에 작업 전달

GET /jobs/{job_id}
→ DB에서 작업 조회
→ 현재 상태와 결과 반환
```

현재까지 만든 모델과 스키마를 기준으로 `app/api/jobs.py`를 우선 이렇게 만들면 됩니다.

```python
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.database_pool import get_db
from app.database.models import Job
from app.schemas.job import JobCreate, JobResponse
from app.workers.tasks import process_job


router = APIRouter()


@router.post(
    "/",
    response_model=JobResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_job(
    request: JobCreate,
    db: AsyncSession = Depends(get_db),
):
    job = Job(
        host_id=request.host_id,
    )

    db.add(job)

    await db.commit()
    await db.refresh(job)

    process_job.delay(job.id)

    return job


@router.get(
    "/{job_id}",
    response_model=JobResponse,
)
async def get_job(
    job_id: int,
    db: AsyncSession = Depends(get_db),
):
    job = await db.get(Job, job_id)

    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found",
        )

    return job
```

이제 코드를 하나씩 보면 이해가 쉽습니다.

### 1. `router = APIRouter()`

```python
router = APIRouter()
```

`jobs.py` 자체에서 FastAPI 앱을 만드는 게 아니라, **Job API들의 묶음**을 만듭니다.

나중에 `main.py`에서:

```python
app.include_router(
    jobs.router,
    prefix="/jobs",
)
```

처럼 등록합니다.

그러면 `jobs.py`에:

```python
@router.post("/")
```

라고만 작성해도 실제 주소는:

```text
POST /jobs/
```

가 됩니다.

구조는:

```text
main.py
   │
   └── prefix="/jobs"
             │
             ▼
         jobs.py
         ├── POST /
         └── GET /{job_id}

최종 URL
├── POST /jobs/
└── GET  /jobs/{job_id}
```

입니다.

---

## 2. `POST /jobs`

핵심은 이 함수입니다.

```python
@router.post(
    "/",
    response_model=JobResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_job(
    request: JobCreate,
    db: AsyncSession = Depends(get_db),
):
```

사용자가 새로운 작업을 요청하면 실행됩니다.

### `request: JobCreate`

앞에서 만든:

```python
class JobCreate(BaseModel):
    host_id: int
```

가 사용됩니다.

따라서 클라이언트가:

```json
{
    "host_id": 10
}
```

을 보내면 FastAPI가 자동으로:

```python
request.host_id
```

로 사용할 수 있게 만들어줍니다.

잘못된 데이터가 들어오면 FastAPI/Pydantic이 자동으로 거절합니다.

예를 들어:

```json
{
    "host_id": "abc"
}
```

처럼 들어오면 입력 검증 오류가 발생합니다.

---

## 3. `Depends(get_db)`

```python
db: AsyncSession = Depends(get_db)
```

앞에서 만든 `get_db()`가 여기서 사용됩니다.

예를 들어:

```python
async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
```

FastAPI가 API 요청마다 DB 세션을 하나 만들어서 `db`에 넣어줍니다.

즉:

```text
POST /jobs
    ↓
FastAPI
    ↓
get_db()
    ↓
AsyncSession 생성
    ↓
yield session
    ↓
db 변수
```

그래서 `create_job()`에서:

```python
db.add(...)
await db.commit()
```

을 할 수 있습니다.

---

## 4. DB에 새로운 Job 생성

```python
job = Job(
    host_id=request.host_id,
)
```

앞에서 만든 SQLAlchemy 모델을 이용해서 Job 객체를 생성합니다.

현재 모델이:

```python
class Job(Base):
    __tablename__ = "tasks"

    id = ...
    host_id = ...
    status = ...
```

였으므로:

```python
job = Job(
    host_id=request.host_id,
)
```

만 넣어도 됩니다.

`status`는 모델에서:

```python
default="PENDING"
```

으로 해뒀으므로 기본값이 사용됩니다.

즉 개념적으로:

```text
Job(
    id = 자동 생성,
    host_id = 10,
    status = PENDING,
    result = NULL,
    ...
)
```

가 됩니다.

---

## 5. `db.add(job)`

```python
db.add(job)
```

SQLAlchemy 세션에게:

> 이 객체를 DB에 추가할 예정이야.

라고 등록합니다.

이 시점에는 아직 트랜잭션이 최종 확정된 것은 아닙니다.

---

## 6. `await db.commit()`

```python
await db.commit()
```

여기서 실제 INSERT가 수행되고 트랜잭션이 확정됩니다.

대략 SQL 관점에서는:

```sql
INSERT INTO tasks (host_id, status, ...)
VALUES (10, 'PENDING', ...);
```

가 실행된다고 생각하면 됩니다.

---

## 7. 왜 `refresh()`를 하지?

```python
await db.refresh(job)
```

DB가 자동으로 만든 값을 다시 객체에 가져오기 위해서입니다.

특히:

```python
id
```

가 대표적입니다.

현재:

```python
id: Mapped[int] = mapped_column(
    Integer,
    primary_key=True,
    autoincrement=True,
)
```

이므로 ID는 PostgreSQL이 결정합니다.

DB INSERT 전:

```text
job.id
→ 아직 확실하지 않음
```

INSERT 후:

```text
DB
→ id = 25 생성
```

그리고:

```python
await db.refresh(job)
```

하면:

```text
job.id = 25
```

같이 최신 DB 값을 객체에 반영할 수 있습니다.

---

## 8. Celery 작업 전달

이제 중요한 부분입니다.

```python
process_job.delay(job.id)
```

여기서는:

```python
process_job(job.id)
```

라고 직접 호출하지 않습니다.

`delay()`를 호출하면:

```text
FastAPI
   │
   │ process_job.delay(25)
   ▼
RabbitMQ
   │
   ▼
Celery Worker
   │
   ▼
process_job(25)
```

가 됩니다.

즉 API 서버는 실제 오래 걸리는 작업을 수행하지 않습니다.

작업을 큐에 넣은 뒤 바로 사용자에게 응답할 수 있습니다.

이게 지금 FastAPI + RabbitMQ + Celery 구조를 사용하는 핵심 이유입니다.

---

## 9. `return job`

```python
return job
```

SQLAlchemy `Job` 객체를 그대로 반환합니다.

그런데 위에서:

```python
response_model=JobResponse
```

를 지정했기 때문에 FastAPI가 `JobResponse` 형태로 응답을 만들어줍니다.

앞서 스키마에서:

```python
class JobResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )
```

라고 설정했기 때문에 SQLAlchemy 객체를 읽을 수 있습니다.

그래서 사용자에게는 대략:

```json
{
    "id": 25,
    "host_id": 10,
    "status": "PENDING",
    "result": null,
    "created_at": "2026-08-16T14:20:00Z",
    "started_at": null,
    "finished_at": null,
    "error_message": null
}
```

가 반환됩니다.

여기서 모델 필드가 `create_at`이라면 당연히 응답 스키마도 `create_at`으로 맞춰야 합니다.

---

# 10. `GET /jobs/{job_id}`

두 번째 API입니다.

```python
@router.get(
    "/{job_id}",
    response_model=JobResponse,
)
async def get_job(
    job_id: int,
    db: AsyncSession = Depends(get_db),
):
```

사용자가:

```text
GET /jobs/25
```

라고 요청하면:

```python
job_id = 25
```

가 됩니다.

그리고:

```python
job = await db.get(Job, job_id)
```

를 수행합니다.

이건:

> `Job` 테이블에서 primary key가 `25`인 행을 찾아라.

라는 의미입니다.

즉 대략:

```sql
SELECT *
FROM tasks
WHERE id = 25;
```

에 해당합니다.

---

## 작업이 없다면

```python
if job is None:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Job not found",
    )
```

예를 들어:

```text
GET /jobs/99999
```

인데 그런 작업이 없다면:

```http
404 Not Found
```

와:

```json
{
    "detail": "Job not found"
}
```

를 반환합니다.

---

## 작업이 있다면

```python
return job
```

합니다.

예를 들어 Celery가 아직 작업 중이라면:

```json
{
    "id": 25,
    "host_id": 10,
    "status": "PROCESSING",
    "result": null,
    "started_at": "2026-08-16T14:20:01Z",
    "finished_at": null,
    "error_message": null
}
```

작업이 끝난 뒤 다시 조회하면:

```json
{
    "id": 25,
    "host_id": 10,
    "status": "SUCCESS",
    "result": "Job 25 completed",
    "started_at": "2026-08-16T14:20:01Z",
    "finished_at": "2026-08-16T14:20:06Z",
    "error_message": null
}
```

가 될 수 있습니다.

---

# 전체에서 `jobs.py`의 위치

이 파일이 특히 중요한 이유는 **외부 세계와 내부 백엔드를 연결하는 입구**이기 때문입니다.

```text
                       사용자
                         │
                         │ HTTP
                         ▼
                   api/jobs.py
                         │
             ┌───────────┴───────────┐
             │                       │
        POST /jobs             GET /jobs/{id}
             │                       │
             ▼                       ▼
        Job 생성                 Job 조회
             │                       │
             ▼                       │
        PostgreSQL ◀────────────────┘
             │
             │ job.id
             ▼
    process_job.delay()
             │
             ▼
          RabbitMQ
             │
             ▼
      Celery Worker
             │
             ▼
         tasks.py
             │
             ▼
      job_service.py
             │
             ▼
        PostgreSQL
```

그래서 책임을 한 문장씩 나누면:

```text
jobs.py
→ HTTP 요청과 응답을 처리

models.py
→ DB 테이블 구조를 정의

schemas/job.py
→ API 입력/출력 형식을 정의

job_service.py
→ Job 상태를 관리

tasks.py
→ 백그라운드 작업 실행 흐름을 담당

celery_app.py
→ Celery/RabbitMQ 환경 설정
```

입니다.

한 가지 개선한다면, 나중에는 `create_job()` 안의 DB 생성 코드도 `job_service.py`로 옮길 수 있습니다. 하지만 **지금은 백엔드 구조를 이해하고 완성하는 단계이므로 위 정도가 가장 적당합니다.**

이 `jobs.py`가 정상 동작하는 것까지 확인한 뒤 **마지막으로 `main.py`에서 이 router를 등록하면 FastAPI API가 실제로 열립니다.**
