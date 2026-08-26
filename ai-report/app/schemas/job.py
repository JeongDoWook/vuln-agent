from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict


class JobCreate(BaseModel):
    host_uuid: UUID


class JobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    host_uuid: UUID
    status: str
    result: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None