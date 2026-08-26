import asyncio

from app.database.postgresql_session import Base, async_engine
from app.database import models


async def create_tables():
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


if __name__ == "__main__":
    asyncio.run(create_tables())