from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.config import settings


mysql_engine = create_engine(
    settings.mysql_url,
    pool_pre_ping=True,
)


MySQLSessionLocal = sessionmaker(
    bind=mysql_engine,
    autoflush=False,
    expire_on_commit=False,
)