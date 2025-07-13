# db.py

import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# 1) Load the same DATABASE_URL used elsewhere (with asyncpg)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@postgres:5432/vectors"
)

# 2) Create the async engine
engine = create_async_engine(DATABASE_URL, echo=True)

# 3) Configure sessionmaker for AsyncSession
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# 4) Dependency to get DB session in FastAPI
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
