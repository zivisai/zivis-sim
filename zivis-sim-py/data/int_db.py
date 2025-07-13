# int_db.py

import os
import asyncio

from sqlalchemy import (
    MetaData, Table, Column, Integer, String, Text, TIMESTAMP, ForeignKey, text
)
from sqlalchemy.ext.asyncio import create_async_engine

# 1) Pull in your async URL
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@postgres:5432/vectors"
)

# 2) Create the async engine
engine = create_async_engine(DATABASE_URL, echo=True)

# 3) Define metadata and tables
metadata = MetaData()

conversations = Table(
    "conversations", metadata,
    Column("id", String, primary_key=True, server_default=text("gen_random_uuid()")),
    Column("created_at", TIMESTAMP(timezone=True), server_default=text("now()")),
    Column("seed_password", Text, nullable=False)
)

messages = Table(
    "messages", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("conversation_id", String, ForeignKey("conversations.id", ondelete="CASCADE")),
    Column("role", String, nullable=False),
    Column("content", Text, nullable=False),
    Column("created_at", TIMESTAMP(timezone=True), server_default=text("now()"))
)

# 4) Async init function
async def init_models():
    # This runs metadata.create_all() in a sync-to-async bridge
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    print("✅ conversations & messages tables created (if not already present)")

# 5) Kick off the async job
if __name__ == "__main__":
    asyncio.run(init_models())
