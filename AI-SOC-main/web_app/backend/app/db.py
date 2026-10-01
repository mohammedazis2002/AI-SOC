from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.config import get_settings

_client: AsyncIOMotorClient | None = None


async def connect_db() -> AsyncIOMotorDatabase:
    global _client
    settings = get_settings()
    _client = AsyncIOMotorClient(settings.resolved_mongo_uri)
    return _client[settings.mongo_db_name]


async def close_db() -> None:
    global _client
    if _client:
        _client.close()
        _client = None


def get_db() -> AsyncIOMotorDatabase:
    if _client is None:
        raise RuntimeError('Database not initialized')
    settings = get_settings()
    return _client[settings.mongo_db_name]
