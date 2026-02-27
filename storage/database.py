"""MongoDB async connection management."""
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from typing import Optional
from utils.config import settings
from utils.logger import get_logger

logger = get_logger(__name__)


class Database:
    """MongoDB connection manager with singleton pattern."""
    
    client: Optional[AsyncIOMotorClient] = None
    db: Optional[AsyncIOMotorDatabase] = None
    
    @classmethod
    async def connect(cls) -> None:
        """Establish connection to MongoDB."""
        try:
            cls.client = AsyncIOMotorClient(
                settings.mongodb_uri,
                maxPoolSize=10,
                minPoolSize=1,
                serverSelectionTimeoutMS=5000,
            )
            cls.db = cls.client[settings.mongodb_db_name]
            
            # Verify connection
            await cls.client.admin.command('ping')
            logger.info("mongodb_connected", database=settings.mongodb_db_name)
            
        except Exception as e:
            logger.error("mongodb_connection_failed", error=str(e))
            raise
    
    @classmethod
    async def disconnect(cls) -> None:
        """Close MongoDB connection."""
        if cls.client:
            cls.client.close()
            logger.info("mongodb_disconnected")
    
    @classmethod
    def get_database(cls) -> AsyncIOMotorDatabase:
        """Get database instance."""
        if cls.db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return cls.db
    
    @classmethod
    async def health_check(cls) -> bool:
        """Check database connection health."""
        try:
            if cls.client:
                await cls.client.admin.command('ping')
                return True
        except Exception as e:
            logger.error("mongodb_health_check_failed", error=str(e))
        return False


# Dependency for FastAPI
async def get_db() -> AsyncIOMotorDatabase:
    """FastAPI dependency for database access."""
    return Database.get_database()
