"""Configuration management using Pydantic settings."""
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # MongoDB Configuration
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_db_name: str = "threat_intel"
    
    # OSINT API Keys
    alienvault_api_key: Optional[str] = None
    abusedb_api_key: Optional[str] = None
    
    # Rate Limiting
    rate_limit_default: int = 60
    
    # Application Settings
    log_level: str = "INFO"
    environment: str = "development"
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )


# Global settings instance
settings = Settings()
