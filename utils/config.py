"""Configuration management using Pydantic settings."""
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional


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

    # DGA ML Classifier
    # Probability threshold above which a domain is flagged as DGA-generated.
    # Range [0, 1]. Default 0.9 means only very high-confidence DGA hits fire.
    dga_threshold: float = 0.9
    # Domains in this allowlist are never scored by the DGA classifier even if
    # they look algorithmically generated (common CDN/cloud wildcard names, etc.)
    dga_allowlist: List[str] = [
        "amazonaws.com",
        "cloudfront.net",
        "akamaiedge.net",
        "fastly.net",
        "cdn.net",
        "akamaitechnologies.com",
        "edgecastcdn.net",
        "azureedge.net",
    ]

    # LLM Configuration
    llm_provider: str = "none"  # none, ollama, openai, anthropic, gemini
    llm_model: Optional[str] = None
    llm_api_key: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_timeout_seconds: float = 20.0
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )


# Global settings instance
settings = Settings()
