"""Base collector interface for OSINT sources."""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
import httpx
from utils.logger import get_logger

logger = get_logger(__name__)


class BaseCollector(ABC):
    """Abstract base class for OSINT collectors."""
    
    def __init__(self, api_key: str = None, timeout: int = 30):
        """
        Initialize collector.
        
        Args:
            api_key: Optional API key for authenticated sources
            timeout: HTTP request timeout in seconds
        """
        self.api_key = api_key
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout)
    
    @abstractmethod
    async def collect(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Collect threat intelligence data.
        
        Args:
            limit: Maximum number of items to collect
            
        Returns:
            List of raw threat intelligence data
        """
        pass
    
    @property
    @abstractmethod
    def source_name(self) -> str:
        """Return the name of this collector source."""
        pass
    
    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.aclose()
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
