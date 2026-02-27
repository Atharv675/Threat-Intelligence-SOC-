"""OpenPhish collector for phishing URLs."""
import httpx
from collectors.base import BaseCollector
from typing import List, Dict, Any
from utils.logger import get_logger
from datetime import datetime

logger = get_logger(__name__)


class OpenPhishCollector(BaseCollector):
    """Collector for OpenPhish threat intelligence."""
    
    FEED_URL = "https://openphish.com/feed.txt"
    
    @property
    def source_name(self) -> str:
        """Return source name."""
        return "OpenPhish"
    
    async def collect(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Collect phishing URLs from OpenPhish feed.
        
        Args:
            limit: Maximum number of URLs to fetch
            
        Returns:
            List of phishing URL indicators
        """
        try:
            response = await self.client.get(self.FEED_URL, follow_redirects=True)
            response.raise_for_status()
            
            # Parse text feed (one URL per line)
            text = response.text
            urls = [line.strip() for line in text.split('\n') if line.strip()]
            
            indicators = []
            for url in urls[:limit]:
                indicators.append({
                    "type": "url",
                    "value": url,
                    "threat_type": "phishing",
                    "collected_at": datetime.utcnow().isoformat(),
                })
            
            logger.info("openphish_collected", count=len(indicators))
            return indicators
            
        except httpx.HTTPError as e:
            logger.error("openphish_collection_failed", error=str(e))
            return []
        except Exception as e:
            logger.error("openphish_unexpected_error", error=str(e))
            return []
