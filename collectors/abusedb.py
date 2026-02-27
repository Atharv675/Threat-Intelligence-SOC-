"""Abuse.ch collector for malware URLs and IPs."""
import httpx
from collectors.base import BaseCollector
from typing import List, Dict, Any
from utils.logger import get_logger

logger = get_logger(__name__)


class AbuseDBCollector(BaseCollector):
    """Collector for Abuse.ch threat intelligence (URLhaus & Feodo)."""
    
    URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    
    @property
    def source_name(self) -> str:
        """Return source name."""
        return "Abuse.ch"
    
    async def collect(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Collect malware URLs and IPs from Abuse.ch.
        
        Args:
            limit: Maximum number of indicators to fetch
            
        Returns:
            List of threat indicators
        """
        indicators = []
        
        # Collect from URLhaus
        try:
            # urlhaus-api.abuse.ch/v1/urls/recent/ accepts POST with limit
            response = await self.client.get(self.URLHAUS_URL) # Recent docs say GET is fine for recent URLs, or POST. Let's stick to what was likely working or use GET if unsure. The original code used POST. Let's try GET first as it is safer for "recent".
            # Actually, let's look at what the user replaced. 
            # Original was: response = await self.client.post(self.URLHAUS_URL, data={"limit": min(limit, 100)})
            # I should restore that.
            response = await self.client.post(
                self.URLHAUS_URL,
                data={"limit": min(limit, 100)}
            )
            response.raise_for_status()
            
            data = response.json()
            urls = data.get("urls", [])
            
            for url_data in urls[:limit]:
                indicators.append({
                    "type": "url",
                    "value": url_data.get("url", ""),
                    "threat": url_data.get("threat", ""),
                    "tags": url_data.get("tags", []),
                    "date_added": url_data.get("date_added", ""),
                    "urlhaus_link": url_data.get("urlhaus_link", ""),
                })
            
            logger.info("urlhaus_collected", count=len(indicators))
            
        except httpx.HTTPError as e:
            logger.error("urlhaus_collection_failed", error=str(e))
        except Exception as e:
            logger.error("urlhaus_unexpected_error", error=str(e))
        
        # Collect from Feodo Tracker (if we need more indicators)
        if len(indicators) < limit:
            try:
                response = await self.client.get(self.FEODO_URL)
                response.raise_for_status()
                
                data = response.json()
                remaining = limit - len(indicators)
                
                for ip_data in data[:remaining]:
                    indicators.append({
                        "type": "ip",
                        "value": ip_data.get("ip_address", ""),
                        "malware": ip_data.get("malware", ""),
                        "first_seen": ip_data.get("first_seen", ""),
                        "last_online": ip_data.get("last_online", ""),
                    })
                
                logger.info("feodo_collected", count=len(indicators) - len(urls))
                
            except httpx.HTTPError as e:
                logger.error("feodo_collection_failed", error=str(e))
            except Exception as e:
                logger.error("feodo_unexpected_error", error=str(e))
        
        logger.info("abusedb_collected", total_count=len(indicators))
        return indicators[:limit]
