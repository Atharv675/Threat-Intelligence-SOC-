"""AlienVault OTX collector for threat intelligence."""
from collectors.base import BaseCollector
from typing import List, Dict, Any
from utils.logger import get_logger

logger = get_logger(__name__)


class AlienVaultCollector(BaseCollector):
    """Collector for AlienVault OTX threat intelligence."""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    @property
    def source_name(self) -> str:
        """Return source name."""
        return "AlienVault"
    
    async def collect(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Collect threat indicators from AlienVault OTX.
        
        Args:
            limit: Maximum number of pulses to fetch
            
        Returns:
            List of threat indicators
        """
        try:
            headers = {}
            if self.api_key:
                headers["X-OTX-API-KEY"] = self.api_key
            
            # Fetch recent pulses
            url = f"{self.BASE_URL}/pulses/subscribed"
            params = {"limit": min(limit, 50)}
            
            response = await self.client.get(url, headers=headers, params=params)
            response.raise_for_status()
            
            data = response.json()
            pulses = data.get("results", [])
            
            # Extract indicators from pulses
            indicators = []
            for pulse in pulses[:limit]:
                pulse_indicators = pulse.get("indicators", [])
                for indicator in pulse_indicators:
                    indicators.append({
                        "type": indicator.get("type", "unknown"),
                        "value": indicator.get("indicator", ""),
                        "pulse_name": pulse.get("name", ""),
                        "pulse_id": pulse.get("id", ""),
                        "tags": pulse.get("tags", []),
                        "created": pulse.get("created", ""),
                        "modified": pulse.get("modified", ""),
                    })
            
            logger.info("alienvault_collected", count=len(indicators))
            return indicators[:limit]
            
        except httpx.HTTPError as e:
            logger.error("alienvault_collection_failed", error=str(e))
            return []
        except Exception as e:
            logger.error("alienvault_unexpected_error", error=str(e))
            return []
