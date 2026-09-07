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
    THREATFOX_URL = "https://threatfox.abuse.ch/export/json/recent/"

    # ThreatFox ioc_type -> our normalized type strings
    THREATFOX_TYPE_MAP = {
        "domain": "domain",
        "url": "url",
        "ip:port": "ip",
        "md5_hash": "hash",
        "sha1_hash": "hash",
        "sha256_hash": "hash",
    }
    
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
        urls = []  # populated on a successful URLhaus fetch; kept for the Feodo count log below

        # Collect from URLhaus
        try:
            # urlhaus-api.abuse.ch/v1/urls/recent/ accepts POST with a limit param
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

        # Collect from ThreatFox (public export, no auth key required) — this is
        # what actually diversifies IOC types beyond just url/ip: it adds
        # domain and file-hash indicators, which correlate into their own
        # distinct clusters instead of folding into the url/ip ones.
        if len(indicators) < limit:
            try:
                response = await self.client.get(self.THREATFOX_URL)
                response.raise_for_status()

                data = response.json()
                remaining = limit - len(indicators)
                added = 0

                for entries in data.values():
                    if added >= remaining:
                        break
                    entry = entries[0] if entries else {}
                    ioc_type = self.THREATFOX_TYPE_MAP.get(entry.get("ioc_type", ""))
                    if not ioc_type:
                        continue

                    value = entry.get("ioc_value", "")
                    if ioc_type == "ip":
                        value = value.split(":")[0]  # strip the port

                    indicators.append({
                        "type": ioc_type,
                        "value": value,
                        "malware": entry.get("malware_printable", ""),
                        "threat_type": entry.get("threat_type", ""),
                        "confidence_level": entry.get("confidence_level", 0),
                        "first_seen": entry.get("first_seen_utc", ""),
                    })
                    added += 1

                logger.info("threatfox_collected", count=added)

            except httpx.HTTPError as e:
                logger.error("threatfox_collection_failed", error=str(e))
            except Exception as e:
                logger.error("threatfox_unexpected_error", error=str(e))

        logger.info("abusedb_collected", total_count=len(indicators))
        return indicators[:limit]
