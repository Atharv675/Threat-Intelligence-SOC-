"""Detection execution engine for IOC matching."""
from typing import Dict, Any, List, Optional, Set
from motor.motor_asyncio import AsyncIOMotorDatabase
from storage.repositories import EventRepository
from utils.logger import get_logger
import uuid
from datetime import datetime
import re

logger = get_logger(__name__)


class DetectionEngine:
    """Match log events against stored threat intelligence."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        """
        Initialize detection engine.
        
        Args:
            db: MongoDB database instance
        """
        self.db = db
        self.event_repo = EventRepository(db)
        self._ioc_cache: Optional[Dict[str, Any]] = None
    
    async def _load_ioc_cache(self) -> Dict[str, Dict[str, Any]]:
        """
        Load IOCs from events collection into memory cache.
        
        Returns:
            Dictionary mapping IOC values to event data
        """
        if self._ioc_cache is not None:
            return self._ioc_cache
        
        # Retrieve all events from MongoDB
        events = await self.event_repo.find_all(skip=0, limit=10000)
        
        # Build lookup map: {ioc_value: event_data}
        ioc_map = {}
        for event in events:
            value = event.get("value", "").lower()
            if value:
                ioc_map[value] = event
        
        self._ioc_cache = ioc_map
        logger.info("ioc_cache_loaded", ioc_count=len(ioc_map))
        return ioc_map
    
    def _extract_iocs_from_log(self, log_event: Dict[str, Any]) -> Set[str]:
        """
        Extract potential IOCs from log event.
        
        Args:
            log_event: Validated log event
            
        Returns:
            Set of IOC values (IPs, domains, URLs)
        """
        iocs = set()
        log_type = log_event.get("log_type")
        
        # Extract based on log type
        if log_type == "auth":
            # Extract source IP
            source_ip = log_event.get("source_ip")
            if source_ip:
                iocs.add(source_ip.lower())
        
        elif log_type == "nginx":
            # Extract client IP
            client_ip = log_event.get("client_ip")
            if client_ip:
                iocs.add(client_ip.lower())
            
            # Extract domain from path (if full URL)
            path = log_event.get("path", "")
            if path.startswith("http://") or path.startswith("https://"):
                iocs.add(path.lower())
            
            # Extract domains from referrer
            referrer = log_event.get("referrer", "")
            if referrer and referrer != "-":
                iocs.add(referrer.lower())
        
        elif log_type == "dns":
            # Extract queried domain
            domain = log_event.get("domain")
            if domain:
                iocs.add(domain.lower())
            
            query = log_event.get("query")
            if query:
                iocs.add(query.lower())
            
            # Extract client IP
            client_ip = log_event.get("client_ip")
            if client_ip:
                iocs.add(client_ip.lower())
        
        return iocs
    
    async def detect(self, log_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect if log event matches known IOCs.
        
        Args:
            log_event: Validated log event dictionary
            
        Returns:
            Detection dict if match found, None otherwise
        """
        try:
            # Load IOC cache
            ioc_map = await self._load_ioc_cache()
            
            if not ioc_map:
                logger.debug("no_iocs_available")
                return None
            
            # Extract IOCs from log
            log_iocs = self._extract_iocs_from_log(log_event)
            
            # Check for matches
            for ioc_value in log_iocs:
                if ioc_value in ioc_map:
                    threat_event = ioc_map[ioc_value]
                    
                    # Determine matched field
                    matched_field = self._determine_matched_field(log_event, ioc_value)
                    
                    # Create detection
                    detection = {
                        "detection_id": str(uuid.uuid4()),
                        "log_type": log_event.get("log_type"),
                        "matched_ioc": ioc_value,
                        "matched_field": matched_field,
                        "ioc_source": threat_event.get("source"),
                        "ioc_type": threat_event.get("type"),
                        "confidence": threat_event.get("confidence", 0.5),
                        "log_event": log_event,
                        "threat_event_id": threat_event.get("event_id"),
                        "timestamp": datetime.utcnow(),
                    }
                    
                    logger.info(
                        "detection_created",
                        detection_id=detection["detection_id"],
                        matched_ioc=ioc_value,
                        log_type=log_event.get("log_type")
                    )
                    
                    return detection
            
            # No matches found
            logger.debug("no_ioc_match", log_type=log_event.get("log_type"))
            return None
            
        except Exception as e:
            logger.error("detection_failed", error=str(e))
            return None
    
    def _determine_matched_field(self, log_event: Dict[str, Any], ioc_value: str) -> str:
        """
        Determine which field in the log matched the IOC.
        
        Args:
            log_event: Log event
            ioc_value: Matched IOC value
            
        Returns:
            Field name that matched
        """
        log_type = log_event.get("log_type")
        
        if log_type == "auth":
            if log_event.get("source_ip", "").lower() == ioc_value:
                return "source_ip"
        
        elif log_type == "nginx":
            if log_event.get("client_ip", "").lower() == ioc_value:
                return "client_ip"
            if log_event.get("path", "").lower() == ioc_value:
                return "path"
            if log_event.get("referrer", "").lower() == ioc_value:
                return "referrer"
        
        elif log_type == "dns":
            if log_event.get("domain", "").lower() == ioc_value:
                return "domain"
            if log_event.get("query", "").lower() == ioc_value:
                return "query"
            if log_event.get("client_ip", "").lower() == ioc_value:
                return "client_ip"
        
        return "unknown"
    
    def clear_cache(self) -> None:
        """Clear IOC cache to force reload."""
        self._ioc_cache = None
        logger.info("ioc_cache_cleared")
