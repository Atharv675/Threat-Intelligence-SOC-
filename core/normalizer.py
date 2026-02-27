"""Data normalization with strict schema validation."""
from typing import Dict, Any, List
from datetime import datetime
from security.validation import NormalizedEvent, IOCType, ThreatSource
from security.sanitizer import Sanitizer
from utils.logger import get_logger
import hashlib

logger = get_logger(__name__)


def _varied_confidence(value: str, base: float, spread: float) -> float:
    """Return a deterministic confidence score within [base, base+spread] based on value hash."""
    h = int(hashlib.md5(value.encode()).hexdigest(), 16)
    jitter = (h % 1000) / 1000.0  # 0.000 – 0.999
    return round(base + jitter * spread, 3)


class Normalizer:
    """Normalize threat intelligence data from various sources."""
    
    @staticmethod
    def normalize_alienvault(raw_data: Dict[str, Any]) -> NormalizedEvent:
        """
        Normalize AlienVault indicator data.
        
        Args:
            raw_data: Raw AlienVault indicator
            
        Returns:
            Normalized event
        """
        # Map AlienVault types to standard IOC types
        type_mapping = {
            "IPv4": IOCType.IP,
            "IPv6": IOCType.IP,
            "domain": IOCType.DOMAIN,
            "hostname": IOCType.DOMAIN,
            "URL": IOCType.URL,
            "FileHash-MD5": IOCType.HASH,
            "FileHash-SHA1": IOCType.HASH,
            "FileHash-SHA256": IOCType.HASH,
            "email": IOCType.EMAIL,
        }
        
        ioc_type = type_mapping.get(raw_data.get("type", ""), IOCType.DOMAIN)
        value = Sanitizer.sanitize_string(raw_data.get("value", ""), max_length=500)
        
        # Confidence varies between 0.50–0.75 based on IOC value (deterministic)
        tags = raw_data.get("tags", [])
        base = 0.55 if tags else 0.50
        confidence = _varied_confidence(value, base, 0.25)
        
        return NormalizedEvent(
            type=ioc_type,
            value=value,
            source=ThreatSource.ALIENVAULT,
            timestamp=datetime.utcnow(),
            confidence=confidence,
            raw_data=raw_data
        )
    
    @staticmethod
    def normalize_abusedb(raw_data: Dict[str, Any]) -> NormalizedEvent:
        """
        Normalize Abuse.ch data.
        
        Args:
            raw_data: Raw Abuse.ch indicator
            
        Returns:
            Normalized event
        """
        ioc_type_str = raw_data.get("type", "url").lower()
        ioc_type = IOCType.URL if ioc_type_str == "url" else IOCType.IP
        value = Sanitizer.sanitize_string(raw_data.get("value", ""), max_length=500)
        
        # Abuse.ch data is high confidence but varies between 0.75–0.95
        confidence = _varied_confidence(value, 0.75, 0.20)
        
        return NormalizedEvent(
            type=ioc_type,
            value=value,
            source=ThreatSource.ABUSEDB,
            timestamp=datetime.utcnow(),
            confidence=confidence,
            raw_data=raw_data
        )
    
    @staticmethod
    def normalize_openphish(raw_data: Dict[str, Any]) -> NormalizedEvent:
        """
        Normalize OpenPhish data.
        
        Args:
            raw_data: Raw OpenPhish URL
            
        Returns:
            Normalized event
        """
        value = Sanitizer.sanitize_string(raw_data.get("value", ""), max_length=500)
        
        # OpenPhish confidence varies between 0.60–0.92 per IOC (deterministic)
        confidence = _varied_confidence(value, 0.60, 0.32)
        
        return NormalizedEvent(
            type=IOCType.URL,
            value=value,
            source=ThreatSource.OPENPHISH,
            timestamp=datetime.utcnow(),
            confidence=confidence,
            raw_data=raw_data
        )
    
    @classmethod
    def normalize(cls, raw_data: Dict[str, Any], source: str) -> NormalizedEvent:
        """
        Normalize data based on source.
        
        Args:
            raw_data: Raw threat data
            source: Source name (AlienVault, Abuse.ch, OpenPhish)
            
        Returns:
            Normalized event
        """
        source_lower = source.lower()
        
        if "alienvault" in source_lower:
            return cls.normalize_alienvault(raw_data)
        elif "abuse" in source_lower:
            return cls.normalize_abusedb(raw_data)
        elif "openphish" in source_lower:
            return cls.normalize_openphish(raw_data)
        else:
            logger.warning("unknown_source", source=source)
            # Default normalization
            return NormalizedEvent(
                type=IOCType.DOMAIN,
                value=Sanitizer.sanitize_string(raw_data.get("value", "unknown"), max_length=500),
                source=ThreatSource.ALIENVAULT,
                timestamp=datetime.utcnow(),
                confidence=0.5,
                raw_data=raw_data
            )
    
    @classmethod
    def normalize_batch(cls, raw_data_list: List[Dict[str, Any]], source: str) -> List[NormalizedEvent]:
        """
        Normalize a batch of raw data.
        
        Args:
            raw_data_list: List of raw threat data
            source: Source name
            
        Returns:
            List of normalized events
        """
        normalized = []
        for raw_data in raw_data_list:
            try:
                event = cls.normalize(raw_data, source)
                normalized.append(event)
            except Exception as e:
                logger.error("normalization_failed", error=str(e), data=raw_data)
        
        logger.info("normalized_batch", count=len(normalized), source=source)
        return normalized
