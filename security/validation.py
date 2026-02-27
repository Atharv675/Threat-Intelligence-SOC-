"""Pydantic models for strict input validation."""
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    """Alert severity levels."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class IOCType(str, Enum):
    """Indicator of Compromise types."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"


class ThreatSource(str, Enum):
    """OSINT threat intelligence sources."""
    ALIENVAULT = "AlienVault"
    ABUSEDB = "Abuse.ch"
    OPENPHISH = "OpenPhish"


class NormalizedEvent(BaseModel):
    """Normalized threat event with strict validation."""
    
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    
    type: IOCType = Field(..., description="Type of indicator")
    value: str = Field(..., min_length=1, max_length=500, description="Indicator value")
    source: ThreatSource = Field(..., description="Source of threat intelligence")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0-1)")
    raw_data: Optional[Dict[str, Any]] = Field(default=None, description="Original raw data")
    
    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        """Validate and sanitize indicator value."""
        if len(v.strip()) == 0:
            raise ValueError("Value cannot be empty")
        return v.strip()


class EnrichedEvent(NormalizedEvent):
    """Event with enrichment data."""
    
    model_config = ConfigDict(extra="forbid")
    
    geo_data: Optional[Dict[str, Any]] = Field(default=None, description="GeoIP enrichment")
    asn_data: Optional[Dict[str, Any]] = Field(default=None, description="ASN enrichment")
    whois_data: Optional[Dict[str, Any]] = Field(default=None, description="WHOIS enrichment")


class CorrelatedEvent(EnrichedEvent):
    """Event with correlation metadata."""
    
    model_config = ConfigDict(extra="forbid")
    
    event_id: Optional[str] = Field(default=None, description="Stable hash-based node ID for graph")
    correlation_id: Optional[str] = Field(default=None, description="Correlation cluster ID")
    related_events: List[str] = Field(default_factory=list, description="Related event IDs")
    correlation_strength: float = Field(default=0.0, ge=0.0, le=1.0, description="Correlation strength")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")


class Alert(BaseModel):
    """Threat alert with explanations and risk breakdown."""
    
    model_config = ConfigDict(extra="forbid")
    
    alert_id: str = Field(..., description="Unique alert identifier")
    severity: SeverityLevel = Field(..., description="Alert severity")
    risk_score: float = Field(..., ge=0.0, le=10.0, description="Risk score (0-10)")
    explanation: List[str] = Field(..., min_length=1, description="Alert explanations")
    risk_breakdown: Dict[str, Any] = Field(..., description="Detailed risk breakdown")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")
    related_events: List[str] = Field(..., description="Related event identifiers")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Alert timestamp")
    analyst_summary: Optional[str] = Field(default=None, description="Analyst summary")


class CollectRequest(BaseModel):
    """Request to trigger threat intelligence collection."""
    
    model_config = ConfigDict(extra="forbid")
    
    sources: Optional[List[ThreatSource]] = Field(
        default=None,
        description="Specific sources to collect from (default: all)"
    )
    limit: int = Field(default=10, ge=1, le=100, description="Maximum items per source")


class AlertQueryParams(BaseModel):
    """Query parameters for alert retrieval."""
    
    model_config = ConfigDict(extra="forbid")
    
    severity: Optional[SeverityLevel] = Field(default=None, description="Filter by severity")
    min_risk_score: Optional[float] = Field(default=None, ge=0.0, le=10.0, description="Minimum risk score")
    skip: int = Field(default=0, ge=0, description="Pagination offset")
    limit: int = Field(default=10, ge=1, le=100, description="Page size")