"""MongoDB document models and indexes."""
from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class EventDocument(BaseModel):
    """MongoDB document model for events collection."""
    
    event_id: str = Field(..., description="Unique event identifier")
    type: str = Field(..., description="IOC type")
    value: str = Field(..., description="IOC value")
    source: str = Field(..., description="Threat source")
    timestamp: datetime = Field(..., description="Event timestamp")
    confidence: float = Field(..., description="Confidence score")
    
    # Enrichment data
    geo_data: Optional[Dict[str, Any]] = None
    asn_data: Optional[Dict[str, Any]] = None
    whois_data: Optional[Dict[str, Any]] = None
    
    # Correlation data
    correlation_id: Optional[str] = None
    related_events: List[str] = Field(default_factory=list)
    correlation_strength: float = 0.0
    
    # MITRE mapping
    mitre_techniques: List[str] = Field(default_factory=list)
    
    # Risk scoring
    risk_score: float = 0.0
    
    # Raw data
    raw_data: Optional[Dict[str, Any]] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class AlertDocument(BaseModel):
    """MongoDB document model for alerts collection."""
    
    alert_id: str = Field(..., description="Unique alert identifier")
    severity: str = Field(..., description="Alert severity")
    risk_score: float = Field(..., description="Risk score (0-10)")
    explanation: List[str] = Field(..., description="Alert explanations")
    risk_breakdown: Dict[str, Any] = Field(..., description="Risk breakdown")
    mitre_techniques: List[str] = Field(..., description="MITRE techniques")
    related_events: List[str] = Field(..., description="Related event IDs")
    timestamp: datetime = Field(..., description="Alert timestamp")
    analyst_summary: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# Index definitions
EVENT_INDEXES = [
    [("event_id", 1)],  # Unique index
    [("timestamp", -1)],  # Sort by timestamp descending
    [("type", 1)],
    [("value", 1)],
    [("source", 1)],
    [("risk_score", -1)],
]

ALERT_INDEXES = [
    [("alert_id", 1)],  # Unique index
    [("timestamp", -1)],  # Sort by timestamp descending
    [("severity", 1)],
    [("risk_score", -1)],
]


class DetectionDocument(BaseModel):
    """MongoDB document model for detections collection."""
    
    detection_id: str = Field(..., description="Unique detection identifier")
    log_type: str = Field(..., description="Log type (auth, nginx, dns)")
    matched_ioc: str = Field(..., description="Matched IOC value")
    matched_field: str = Field(..., description="Field that matched")
    ioc_source: str = Field(..., description="IOC source (AlienVault, etc)")
    ioc_type: str = Field(..., description="IOC type")
    confidence: float = Field(..., description="Detection confidence")
    log_event: Dict[str, Any] = Field(..., description="Original log event")
    threat_event_id: str = Field(..., description="Link to events collection")
    timestamp: datetime = Field(..., description="Detection timestamp")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class IncidentDocument(BaseModel):
    """MongoDB document model for incidents collection."""
    
    incident_id: str = Field(..., description="Unique incident identifier")
    title: str = Field(..., description="Incident title")
    description: str = Field(..., description="Incident description")
    status: str = Field(..., description="Incident status")
    severity: str = Field(..., description="Incident severity")
    assigned_to: Optional[str] = Field(None, description="Assigned analyst")
    notes: List[Dict[str, Any]] = Field(default_factory=list, description="Incident notes")
    related_detections: List[str] = Field(default_factory=list, description="Detection IDs")
    related_alerts: List[str] = Field(default_factory=list, description="Alert IDs")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# Detection collection indexes
DETECTION_INDEXES = [
    [("detection_id", 1)],  # Unique index
    [("timestamp", -1)],  # Sort by timestamp descending
    [("log_type", 1)],
    [("matched_ioc", 1)],
]

# Incident collection indexes
INCIDENT_INDEXES = [
    [("incident_id", 1)],  # Unique index
    [("created_at", -1)],  # Sort by creation timestamp descending
    [("status", 1)],
    [("severity", 1)],
]

