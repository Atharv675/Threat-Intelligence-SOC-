"""Repository pattern for MongoDB operations."""
from typing import List, Optional, Dict, Any
from motor.motor_asyncio import AsyncIOMotorDatabase
from storage.models import (
    EventDocument, AlertDocument, DetectionDocument, IncidentDocument,
    EVENT_INDEXES, ALERT_INDEXES, DETECTION_INDEXES, INCIDENT_INDEXES
)
from security.sanitizer import Sanitizer
from utils.logger import get_logger
from datetime import datetime
import uuid

logger = get_logger(__name__)


class EventRepository:
    """Repository for events collection."""
    
    COLLECTION_NAME = "events"
    
    def __init__(self, db: AsyncIOMotorDatabase):
        """Initialize repository with database connection."""
        self.db = db
        self.collection = db[self.COLLECTION_NAME]
    
    async def create_indexes(self) -> None:
        """Create collection indexes."""
        for index in EVENT_INDEXES:
            await self.collection.create_index(index)
        logger.info("event_indexes_created")
    
    async def insert_one(self, event: Dict[str, Any]) -> str:
        """
        Insert a single event document.
        
        Args:
            event: Event data dictionary
            
        Returns:
            Event ID
        """
        # Sanitize input
        sanitized = Sanitizer.sanitize_dict(event) if isinstance(event, dict) else event
        
        # Generate unique ID if not present
        if "event_id" not in sanitized:
            sanitized["event_id"] = str(uuid.uuid4())
        
        result = await self.collection.insert_one(sanitized)
        logger.info("event_inserted", event_id=sanitized["event_id"])
        return sanitized["event_id"]
    
    async def insert_many(self, events: List[Dict[str, Any]]) -> List[str]:
        """
        Insert multiple event documents.
        
        Args:
            events: List of event data dictionaries
            
        Returns:
            List of event IDs
        """
        if not events:
            return []
        
        # Sanitize and add IDs
        sanitized_events = []
        event_ids = []
        for event in events:
            sanitized = Sanitizer.sanitize_dict(event)
            if "event_id" not in sanitized:
                sanitized["event_id"] = str(uuid.uuid4())
            event_ids.append(sanitized["event_id"])
            sanitized_events.append(sanitized)
        
        await self.collection.insert_many(sanitized_events)
        logger.info("events_inserted", count=len(event_ids))
        return event_ids
    
    async def find_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Find event by ID."""
        event_id = Sanitizer.sanitize_string(event_id, max_length=100)
        return await self.collection.find_one({"event_id": event_id}, {"_id": 0})
    
    async def find_all(self, skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
        """Find all events with pagination."""
        cursor = self.collection.find({}, {"_id": 0}).sort("timestamp", -1).skip(skip).limit(limit)
        return await cursor.to_list(length=limit)
    
    async def count(self) -> int:
        """Count total events."""
        return await self.collection.count_documents({})


class AlertRepository:
    """Repository for alerts collection."""
    
    COLLECTION_NAME = "alerts"
    
    def __init__(self, db: AsyncIOMotorDatabase):
        """Initialize repository with database connection."""
        self.db = db
        self.collection = db[self.COLLECTION_NAME]
    
    async def create_indexes(self) -> None:
        """Create collection indexes."""
        for index in ALERT_INDEXES:
            await self.collection.create_index(index)
        logger.info("alert_indexes_created")
    
    async def insert_one(self, alert: Dict[str, Any]) -> str:
        """
        Insert a single alert document.
        
        Args:
            alert: Alert data dictionary
            
        Returns:
            Alert ID
        """
        # Sanitize input
        sanitized = Sanitizer.sanitize_dict(alert) if isinstance(alert, dict) else alert
        
        # Generate unique ID if not present
        if "alert_id" not in sanitized:
            sanitized["alert_id"] = str(uuid.uuid4())
        
        result = await self.collection.insert_one(sanitized)
        logger.info("alert_inserted", alert_id=sanitized["alert_id"])
        return sanitized["alert_id"]
    
    async def insert_many(self, alerts: List[Dict[str, Any]]) -> List[str]:
        """
        Insert multiple alert documents.
        
        Args:
            alerts: List of alert data dictionaries
            
        Returns:
            List of alert IDs
        """
        if not alerts:
            return []
        
        # Sanitize and add IDs
        sanitized_alerts = []
        alert_ids = []
        for alert in alerts:
            sanitized = Sanitizer.sanitize_dict(alert)
            if "alert_id" not in sanitized:
                sanitized["alert_id"] = str(uuid.uuid4())
            alert_ids.append(sanitized["alert_id"])
            sanitized_alerts.append(sanitized)
        
        await self.collection.insert_many(sanitized_alerts)
        logger.info("alerts_inserted", count=len(alert_ids))
        return alert_ids
    
    async def find_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Find alert by ID."""
        alert_id = Sanitizer.sanitize_string(alert_id, max_length=100)
        return await self.collection.find_one({"alert_id": alert_id}, {"_id": 0})
    
    async def find_all(
        self,
        severity: Optional[str] = None,
        min_risk_score: Optional[float] = None,
        skip: int = 0,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Find alerts with optional filters and pagination.
        
        Args:
            severity: Filter by severity level
            min_risk_score: Minimum risk score filter
            skip: Pagination offset
            limit: Page size
            
        Returns:
            List of alert documents
        """
        query = {}
        if severity:
            query["severity"] = Sanitizer.sanitize_string(severity, max_length=20)
        if min_risk_score is not None:
            query["risk_score"] = {"$gte": min_risk_score}
        
        cursor = self.collection.find(query, {"_id": 0}).sort("timestamp", -1).skip(skip).limit(limit)
        return await cursor.to_list(length=limit)
    
    async def count(self, severity: Optional[str] = None, min_risk_score: Optional[float] = None) -> int:
        """Count alerts with optional filters."""
        query = {}
        if severity:
            query["severity"] = Sanitizer.sanitize_string(severity, max_length=20)
        if min_risk_score is not None:
            query["risk_score"] = {"$gte": min_risk_score}
        return await self.collection.count_documents(query)


class DetectionRepository:
    """Repository for detections collection."""
    
    COLLECTION_NAME = "detections"
    
    def __init__(self, db: AsyncIOMotorDatabase):
        """Initialize repository with database connection."""
        self.db = db
        self.collection = db[self.COLLECTION_NAME]
    
    async def create_indexes(self) -> None:
        """Create collection indexes."""
        for index in DETECTION_INDEXES:
            await self.collection.create_index(index)
        logger.info("detection_indexes_created")
    
    async def insert_one(self, detection: Dict[str, Any]) -> str:
        """
        Insert a single detection document.
        
        Args:
            detection: Detection data dictionary
            
        Returns:
            Detection ID
        """
        # Sanitize input
        sanitized = Sanitizer.sanitize_dict(detection) if isinstance(detection, dict) else detection
        
        # Generate unique ID if not present
        if "detection_id" not in sanitized:
            sanitized["detection_id"] = str(uuid.uuid4())
        
        result = await self.collection.insert_one(sanitized)
        logger.info("detection_inserted", detection_id=sanitized["detection_id"])
        return sanitized["detection_id"]
    
    async def find_by_id(self, detection_id: str) -> Optional[Dict[str, Any]]:
        """Find detection by ID."""
        detection_id = Sanitizer.sanitize_string(detection_id, max_length=100)
        return await self.collection.find_one({"detection_id": detection_id}, {"_id": 0})
    
    async def find_all(
        self,
        log_type: Optional[str] = None,
        skip: int = 0,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Find detections with optional filters and pagination.
        
        Args:
            log_type: Filter by log type
            skip: Pagination offset
            limit: Page size
            
        Returns:
            List of detection documents
        """
        query = {}
        if log_type:
            query["log_type"] = Sanitizer.sanitize_string(log_type, max_length=20)
        
        cursor = self.collection.find(query, {"_id": 0}).sort("timestamp", -1).skip(skip).limit(limit)
        return await cursor.to_list(length=limit)
    
    async def count(self, log_type: Optional[str] = None) -> int:
        """Count detections with optional filters."""
        query = {}
        if log_type:
            query["log_type"] = Sanitizer.sanitize_string(log_type, max_length=20)
        return await self.collection.count_documents(query)


class IncidentRepository:
    """Repository for incidents collection."""
    
    COLLECTION_NAME = "incidents"
    
    def __init__(self, db: AsyncIOMotorDatabase):
        """Initialize repository with database connection."""
        self.db = db
        self.collection = db[self.COLLECTION_NAME]
    
    async def create_indexes(self) -> None:
        """Create collection indexes."""
        for index in INCIDENT_INDEXES:
            await self.collection.create_index(index)
        logger.info("incident_indexes_created")
    
    async def insert_one(self, incident: Dict[str, Any]) -> str:
        """
        Insert a single incident document.
        
        Args:
            incident: Incident data dictionary
            
        Returns:
            Incident ID
        """
        # Sanitize input
        sanitized = Sanitizer.sanitize_dict(incident) if isinstance(incident, dict) else incident
        
        # Generate unique ID if not present
        if "incident_id" not in sanitized:
            sanitized["incident_id"] = str(uuid.uuid4())
        
        result = await self.collection.insert_one(sanitized)
        logger.info("incident_inserted", incident_id=sanitized["incident_id"])
        return sanitized["incident_id"]
    
    async def update_one(self, incident_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update an incident document.
        
        Args:
            incident_id: Incident ID
            updates: Fields to update
            
        Returns:
            True if updated, False otherwise
        """
        incident_id = Sanitizer.sanitize_string(incident_id, max_length=100)
        
        result = await self.collection.update_one(
            {"incident_id": incident_id},
            {"$set": updates}
        )
        
        if result.modified_count > 0:
            logger.info("incident_updated", incident_id=incident_id)
            return True
        return False
    
    async def find_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Find incident by ID."""
        incident_id = Sanitizer.sanitize_string(incident_id, max_length=100)
        return await self.collection.find_one({"incident_id": incident_id}, {"_id": 0})
    
    async def find_all(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        skip: int = 0,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Find incidents with optional filters and pagination.
        
        Args:
            status: Filter by status
            severity: Filter by severity
            skip: Pagination offset
            limit: Page size
            
        Returns:
            List of incident documents
        """
        query = {}
        if status:
            query["status"] = Sanitizer.sanitize_string(status, max_length=20)
        if severity:
            query["severity"] = Sanitizer.sanitize_string(severity, max_length=20)
        
        cursor = self.collection.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit)
        return await cursor.to_list(length=limit)
    
    async def count(self, status: Optional[str] = None, severity: Optional[str] = None) -> int:
        """Count incidents with optional filters."""
        query = {}
        if status:
            query["status"] = Sanitizer.sanitize_string(status, max_length=20)
        if severity:
            query["severity"] = Sanitizer.sanitize_string(severity, max_length=20)
        return await self.collection.count_documents(query)

