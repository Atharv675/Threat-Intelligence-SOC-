"""Timeline view generator for chronological events."""
from typing import Dict, Any, List, Optional
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorDatabase
from storage.repositories import EventRepository, DetectionRepository, IncidentRepository
from utils.logger import get_logger

logger = get_logger(__name__)


class TimelineView:
    """Generate chronological timeline of events."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        """Initialize with database connection."""
        self.db = db
        self.event_repo = EventRepository(db)
        self.detection_repo = DetectionRepository(db)
        self.incident_repo = IncidentRepository(db)
    
    async def get_timeline_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Retrieve timeline events in chronological order.
        
        Args:
            start_time: Optional start time filter
            end_time: Optional end time filter
            limit: Maximum number of events
            
        Returns:
            List of timeline events
        """
        try:
            timeline_events = []
            
            # Fetch IOC ingestion events
            events = await self.event_repo.find_all(skip=0, limit=limit)
            for event in events:
                timestamp = event.get("timestamp")
                if timestamp:
                    timeline_events.append({
                        "timestamp": timestamp,
                        "event_type": "ioc_ingestion",
                        "description": f"IOC ingested: {event.get('value', 'unknown')}",
                        "details": {
                            "type": event.get("type"),
                            "source": event.get("source"),
                            "confidence": event.get("confidence")
                        },
                        "severity": None
                    })
            
            # Fetch correlation events (events with correlation_id)
            correlated_events = [e for e in events if e.get("correlation_id")]
            for event in correlated_events[:limit//3]:
                timestamp = event.get("timestamp")
                if timestamp:
                    timeline_events.append({
                        "timestamp": timestamp,
                        "event_type": "correlation",
                        "description": f"Correlated {len(event.get('related_events', []))} related event(s)",
                        "details": {
                            "correlation_id": event.get("correlation_id"),
                            "strength": event.get("correlation_strength")
                        },
                        "severity": None
                    })
            
            # Fetch detection events
            detections = await self.detection_repo.find_all(skip=0, limit=limit//3)
            for detection in detections:
                timestamp = detection.get("timestamp")
                if timestamp:
                    timeline_events.append({
                        "timestamp": timestamp,
                        "event_type": "detection",
                        "description": f"Threat detected in {detection.get('log_type', 'unknown')} log",
                        "details": {
                            "matched_ioc": detection.get("matched_ioc"),
                            "ioc_source": detection.get("ioc_source"),
                            "confidence": detection.get("confidence")
                        },
                        "severity": "Medium"
                    })
            
            # Fetch incident events
            incidents = await self.incident_repo.find_all(skip=0, limit=limit//3)
            for incident in incidents:
                # Incident created
                created_at = incident.get("created_at")
                if created_at:
                    timeline_events.append({
                        "timestamp": created_at,
                        "event_type": "incident_created",
                        "description": f"Incident created: {incident.get('title', 'Unknown')}",
                        "details": {
                            "incident_id": incident.get("incident_id"),
                            "severity": incident.get("severity"),
                            "status": incident.get("status")
                        },
                        "severity": incident.get("severity")
                    })
                
                # Incident updates (from notes)
                for note in incident.get("notes", []):
                    note_timestamp = note.get("timestamp")
                    if note_timestamp:
                        timeline_events.append({
                            "timestamp": note_timestamp,
                            "event_type": "incident_updated",
                            "description": f"Incident update: {incident.get('title', 'Unknown')}",
                            "details": {
                                "incident_id": incident.get("incident_id"),
                                "author": note.get("author"),
                                "note": note.get("content")
                            },
                            "severity": None
                        })
            
            # Sort by timestamp (newest first)
            timeline_events.sort(key=lambda x: x["timestamp"], reverse=True)
            
            # Apply filters
            if start_time:
                timeline_events = [e for e in timeline_events if e["timestamp"] >= start_time]
            if end_time:
                timeline_events = [e for e in timeline_events if e["timestamp"] <= end_time]
            
            # Limit results
            timeline_events = timeline_events[:limit]
            
            # Convert timestamps to ISO format
            for event in timeline_events:
                if isinstance(event["timestamp"], datetime):
                    event["timestamp"] = event["timestamp"].isoformat()
            
            logger.info("timeline_events_retrieved", count=len(timeline_events))
            return timeline_events
            
        except Exception as e:
            logger.error("timeline_events_failed", error=str(e))
            return []
