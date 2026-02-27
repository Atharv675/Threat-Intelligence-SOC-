"""Pipeline status monitoring."""
from typing import Dict, Any
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorDatabase
from storage.repositories import EventRepository, DetectionRepository, IncidentRepository, AlertRepository
from storage.database import Database
from utils.logger import get_logger

logger = get_logger(__name__)


class PipelineStatus:
    """Monitor pipeline component status."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        """Initialize with database connection."""
        self.db = db
        self.event_repo = EventRepository(db)
        self.alert_repo = AlertRepository(db)
        self.detection_repo = DetectionRepository(db)
        self.incident_repo = IncidentRepository(db)
    
    async def get_status(self) -> Dict[str, Any]:
        """
        Return status of all pipeline components.
        
        Returns:
            Status dictionary with collection, detection, and incident stats
        """
        try:
            # Collection status
            total_events = await self.event_repo.count()
            total_alerts = await self.alert_repo.count()
            
            # Get latest event timestamp
            events = await self.event_repo.find_all(skip=0, limit=1)
            last_collection = None
            if events:
                last_collection = events[0].get("timestamp")
            
            # Detection status
            total_detections = await self.detection_repo.count()
            
            # Count detections from today
            today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            all_detections = await self.detection_repo.find_all(skip=0, limit=1000)
            detections_today = sum(
                1 for d in all_detections
                if d.get("timestamp") and d.get("timestamp") >= today_start
            )
            
            # Incident status
            open_incidents = await self.incident_repo.count(status="Open")
            in_progress_incidents = await self.incident_repo.count(status="In Progress")
            resolved_incidents = await self.incident_repo.count(status="Resolved")
            closed_incidents = await self.incident_repo.count(status="Closed")
            
            # Database health
            db_healthy = await Database.health_check()
            
            status = {
                "collection": {
                    "total_events": total_events,
                    "total_alerts": total_alerts,
                    "last_collection": last_collection.isoformat() if last_collection else None,
                    "sources": ["AlienVault", "Abuse.ch", "OpenPhish"]
                },
                "detection": {
                    "total_detections": total_detections,
                    "detections_today": detections_today,
                    "log_types": ["auth", "nginx", "dns"]
                },
                "incidents": {
                    "open": open_incidents,
                    "in_progress": in_progress_incidents,
                    "resolved": resolved_incidents,
                    "closed": closed_incidents,
                    "total": open_incidents + in_progress_incidents + resolved_incidents + closed_incidents
                },
                "database": {
                    "healthy": db_healthy,
                    "collections": ["events", "alerts", "detections", "incidents"]
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info("pipeline_status_retrieved")
            return status
            
        except Exception as e:
            logger.error("pipeline_status_failed", error=str(e))
            return {
                "collection": {"total_events": 0, "total_alerts": 0},
                "detection": {"total_detections": 0, "detections_today": 0},
                "incidents": {"open": 0, "in_progress": 0, "resolved": 0, "closed": 0},
                "database": {"healthy": False},
                "error": str(e)
            }
