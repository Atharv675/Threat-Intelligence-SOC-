"""Incident lifecycle manager for security incidents."""
from typing import Dict, Any, List, Optional
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorDatabase
from storage.repositories import IncidentRepository
from utils.logger import get_logger
import uuid

logger = get_logger(__name__)


class IncidentStatus:
    """Incident status constants."""
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    RESOLVED = "Resolved"
    CLOSED = "Closed"
    
    @classmethod
    def all(cls) -> List[str]:
        return [cls.OPEN, cls.IN_PROGRESS, cls.RESOLVED, cls.CLOSED]


class IncidentSeverity:
    """Incident severity constants."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    
    @classmethod
    def all(cls) -> List[str]:
        return [cls.LOW, cls.MEDIUM, cls.HIGH, cls.CRITICAL]


class IncidentManager:
    """Manage security incident lifecycle."""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        """
        Initialize incident manager.
        
        Args:
            db: MongoDB database instance
        """
        self.db = db
        self.incident_repo = IncidentRepository(db)
    
    async def create_incident(
        self,
        title: str,
        description: str,
        severity: str,
        detections: Optional[List[str]] = None,
        alerts: Optional[List[str]] = None,
        assigned_to: Optional[str] = None
    ) -> str:
        """
        Create a new security incident.
        
        Args:
            title: Incident title
            description: Detailed description
            severity: Severity level (Low/Medium/High/Critical)
            detections: List of detection IDs
            alerts: List of alert IDs
            assigned_to: Assigned analyst
            
        Returns:
            Incident ID
            
        Raises:
            ValueError: If severity is invalid
        """
        if severity not in IncidentSeverity.all():
            raise ValueError(f"Invalid severity. Must be one of: {IncidentSeverity.all()}")
        
        incident_id = str(uuid.uuid4())
        now = datetime.utcnow()
        
        incident = {
            "incident_id": incident_id,
            "title": title,
            "description": description,
            "status": IncidentStatus.OPEN,
            "severity": severity,
            "assigned_to": assigned_to,
            "notes": [],
            "related_detections": detections or [],
            "related_alerts": alerts or [],
            "created_at": now,
            "updated_at": now
        }
        
        await self.incident_repo.insert_one(incident)
        
        logger.info(
            "incident_created",
            incident_id=incident_id,
            severity=severity,
            detections_count=len(detections or []),
            alerts_count=len(alerts or [])
        )
        
        return incident_id
    
    async def update_status(
        self,
        incident_id: str,
        new_status: str,
        note: Optional[str] = None,
        author: str = "system"
    ) -> bool:
        """
        Update incident status.
        
        Args:
            incident_id: Incident ID
            new_status: New status (Open/In Progress/Resolved/Closed)
            note: Optional note about status change
            author: Note author
            
        Returns:
            True if updated, False otherwise
            
        Raises:
            ValueError: If status is invalid
        """
        if new_status not in IncidentStatus.all():
            raise ValueError(f"Invalid status. Must be one of: {IncidentStatus.all()}")
        
        # Get current incident
        incident = await self.incident_repo.find_by_id(incident_id)
        if not incident:
            logger.error("incident_not_found", incident_id=incident_id)
            return False
        
        # Build update
        updates = {
            "status": new_status,
            "updated_at": datetime.utcnow()
        }
        
        # Add status change note
        if note:
            status_note = {
                "timestamp": datetime.utcnow(),
                "author": author,
                "content": f"Status changed to {new_status}: {note}"
            }
        else:
            status_note = {
                "timestamp": datetime.utcnow(),
                "author": author,
                "content": f"Status changed to {new_status}"
            }
        
        current_notes = incident.get("notes", [])
        current_notes.append(status_note)
        updates["notes"] = current_notes
        
        # Update incident
        success = await self.incident_repo.update_one(incident_id, updates)
        
        if success:
            logger.info(
                "incident_status_updated",
                incident_id=incident_id,
                old_status=incident.get("status"),
                new_status=new_status
            )
        
        return success
    
    async def add_note(
        self,
        incident_id: str,
        author: str,
        content: str
    ) -> bool:
        """
        Add a note to an incident.
        
        Args:
            incident_id: Incident ID
            author: Note author
            content: Note content
            
        Returns:
            True if added, False otherwise
        """
        # Get current incident
        incident = await self.incident_repo.find_by_id(incident_id)
        if not incident:
            logger.error("incident_not_found", incident_id=incident_id)
            return False
        
        # Add note
        note = {
            "timestamp": datetime.utcnow(),
            "author": author,
            "content": content
        }
        
        current_notes = incident.get("notes", [])
        current_notes.append(note)
        
        # Update incident
        updates = {
            "notes": current_notes,
            "updated_at": datetime.utcnow()
        }
        
        success = await self.incident_repo.update_one(incident_id, updates)
        
        if success:
            logger.info("incident_note_added", incident_id=incident_id, author=author)
        
        return success
    
    async def assign_to(
        self,
        incident_id: str,
        assignee: str,
        author: str = "system"
    ) -> bool:
        """
        Assign incident to an analyst.
        
        Args:
            incident_id: Incident ID
            assignee: Analyst username/email
            author: Who made the assignment
            
        Returns:
            True if assigned, False otherwise
        """
        # Get current incident
        incident = await self.incident_repo.find_by_id(incident_id)
        if not incident:
            logger.error("incident_not_found", incident_id=incident_id)
            return False
        
        # Update assignment
        updates = {
            "assigned_to": assignee,
            "updated_at": datetime.utcnow()
        }
        
        # Add assignment note
        note = {
            "timestamp": datetime.utcnow(),
            "author": author,
            "content": f"Incident assigned to {assignee}"
        }
        
        current_notes = incident.get("notes", [])
        current_notes.append(note)
        updates["notes"] = current_notes
        
        # Update incident
        success = await self.incident_repo.update_one(incident_id, updates)
        
        if success:
            logger.info(
                "incident_assigned",
                incident_id=incident_id,
                assignee=assignee
            )
        
        return success
    
    async def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Get incident by ID.
        
        Args:
            incident_id: Incident ID
            
        Returns:
            Incident dict or None
        """
        return await self.incident_repo.find_by_id(incident_id)
    
    async def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        skip: int = 0,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        List incidents with optional filters.
        
        Args:
            status: Filter by status
            severity: Filter by severity
            skip: Pagination offset
            limit: Page size
            
        Returns:
            List of incidents
        """
        return await self.incident_repo.find_all(
            status=status,
            severity=severity,
            skip=skip,
            limit=limit
        )
    
    async def count_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None
    ) -> int:
        """
        Count incidents with optional filters.
        
        Args:
            status: Filter by status
            severity: Filter by severity
            
        Returns:
            Incident count
        """
        return await self.incident_repo.count(status=status, severity=severity)
