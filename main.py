"""FastAPI application for Threat Intelligence Aggregator."""
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles  # Added for static file support
from contextlib import asynccontextmanager
from typing import List, Dict, Any

from utils.logger import setup_logging, get_logger
from utils.config import settings
from storage import (
    Database, get_db, EventRepository, AlertRepository,
    DetectionRepository, IncidentRepository
)
from security import limiter, CollectRequest, AlertQueryParams
from ingestion import EventIngestor, AuthLogEvent, NginxLogEvent, DnsLogEvent
from detection import DetectionEngine
from core.incident_manager import IncidentManager, IncidentStatus, IncidentSeverity
from collectors import AlienVaultCollector, AbuseDBCollector, OpenPhishCollector
from core import (
    Normalizer, Enrichment, CorrelationEngine, MITREMapper,
    RiskScoring, AlertGenerator, AnalystSummary
)
from visualization import dashboard_router

# Setup logging
setup_logging(settings.log_level)
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("application_starting")
    await Database.connect()
    
    # Create indexes
    db = Database.get_database()
    event_repo = EventRepository(db)
    alert_repo = AlertRepository(db)
    detection_repo = DetectionRepository(db)
    incident_repo = IncidentRepository(db)
    await event_repo.create_indexes()
    await alert_repo.create_indexes()
    await detection_repo.create_indexes()
    await incident_repo.create_indexes()
    
    logger.info("application_ready")
    yield
    
    # Shutdown
    logger.info("application_shutting_down")
    await Database.disconnect()


# Initialize FastAPI
app = FastAPI(
    title="Threat Intelligence Aggregator",
    description="Secure OSINT Threat Intelligence Aggregator with MITRE ATT&CK mapping",
    version="1.0.0",
    lifespan=lifespan
)

# Add rate limiter
app.state.limiter = limiter

# Mount static files for graphs (MUST come before include_router)
app.mount("/static", StaticFiles(directory="visualization/static"), name="static")

# Include dashboard router
app.include_router(dashboard_router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler - prevents stack trace exposure."""
    logger.error("unhandled_exception", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "message": "An error occurred processing your request"}
    )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    db_healthy = await Database.health_check()
    return {
        "status": "healthy" if db_healthy else "degraded",
        "database": "connected" if db_healthy else "disconnected"
    }


@app.post("/api/v1/collect")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def collect_threat_intelligence(
    request: Request,
    collect_request: CollectRequest = CollectRequest(),
    db = Depends(get_db)
):
    """
    Trigger threat intelligence collection pipeline.
    
    Pipeline: collectors → normalizer → enrichment → correlation → MITRE → risk → alert → summary → MongoDB
    """
    try:
        logger.info("collection_started", sources=collect_request.sources)
        
        # Step 1: Collect from OSINT sources
        all_raw_data = []
        
        # AlienVault
        if not collect_request.sources or "AlienVault" in [s.value for s in collect_request.sources]:
            async with AlienVaultCollector(api_key=settings.alienvault_api_key) as collector:
                av_data = await collector.collect(limit=collect_request.limit)
                all_raw_data.extend([{"source": "AlienVault", "data": d} for d in av_data])
        
        # Abuse.ch
        if not collect_request.sources or "Abuse.ch" in [s.value for s in collect_request.sources]:
            async with AbuseDBCollector(api_key=settings.abusedb_api_key) as collector:
                abuse_data = await collector.collect(limit=collect_request.limit)
                all_raw_data.extend([{"source": "Abuse.ch", "data": d} for d in abuse_data])
        
        # OpenPhish
        if not collect_request.sources or "OpenPhish" in [s.value for s in collect_request.sources]:
            async with OpenPhishCollector() as collector:
                phish_data = await collector.collect(limit=collect_request.limit)
                all_raw_data.extend([{"source": "OpenPhish", "data": d} for d in phish_data])
        
        if not all_raw_data:
            return {"message": "No threat data collected", "alerts": 0, "events": 0}
        
        # Step 2: Normalize
        normalized_events = []
        for item in all_raw_data:
            normalized = Normalizer.normalize(item["data"], item["source"])
            normalized_events.append(normalized)
        
        # Step 3: Enrich
        enrichment_engine = Enrichment()
        enriched_events = [enrichment_engine.enrich(event) for event in normalized_events]
        
        # Step 4: Correlate
        correlation_engine = CorrelationEngine(time_window_minutes=60)
        correlated_events = correlation_engine.correlate(enriched_events)
        
        # Step 5: MITRE Mapping
        mitre_events = [MITREMapper.enrich_with_mitre(event) for event in correlated_events]
        
        # Step 6: Risk Scoring (embedded in alert generation)
        # Step 7: Alert Generation
        alerts = AlertGenerator.generate_alerts(mitre_events)
        
        # Step 8: Analyst Summary
        summary = AnalystSummary.generate_summary(alerts)
        
        # Step 9: MongoDB Persistence
        event_repo = EventRepository(db)
        alert_repo = AlertRepository(db)
        
        # Store events
        event_docs = [event.model_dump() for event in mitre_events]
        event_ids = await event_repo.insert_many(event_docs)
        
        # Store alerts with summary
        alert_docs = []
        for alert in alerts:
            alert_dict = alert.model_dump()
            alert_dict["analyst_summary"] = summary
            alert_docs.append(alert_dict)
        
        alert_ids = await alert_repo.insert_many(alert_docs)
        
        logger.info("collection_completed", events=len(event_ids), alerts=len(alert_ids))
        
        return {
            "message": "Threat intelligence collection completed",
            "events_collected": len(event_ids),
            "alerts_generated": len(alert_ids),
            "summary": summary
        }
        
    except Exception as e:
        logger.error("collection_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Collection failed")


@app.get("/api/v1/alerts")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def get_alerts(
    request: Request,
    severity: str = None,
    min_risk_score: float = None,
    skip: int = 0,
    limit: int = 10,
    db = Depends(get_db)
):
    """Retrieve alerts with optional filters."""
    try:
        alert_repo = AlertRepository(db)
        alerts = await alert_repo.find_all(
            severity=severity,
            min_risk_score=min_risk_score,
            skip=skip,
            limit=limit
        )
        total = await alert_repo.count(severity=severity, min_risk_score=min_risk_score)
        
        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "alerts": alerts
        }
    except Exception as e:
        logger.error("alert_retrieval_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve alerts")


@app.get("/api/v1/alerts/{alert_id}")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def get_alert(
    request: Request,
    alert_id: str,
    db = Depends(get_db)
):
    """Get specific alert by ID."""
    try:
        alert_repo = AlertRepository(db)
        alert = await alert_repo.find_by_id(alert_id)
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return alert
    except HTTPException:
        raise
    except Exception as e:
        logger.error("alert_retrieval_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve alert")


@app.get("/api/v1/events")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def get_events(
    request: Request,
    skip: int = 0,
    limit: int = 10,
    db = Depends(get_db)
):
    """Retrieve threat events with pagination."""
    try:
        event_repo = EventRepository(db)
        events = await event_repo.find_all(skip=skip, limit=limit)
        total = await event_repo.count()
        
        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "events": events
        }
    except Exception as e:
        logger.error("event_retrieval_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve events")


# ============================================================================
# STAGE 2 ENDPOINTS: Log Ingestion, Detection, Incidents
# ============================================================================

@app.post("/api/v1/ingest/auth")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def ingest_auth_log(
    request: Request,
    raw_log: str,
    db = Depends(get_db)
):
    """Ingest and process auth log."""
    try:
        # Ingest and validate
        validated_log = EventIngestor.ingest(raw_log, log_type="auth")
        
        # Convert to dict for processing
        log_dict = validated_log.model_dump()
        
        # Run detection
        detection_engine = DetectionEngine(db)
        detection = await detection_engine.detect(log_dict)
        
        # Store detection if found
        if detection:
            detection_repo = DetectionRepository(db)
            detection_id = await detection_repo.insert_one(detection)
            
            return {
                "message": "Auth log ingested - threat detected",
                "detection_id": detection_id,
                "matched_ioc": detection["matched_ioc"]
            }
        else:
            return {"message": "Auth log ingested - no threats detected"}
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("auth_log_ingestion_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Log ingestion failed")


@app.post("/api/v1/ingest/nginx")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def ingest_nginx_log(
    request: Request,
    raw_log: str,
    db = Depends(get_db)
):
    """Ingest and process nginx log."""
    try:
        validated_log = EventIngestor.ingest(raw_log, log_type="nginx")
        log_dict = validated_log.model_dump()
        
        detection_engine = DetectionEngine(db)
        detection = await detection_engine.detect(log_dict)
        
        if detection:
            detection_repo = DetectionRepository(db)
            detection_id = await detection_repo.insert_one(detection)
            
            return {
                "message": "Nginx log ingested - threat detected",
                "detection_id": detection_id,
                "matched_ioc": detection["matched_ioc"]
            }
        else:
            return {"message": "Nginx log ingested - no threats detected"}
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("nginx_log_ingestion_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Log ingestion failed")


@app.post("/api/v1/ingest/dns")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def ingest_dns_log(
    request: Request,
    raw_log: str,
    db = Depends(get_db)
):
    """Ingest and process DNS log."""
    try:
        validated_log = EventIngestor.ingest(raw_log, log_type="dns")
        log_dict = validated_log.model_dump()
        
        detection_engine = DetectionEngine(db)
        detection = await detection_engine.detect(log_dict)
        
        if detection:
            detection_repo = DetectionRepository(db)
            detection_id = await detection_repo.insert_one(detection)
            
            return {
                "message": "DNS log ingested - threat detected",
                "detection_id": detection_id,
                "matched_ioc": detection["matched_ioc"]
            }
        else:
            return {"message": "DNS log ingested - no threats detected"}
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("dns_log_ingestion_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Log ingestion failed")


@app.get("/api/v1/detections")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def get_detections(
    request: Request,
    log_type: str = None,
    skip: int = 0,
    limit: int = 10,
    db = Depends(get_db)
):
    """Retrieve detections with optional filters."""
    try:
        detection_repo = DetectionRepository(db)
        detections = await detection_repo.find_all(
            log_type=log_type,
            skip=skip,
            limit=limit
        )
        total = await detection_repo.count(log_type=log_type)
        
        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "detections": detections
        }
    except Exception as e:
        logger.error("detection_retrieval_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve detections")


@app.get("/api/v1/detections/{detection_id}")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def get_detection(
    request: Request,
    detection_id: str,
    db = Depends(get_db)
):
    """Get specific detection by ID."""
    try:
        detection_repo = DetectionRepository(db)
        detection = await detection_repo.find_by_id(detection_id)
        
        if not detection:
            raise HTTPException(status_code=404, detail="Detection not found")
        
        return detection
    except HTTPException:
        raise
    except Exception as e:
        logger.error("detection_retrieval_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve detection")


@app.post("/api/v1/incidents")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def create_incident(
    request: Request,
    title: str,
    description: str,
    severity: str,
    detections: List[str] = None,
    alerts: List[str] = None,
    assigned_to: str = None,
    db = Depends(get_db)
):
    """Create a new security incident."""
    try:
        incident_manager = IncidentManager(db)
        incident_id = await incident_manager.create_incident(
            title=title,
            description=description,
            severity=severity,
            detections=detections,
            alerts=alerts,
            assigned_to=assigned_to
        )
        
        return {"message": "Incident created", "incident_id": incident_id}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("incident_creation_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create incident")


@app.get("/api/v1/incidents")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def get_incidents(
    request: Request,
    status: str = None,
    severity: str = None,
    skip: int = 0,
    limit: int = 10,
    db = Depends(get_db)
):
    """List incidents with optional filters."""
    try:
        incident_manager = IncidentManager(db)
        incidents = await incident_manager.list_incidents(
            status=status,
            severity=severity,
            skip=skip,
            limit=limit
        )
        total = await incident_manager.count_incidents(status=status, severity=severity)
        
        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "incidents": incidents
        }
    except Exception as e:
        logger.error("incident_retrieval_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve incidents")


@app.get("/api/v1/incidents/{incident_id}")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def get_incident(
    request: Request,
    incident_id: str,
    db = Depends(get_db)
):
    """Get specific incident by ID."""
    try:
        incident_manager = IncidentManager(db)
        incident = await incident_manager.get_incident(incident_id)
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        return incident
    except HTTPException:
        raise
    except Exception as e:
        logger.error("incident_retrieval_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve incident")


@app.put("/api/v1/incidents/{incident_id}/status")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def update_incident_status(
    request: Request,
    incident_id: str,
    new_status: str,
    note: str = None,
    author: str = "api",
    db = Depends(get_db)
):
    """Update incident status."""
    try:
        incident_manager = IncidentManager(db)
        success = await incident_manager.update_status(
            incident_id=incident_id,
            new_status=new_status,
            note=note,
            author=author
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        return {"message": "Incident status updated", "new_status": new_status}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error("incident_status_update_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update incident status")


@app.post("/api/v1/incidents/{incident_id}/notes")
@limiter.limit(f"{settings.rate_limit_default}/minute")
async def add_incident_note(
    request: Request,
    incident_id: str,
    author: str,
    content: str,
    db = Depends(get_db)
):
    """Add note to an incident."""
    try:
        incident_manager = IncidentManager(db)
        success = await incident_manager.add_note(
            incident_id=incident_id,
            author=author,
            content=content
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        return {"message": "Note added to incident"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("incident_note_add_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to add note")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)