"""Dashboard FastAPI routes and rendering."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from typing import Optional
from datetime import datetime

from storage import get_db
from visualization.graph_view import GraphView
from visualization.cluster_details_panel import ClusterDetailsPanel
from visualization.pipeline_status import PipelineStatus
from visualization.timeline_view import TimelineView
from utils.logger import get_logger

logger = get_logger(__name__)

# Security headers applied to all JSON API responses (OWASP A05)
_SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

# Create router
router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# Setup templates
templates = Jinja2Templates(directory="visualization/templates")


@router.get("", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    """Render main dashboard page."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@router.get("/api/graph-data")
async def get_graph_data(limit: int = 500, db=Depends(get_db)):
    """Get graph nodes and edges for D3.js visualization."""
    try:
        graph_view = GraphView(db)
        data = await graph_view.get_graph_data(limit=limit)
        return JSONResponse(data, headers=_SEC_HEADERS)
    except Exception as e:
        logger.error("graph_data_endpoint_failed", error=str(e))
        return JSONResponse({"nodes": [], "edges": []}, headers=_SEC_HEADERS)


@router.get("/api/cluster/{cluster_id}")
async def get_cluster_details(cluster_id: str, db=Depends(get_db)):
    """
    Get cluster details for panel display.
    OWASP A01: cluster_id used only as a lookup key.
    """
    try:
        cluster_panel = ClusterDetailsPanel(db)
        details = await cluster_panel.get_cluster_details(cluster_id)
        if not details:
            return JSONResponse({"error": "Cluster not found"}, headers=_SEC_HEADERS)
        return JSONResponse(details, headers=_SEC_HEADERS)
    except Exception as e:
        logger.error("cluster_details_endpoint_failed", error=str(e))
        return JSONResponse({"error": "Internal server error"}, status_code=500, headers=_SEC_HEADERS)


@router.get("/api/status")
async def get_pipeline_status(db=Depends(get_db)):
    """Get pipeline status summary."""
    try:
        pipeline_status = PipelineStatus(db)
        status = await pipeline_status.get_status()
        return JSONResponse(status, headers=_SEC_HEADERS)
    except Exception as e:
        logger.error("pipeline_status_endpoint_failed", error=str(e))
        return JSONResponse({"error": str(e)}, headers=_SEC_HEADERS)


@router.get("/api/timeline")
async def get_timeline(limit: int = 100, db=Depends(get_db)):
    """Get timeline events."""
    try:
        timeline_view = TimelineView(db)
        events = await timeline_view.get_timeline_events(limit=limit)
        return JSONResponse({"events": events}, headers=_SEC_HEADERS)
    except Exception as e:
        logger.error("timeline_endpoint_failed", error=str(e))
        return JSONResponse({"events": []}, headers=_SEC_HEADERS)


@router.get("/api/incident-stats")
async def get_incident_stats(db=Depends(get_db)):
    """
    Return incident counts broken down by status and severity.
    Powers the Overview ring, summary table and status indicator cards.
    """
    try:
        from storage.repositories import IncidentRepository, AlertRepository, DetectionRepository, EventRepository
        inc_repo = IncidentRepository(db)
        alt_repo = AlertRepository(db)
        det_repo = DetectionRepository(db)
        evt_repo = EventRepository(db)

        statuses = ["Open", "In Progress", "Resolved", "Closed"]
        severities = ["Critical", "High", "Medium", "Low", "Informational"]

        # Count by status
        status_counts = {}
        for s in statuses:
            status_counts[s] = await inc_repo.count(status=s)

        # Count by severity (incidents table uses these)
        severity_counts = {}
        for sev in severities:
            try:
                sev_total = await inc_repo.count(severity=sev)
            except Exception:
                sev_total = 0
            severity_counts[sev] = sev_total

        total_incidents = sum(status_counts.values())
        active = status_counts.get("Open", 0) + status_counts.get("In Progress", 0)
        resolved = status_counts.get("Resolved", 0) + status_counts.get("Closed", 0)

        # Detection and event totals
        total_detections = await det_repo.count()
        total_events = await evt_repo.count()
        total_alerts = await alt_repo.count()

        # Analyst assignment breakdown — read from incidents collection
        analyst_map: dict = {}
        all_incidents = await inc_repo.find_all(skip=0, limit=500)
        for inc in all_incidents:
            analyst = inc.get("assigned_to") or "Unassigned"
            # normalise email → display name
            name = analyst.split("@")[0].replace(".", " ").title()
            if name not in analyst_map:
                analyst_map[name] = {"new": 0, "in_progress": 0, "resolved": 0, "total": 0}
            s = inc.get("status", "Open")
            analyst_map[name]["total"] += 1
            if s == "Open":
                analyst_map[name]["new"] += 1
            elif s == "In Progress":
                analyst_map[name]["in_progress"] += 1
            elif s in ("Resolved", "Closed"):
                analyst_map[name]["resolved"] += 1

        analysts = [{"name": k, **v} for k, v in analyst_map.items()]

        # MITRE tactic breakdown from events collection
        tactic_map: dict = {}
        all_events = await evt_repo.find_all(skip=0, limit=1000)
        for evt in all_events:
            techniques = evt.get("mitre_techniques", [])
            tactic = evt.get("mitre_tactic", "Unknown")
            if techniques and tactic:
                tactic_map[tactic] = tactic_map.get(tactic, 0) + 1

        # Category breakdown (derived from IOC types → attack categories)
        IOC_TO_CATEGORY = {
            "url": "Web Attack",
            "ip": "Unauthorized Access",
            "domain": "Malware C2",
            "hash": "Malware",
            "email": "Phishing",
        }
        category_map: dict = {}
        for evt in all_events:
            ioc_type = evt.get("type", "unknown")
            cat = IOC_TO_CATEGORY.get(ioc_type, "Suspicious Activity")
            if cat not in category_map:
                category_map[cat] = {"new": 0, "in_progress": 0, "resolved": 0, "total": 0}
            sev_score = evt.get("risk_score", 0)
            category_map[cat]["total"] += 1
            if sev_score >= 7:
                category_map[cat]["new"] += 1
            elif sev_score >= 4:
                category_map[cat]["in_progress"] += 1
            else:
                category_map[cat]["resolved"] += 1

        categories = [{"name": k, **v} for k, v in category_map.items()]

        return JSONResponse({
            "total_incidents": total_incidents,
            "active": active,
            "resolved": resolved,
            "false_positive": 0,   # placeholder; extend when FP logic is added
            "mitigated": resolved,
            "total_detections": total_detections,
            "total_alerts": total_alerts,
            "total_events": total_events,
            "new": status_counts.get("Open", 0),
            "in_progress": status_counts.get("In Progress", 0),
            "escalated": 0,        # placeholder
            "status_counts": status_counts,
            "severity_counts": severity_counts,
            "analysts": analysts,
            "tactic_counts": tactic_map,
            "categories": categories,
        }, headers=_SEC_HEADERS)
    except Exception as e:
        logger.error("incident_stats_endpoint_failed", error=str(e))
        return JSONResponse({"error": "Internal server error"}, status_code=500, headers=_SEC_HEADERS)
