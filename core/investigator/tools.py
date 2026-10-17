"""Read-only investigation tools for SOC investigator agent.

Safety & Constraints:
- Pydantic argument validation with extra="forbid".
- Max 20 items in list results; strings truncated to 200 chars.
- Strips all raw log lines (prevents prompt injection from log payloads).
- Runs outputs through Sanitizer.
- STRICTLY READ-ONLY: Never imports or calls any insert, update, delete, or save methods.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field, ConfigDict

from security.sanitizer import Sanitizer
from utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Argument Schemas (extra="forbid")
# ---------------------------------------------------------------------------

class GetIncidentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str = Field(..., description="Unique ID of the incident to inspect", min_length=1, max_length=100)


class GetDetectionsForIpArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str = Field(..., description="IP address to search detections for", min_length=1, max_length=100)
    limit: int = Field(10, description="Max detections to retrieve (capped at 20)", ge=1, le=20)


class GetDetectionsForDomainArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str = Field(..., description="Domain to search detections for", min_length=1, max_length=200)
    limit: int = Field(10, description="Max detections to retrieve (capped at 20)", ge=1, le=20)


class LookupIocArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str = Field(..., description="IOC value (IP, domain, URL, hash) to lookup in threat intel", min_length=1, max_length=200)


class GetRelatedEventsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(..., description="Threat event ID to find correlated cluster events for", min_length=1, max_length=100)


class GetTimelineArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str = Field(..., description="Incident ID to compile chronological event timeline for", min_length=1, max_length=100)


class GetMitreInfoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID (e.g. T1110, T1568)", min_length=3, max_length=20)


# ---------------------------------------------------------------------------
# MITRE Static Knowledge Table (Read-Only)
# ---------------------------------------------------------------------------

KNOWN_MITRE_DATA: Dict[str, Dict[str, str]] = {
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "description": "Adversaries may communicate using application layer protocols to avoid detection."},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control", "description": "Adversaries may communicate using standard HTTP/HTTPS protocols."},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "description": "Adversaries may use brute force techniques to attempt credential guessing."},
    "T1568": {"name": "Dynamic Resolution", "tactic": "Command and Control", "description": "Adversaries may dynamically resolve domain names using Fast Flux or DGA."},
    "T1568.002": {"name": "Domain Generation Algorithms", "tactic": "Command and Control", "description": "Adversaries may use DGAs to dynamically identify C2 domains."},
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance", "description": "Adversaries may execute active reconnaissance scans against network hosts."},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery", "description": "Adversaries may attempt to enumerate network services running on hosts."},
    "T1566": {"name": "Phishing", "tactic": "Initial Access", "description": "Adversaries may send phishing messages with malicious attachments or links."},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access", "description": "Adversaries may send spearphishing messages with links to malicious sites."},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "description": "Adversaries may abuse command and script interpreters to execute commands."},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion", "description": "Adversaries may obtain and abuse credentials of existing accounts."},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact", "description": "Adversaries may perform denial of service attacks to degrade system availability."},
}


# ---------------------------------------------------------------------------
# Sanitization & Output Hygiene Helper
# ---------------------------------------------------------------------------

def _clean_and_truncate(obj: Any, max_len: int = 200, max_items: int = 20) -> Any:
    """
    Recursively sanitize and truncate values.
    Limits lists to max_items, truncates strings to max_len, and deletes raw log lines.
    """
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            # Exclude raw attacker-controlled log fields and DB internal _id
            if k in ("_id", "raw", "raw_data", "raw_log"):
                continue
            cleaned[k] = _clean_and_truncate(v, max_len, max_items)
        return cleaned
    elif isinstance(obj, list):
        return [_clean_and_truncate(item, max_len, max_items) for item in obj[:max_items]]
    elif hasattr(obj, "isoformat"):
        return obj.isoformat()
    elif isinstance(obj, str):
        val = obj[:max_len]
        try:
            return Sanitizer.sanitize_string(val, max_length=max_len)
        except Exception:
            return val.replace("<", "").replace(">", "").strip()[:max_len]
    return obj


# ---------------------------------------------------------------------------
# Read-Only Tools Class
# ---------------------------------------------------------------------------

class InvestigatorTools:
    """Read-only tool interface strictly executing non-mutating database queries."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db

    async def get_incident(self, incident_id: str) -> Dict[str, Any]:
        """Fetch incident details by ID."""
        args = GetIncidentArgs(incident_id=incident_id)
        doc = await self.db.incidents.find_one({"incident_id": args.incident_id}, {"_id": 0})
        if not doc:
            return {"error": f"Incident not found: {args.incident_id}"}
        return _clean_and_truncate(doc)

    async def get_detections_for_ip(self, ip: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve security detections associated with an IP address."""
        args = GetDetectionsForIpArgs(ip=ip, limit=limit)
        limit_val = min(args.limit, 20)
        query = {
            "$or": [
                {"matched_ioc": args.ip},
                {"log_event.source_ip": args.ip},
                {"log_event.client_ip": args.ip},
            ]
        }
        cursor = self.db.detections.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit_val)
        results = await cursor.to_list(length=limit_val)
        return _clean_and_truncate(results, max_items=20)

    async def get_detections_for_domain(self, domain: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve security detections associated with a domain."""
        args = GetDetectionsForDomainArgs(domain=domain, limit=limit)
        limit_val = min(args.limit, 20)
        dom_clean = args.domain.lower()
        query = {
            "$or": [
                {"matched_ioc": dom_clean},
                {"log_event.domain": dom_clean},
            ]
        }
        cursor = self.db.detections.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit_val)
        results = await cursor.to_list(length=limit_val)
        return _clean_and_truncate(results, max_items=20)

    async def lookup_ioc(self, value: str) -> Dict[str, Any]:
        """Look up threat intelligence enrichment and reputation for an IOC."""
        args = LookupIocArgs(value=value)
        val = args.value.strip()
        doc = await self.db.events.find_one({"value": val}, {"_id": 0})
        if not doc and "." in val:
            doc = await self.db.events.find_one({"value": val.lower()}, {"_id": 0})
        if not doc:
            return {"status": "not_found", "message": f"No threat intelligence record found for IOC: {val}"}
        return _clean_and_truncate(doc)

    async def get_related_events(self, event_id: str) -> List[Dict[str, Any]]:
        """Retrieve correlated events linked to a specific threat event."""
        args = GetRelatedEventsArgs(event_id=event_id)
        parent_event = await self.db.events.find_one({"event_id": args.event_id}, {"_id": 0})
        if not parent_event:
            return []

        related_ids = parent_event.get("related_events", [])
        corr_id = parent_event.get("correlation_id")

        query: Dict[str, Any] = {}
        if related_ids:
            query = {"event_id": {"$in": related_ids[:20]}}
        elif corr_id:
            query = {"correlation_id": corr_id, "event_id": {"$ne": args.event_id}}
        else:
            return []

        cursor = self.db.events.find(query, {"_id": 0}).sort("timestamp", -1).limit(20)
        results = await cursor.to_list(length=20)
        return _clean_and_truncate(results, max_items=20)

    async def get_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """Compile a chronological timeline of detection events for an incident."""
        args = GetTimelineArgs(incident_id=incident_id)
        incident = await self.db.incidents.find_one({"incident_id": args.incident_id}, {"_id": 0})
        if not incident:
            return []

        det_ids = incident.get("related_detections", [])[:20]
        timeline = []

        if det_ids:
            cursor = self.db.detections.find(
                {"detection_id": {"$in": det_ids}},
                {"_id": 0, "detection_id": 1, "log_type": 1, "matched_ioc": 1, "rule_name": 1, "timestamp": 1, "confidence": 1}
            ).sort("timestamp", 1).limit(20)
            timeline = await cursor.to_list(length=20)

        return _clean_and_truncate(timeline, max_items=20)

    async def get_mitre_info(self, technique_id: str) -> Dict[str, Any]:
        """Fetch descriptive context for a MITRE ATT&CK technique."""
        args = GetMitreInfoArgs(technique_id=technique_id)
        tid = args.technique_id.strip().upper()
        if tid in KNOWN_MITRE_DATA:
            data = KNOWN_MITRE_DATA[tid]
            return {
                "technique_id": tid,
                "name": data["name"],
                "tactic": data["tactic"],
                "description": data["description"]
            }
        # Fallback format check
        if re.match(r"^T\d{4}(\.\d{3})?$", tid):
            return {
                "technique_id": tid,
                "name": "Standard MITRE ATT&CK Technique",
                "tactic": "Unknown Tactic",
                "description": f"Standard technique identifier {tid} observed in security events."
            }
        return {"error": f"Invalid technique ID format: {tid}"}


# ---------------------------------------------------------------------------
# Tool Schema Definitions for LLM Prompting
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS = [
    {
        "name": "get_incident",
        "description": "Retrieve incident metadata, severity, status, and related detection IDs.",
        "parameters": GetIncidentArgs.model_json_schema()
    },
    {
        "name": "get_detections_for_ip",
        "description": "Fetch detections associated with a source or client IP address.",
        "parameters": GetDetectionsForIpArgs.model_json_schema()
    },
    {
        "name": "get_detections_for_domain",
        "description": "Fetch detections associated with a queried or matched domain.",
        "parameters": GetDetectionsForDomainArgs.model_json_schema()
    },
    {
        "name": "lookup_ioc",
        "description": "Check threat intelligence reputation and enrichment for an IP, domain, URL, or hash.",
        "parameters": LookupIocArgs.model_json_schema()
    },
    {
        "name": "get_related_events",
        "description": "Fetch correlated events in the same threat cluster by event ID.",
        "parameters": GetRelatedEventsArgs.model_json_schema()
    },
    {
        "name": "get_timeline",
        "description": "Fetch chronological timeline of detections linked to an incident.",
        "parameters": GetTimelineArgs.model_json_schema()
    },
    {
        "name": "get_mitre_info",
        "description": "Fetch description and tactic for a MITRE ATT&CK technique ID (e.g. T1110, T1568).",
        "parameters": GetMitreInfoArgs.model_json_schema()
    },
]
