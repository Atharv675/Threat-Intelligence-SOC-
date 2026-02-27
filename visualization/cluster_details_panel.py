"""Cluster details panel data generator."""
from typing import Dict, Any, Optional, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from storage.repositories import EventRepository, AlertRepository, DetectionRepository
from core.risk_scoring import RiskScoring
from security.validation import CorrelatedEvent
from utils.logger import get_logger
import hashlib

logger = get_logger(__name__)


class ClusterDetailsPanel:
    """Generate cluster details for panel display."""

    def __init__(self, db: AsyncIOMotorDatabase):
        """Initialize with database connection."""
        self.db = db
        self.event_repo = EventRepository(db)
        self.alert_repo = AlertRepository(db)
        self.detection_repo = DetectionRepository(db)

    async def get_cluster_details(self, cluster_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cluster details including IOCs, MITRE, risk, and explanations.

        Lookup strategy:
          1. Find the event whose `event_id` == cluster_id
          2. Pull the risk_score / severity already stored in that event doc
          3. Find the matching alert by searching alerts whose `related_events`
             contains the event's IOC value (guaranteed to be in position 0)
          4. Return explanations and analyst_summary from that alert

        Args:
            cluster_id: stable event_id set by the correlation engine

        Returns:
            Cluster details dictionary or None
        """
        try:
            # ── 1. Find the primary event ─────────────────────────────────
            all_events = await self.event_repo.find_all(skip=0, limit=1000)

            primary_event: Optional[Dict] = None
            cluster_events: List[Dict] = []

            for e in all_events:
                eid = e.get("event_id")
                cid = e.get("correlation_id")
                # Compute the same stable md5 fallback that graph_view.py uses
                val_fb = hashlib.md5(e.get("value", "unknown").encode()).hexdigest()[:16]

                if eid == cluster_id or cid == cluster_id or val_fb == cluster_id:
                    if eid == cluster_id or val_fb == cluster_id:
                        primary_event = e
                    cluster_events.append(e)

            # If we found cluster_events but no primary, take the first
            if not primary_event and cluster_events:
                primary_event = cluster_events[0]

            if not primary_event:
                logger.warning("cluster_not_found", cluster_id=cluster_id)
                return None

            ioc_value = primary_event.get("value", "")

            # ── 2. Pull risk score directly from the event doc ────────────
            # (stamped by demo.py at collection time)
            risk_score = float(primary_event.get("risk_score", 0.0))

            # Recalculate inline if still 0 (old data in DB before the fix)
            if risk_score == 0.0:
                try:
                    ce = CorrelatedEvent(**{
                        k: v for k, v in primary_event.items()
                        if k not in ("_id", "risk_score", "severity")
                    })
                    risk_score = RiskScoring.calculate_risk_score(ce)
                except Exception:
                    risk_score = 0.0

            # Severity based on current thresholds
            severity = "Low"
            if risk_score >= 6.5:
                severity = "High"
            elif risk_score >= 4.0:
                severity = "Medium"

            # ── 3. Aggregate IOCs ─────────────────────────────────────────
            iocs = []
            mitre_techniques: set = set()
            for e in cluster_events:
                iocs.append({
                    "type":       e.get("type", "unknown"),
                    "value":      e.get("value", "unknown"),
                    "confidence": e.get("confidence", 0.0),
                    "source":     e.get("source", "unknown"),
                })
                mitre_techniques.update(e.get("mitre_techniques", []))

            # ── 4. Find matching alert ────────────────────────────────────
            # Alerts store ioc_value as the first element of related_events
            all_alerts = await self.alert_repo.find_all(skip=0, limit=500)
            related_alert: Optional[Dict] = None

            for alert in all_alerts:
                rel = alert.get("related_events", [])
                # Match on the IOC value (first element) OR on event_id anywhere in the list
                if ioc_value and ioc_value in rel:
                    related_alert = alert
                    break
                if cluster_id in rel:
                    related_alert = alert
                    break

            explanations: List[str] = []
            summary: str = ""
            alert_risk_score = risk_score

            if related_alert:
                explanations = related_alert.get("explanation", [])
                summary = related_alert.get("analyst_summary", "")
                # Prefer the alert's authoritative risk score if available
                stored_risk = related_alert.get("risk_score")
                if stored_risk is not None and stored_risk > 0:
                    alert_risk_score = stored_risk
                    # Re-derive severity from authoritative score
                    if alert_risk_score >= 6.5:
                        severity = "High"
                    elif alert_risk_score >= 4.0:
                        severity = "Medium"
                    else:
                        severity = "Low"

            # ── 5. Build explanations from raw data if none found ─────────
            if not explanations:
                explanations = [
                    f"IOC type: {primary_event.get('type', 'unknown').upper()}",
                    f"Source: {primary_event.get('source', 'unknown')} threat intelligence feed",
                    f"Confidence: {primary_event.get('confidence', 0.0):.0%}",
                ]
                if primary_event.get("geo_data"):
                    geo = primary_event["geo_data"]
                    country = geo.get("country", "Unknown")
                    if country not in ("Unknown", "Private Network"):
                        explanations.append(f"Geographic origin: {country}")
                if primary_event.get("whois_data", {}).get("newly_registered"):
                    explanations.append("⚠️ Newly registered domain — high suspicion")
                techs = list(mitre_techniques)
                if techs:
                    explanations.append(f"MITRE ATT&CK: {', '.join(techs[:4])}")

            # ── 6. Count related detections ───────────────────────────────
            all_detections = await self.detection_repo.find_all(skip=0, limit=1000)
            ioc_values = {i["value"] for i in iocs}
            related_detections = sum(
                1 for d in all_detections
                if d.get("matched_ioc") in ioc_values
            )

            details = {
                "cluster_id":          cluster_id,
                "iocs":                iocs,
                "mitre_techniques":    sorted(mitre_techniques),
                "risk_score":          round(alert_risk_score, 2),
                "severity":            severity,
                "explanations":        explanations,
                "summary":             summary,
                "event_count":         len(cluster_events),
                "related_detections":  related_detections,
                "correlation_strength": primary_event.get("correlation_strength", 0.0),
                "geo":                 primary_event.get("geo_data"),
                "asn":                 primary_event.get("asn_data"),
            }

            logger.info("cluster_details_retrieved", cluster_id=cluster_id,
                        risk_score=alert_risk_score, severity=severity,
                        explanations=len(explanations))
            return details

        except Exception as e:
            logger.error("cluster_details_failed", cluster_id=cluster_id, error=str(e))
            return None
