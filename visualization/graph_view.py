"""Graph view generator for interactive node visualization."""
from typing import Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorDatabase
from storage.repositories import EventRepository, AlertRepository
from utils.logger import get_logger
import hashlib

logger = get_logger(__name__)


# MITRE Tactic to Color Mapping  (matches dashboard.html palette)
TACTIC_COLORS = {
    "Initial Access":       "#ff5e7a",
    "Execution":            "#ff8c42",
    "Persistence":          "#ffe066",
    "Privilege Escalation": "#a855f7",
    "Defense Evasion":      "#38bdf8",
    "Credential Access":    "#f472b6",
    "Discovery":            "#34d399",
    "Lateral Movement":     "#c084fc",
    "Collection":           "#fde68a",
    "Command and Control":  "#fb923c",
    "Exfiltration":         "#f87171",
    "Impact":               "#ef4444",
    "default":              "#94a3b8"
}


class GraphView:
    """Generate graph data for D3.js visualization."""

    def __init__(self, db: AsyncIOMotorDatabase):
        """Initialize graph view with database connection."""
        self.db = db
        self.event_repo = EventRepository(db)
        self.alert_repo = AlertRepository(db)

    @staticmethod
    def _get_primary_tactic(mitre_techniques: List[str], ioc_value: str = "") -> str:
        """
        Extract primary MITRE tactic from techniques.

        Uses a SHA-256 hash of the IOC value to rotate the chosen technique,
        so nodes of the same type get varied colours across the graph.
        OWASP A02: SHA-256 used instead of MD5.
        """
        technique_to_tactic = {
            "T1071":     "Command and Control",
            "T1071.001": "Command and Control",
            "T1102":     "Command and Control",
            "T1219":     "Command and Control",
            "T1568":     "Command and Control",
            "T1566":     "Initial Access",
            "T1566.001": "Initial Access",
            "T1566.002": "Initial Access",
            "T1189":     "Initial Access",
            "T1583":     "Resource Development",
            "T1583.001": "Resource Development",
            "T1584":     "Resource Development",
            "T1608.004": "Resource Development",
            "T1590":     "Reconnaissance",
            "T1595":     "Reconnaissance",
            "T1598":     "Reconnaissance",
            "T1046":     "Discovery",
            "T1190":     "Initial Access",
            "T1203":     "Execution",
            "T1204":     "Execution",
            "T1059":     "Execution",
            "T1080":     "Lateral Movement",
            "T1534":     "Lateral Movement",
            "T1055":     "Privilege Escalation",
            "T1547":     "Persistence",
            "T1499":     "Impact",
        }

        if not mitre_techniques:
            return "default"

        # Rotate which technique is "primary" based on SHA-256 of the IOC value
        # so that different nodes of the same type get different colours.
        if ioc_value and len(mitre_techniques) > 1:
            digest    = int(hashlib.sha256(ioc_value.encode()).hexdigest(), 16)
            primary   = mitre_techniques[digest % len(mitre_techniques)]
        else:
            primary = mitre_techniques[0]

        return technique_to_tactic.get(
            primary,
            technique_to_tactic.get(primary.split(".")[0], "default")
        )

    async def get_graph_data(self, limit: int = 500) -> Dict[str, Any]:
        """
        Build graph nodes and edges from MongoDB.

        Nodes use the stable `event_id` stored by the correlation engine.
        Edges are built from `related_events` which also contains event_id values.

        Args:
            limit: Maximum number of nodes to include

        Returns:
            Dictionary with nodes and edges for D3.js
        """
        try:
            events = await self.event_repo.find_all(skip=0, limit=limit)

            nodes: List[Dict] = []
            edges: List[Dict] = []
            seen_ids: set = set()  # track which node IDs we've emitted

            for event in events:
                # Prefer stable event_id; fall back to correlation_id then a truncated value hash
                # OWASP A02: Use SHA-256 instead of MD5 for stable ID generation
                _fb = hashlib.sha256(event.get("value", "unknown").encode()).hexdigest()[:16]
                event_id = (
                    event.get("event_id")
                    or event.get("correlation_id")
                    or _fb
                )

                mitre_techniques  = event.get("mitre_techniques", [])
                risk_score        = event.get("risk_score", 0.0)
                primary_tactic    = self._get_primary_tactic(mitre_techniques, event.get("value", ""))

                node = {
                    "id":           event_id,
                    "label":        event.get("value", "Unknown")[:30],
                    "risk_score":   risk_score,
                    "mitre_tactic": primary_tactic,
                    "size":         10,   # uniform size for all nodes
                    "color":        TACTIC_COLORS.get(primary_tactic, TACTIC_COLORS["default"]),
                    "type":         event.get("type", "unknown"),
                    "source":       event.get("source", "unknown"),
                    "confidence":   event.get("confidence", 0.0),
                    "correlation_id": event.get("correlation_id"),
                }

                if event_id not in seen_ids:
                    nodes.append(node)
                    seen_ids.add(event_id)

            # Build edges from related_events (these are now stable event_id strings)
            for event in events:
                # OWASP A02: SHA-256 fallback for edge source IDs
                _fb = hashlib.sha256(event.get("value", "unknown").encode()).hexdigest()[:16]
                src_id = (
                    event.get("event_id")
                    or event.get("correlation_id")
                    or _fb
                )
                related = event.get("related_events", [])
                strength = event.get("correlation_strength", 0.0)

                for target_id in related:
                    # Only add edge if the target node actually exists in our node set
                    if target_id in seen_ids and target_id != src_id:
                        edges.append({
                            "source":   src_id,
                            "target":   target_id,
                            "strength": strength,
                        })

            logger.info("graph_data_generated", nodes=len(nodes), edges=len(edges))
            return {"nodes": nodes, "edges": edges}

        except Exception as e:
            logger.error("graph_data_generation_failed", error=str(e))
            return {"nodes": [], "edges": []}
