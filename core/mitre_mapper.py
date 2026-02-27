"""MITRE ATT&CK framework mapping for threat events.

OWASP A08 (Software Integrity): All technique IDs validated against known MITRE format
before being stored or returned.
"""
from typing import List, Dict, Any
import hashlib
import re
from security.validation import IOCType, CorrelatedEvent
from utils.logger import get_logger

logger = get_logger(__name__)

# Regex for valid MITRE technique IDs (e.g. T1071, T1071.001)
_TECHNIQUE_RE = re.compile(r'^T\d{4}(\.\d{3})?$')


def _validate_technique_id(tid: str) -> bool:
    """OWASP A04: Validate technique IDs against MITRE format before use."""
    return bool(_TECHNIQUE_RE.match(tid))


class MITREMapper:
    """Map threat indicators to MITRE ATT&CK techniques and tactics."""

    # Expanded technique mapping — multiple tactics per IOC type so nodes
    # can receive varied colours via the rotate helper below.
    TECHNIQUE_MAPPING: Dict[IOCType, List[Dict[str, str]]] = {
        IOCType.IP: [
            {"id": "T1071",   "name": "Application Layer Protocol",       "tactic": "Command and Control"},
            {"id": "T1595",   "name": "Active Scanning",                  "tactic": "Reconnaissance"},
            {"id": "T1499",   "name": "Endpoint Denial of Service",       "tactic": "Impact"},
            {"id": "T1219",   "name": "Remote Access Software",           "tactic": "Command and Control"},
            {"id": "T1046",   "name": "Network Service Discovery",        "tactic": "Discovery"},
        ],
        IOCType.DOMAIN: [
            {"id": "T1071.001", "name": "Web Protocols",                  "tactic": "Command and Control"},
            {"id": "T1583.001", "name": "Domains",                        "tactic": "Resource Development"},
            {"id": "T1590",   "name": "Gather Victim Network Information","tactic": "Reconnaissance"},
            {"id": "T1568",   "name": "Dynamic Resolution",               "tactic": "Command and Control"},
            {"id": "T1584",   "name": "Compromise Infrastructure",        "tactic": "Resource Development"},
        ],
        IOCType.URL: [
            {"id": "T1566.002", "name": "Spearphishing Link",             "tactic": "Initial Access"},
            {"id": "T1102",   "name": "Web Service",                      "tactic": "Command and Control"},
            {"id": "T1080",   "name": "Taint Shared Content",             "tactic": "Lateral Movement"},
            {"id": "T1189",   "name": "Drive-by Compromise",              "tactic": "Initial Access"},
            {"id": "T1608.004", "name": "Stage Capabilities: Drive-by Target", "tactic": "Resource Development"},
            {"id": "T1071.001", "name": "Web Protocols",                  "tactic": "Command and Control"},
        ],
        IOCType.HASH: [
            {"id": "T1204",   "name": "User Execution",                   "tactic": "Execution"},
            {"id": "T1059",   "name": "Command and Scripting Interpreter","tactic": "Execution"},
            {"id": "T1055",   "name": "Process Injection",                "tactic": "Privilege Escalation"},
            {"id": "T1547",   "name": "Boot/Logon Autostart Execution",   "tactic": "Persistence"},
        ],
        IOCType.EMAIL: [
            {"id": "T1566.001", "name": "Spearphishing Attachment",       "tactic": "Initial Access"},
            {"id": "T1598",   "name": "Phishing for Information",         "tactic": "Reconnaissance"},
            {"id": "T1534",   "name": "Internal Spearphishing",           "tactic": "Lateral Movement"},
        ],
    }

    @classmethod
    def rotate_primary_index(cls, ioc_value: str, technique_count: int) -> int:
        """
        Deterministically pick a technique index based on the IOC value hash.

        This ensures that nodes of the same IOC type are spread across multiple
        tactic colours instead of all being assigned the first entry.
        OWASP A02: Uses SHA-256 (not MD5) for the rotation hash.
        """
        digest = int(hashlib.sha256(ioc_value.encode()).hexdigest(), 16)
        return digest % technique_count

    @classmethod
    def map_techniques(cls, event: CorrelatedEvent) -> List[str]:
        """
        Map event to MITRE ATT&CK techniques, rotating primary technique
        so different nodes of the same type receive different tactic colours.
        """
        all_techniques = cls.TECHNIQUE_MAPPING.get(event.type, [])
        if not all_techniques:
            return []

        # Rotate primary to front based on IOC value hash
        primary_idx = cls.rotate_primary_index(event.value, len(all_techniques))
        rotated = all_techniques[primary_idx:] + all_techniques[:primary_idx]

        technique_ids = [t["id"] for t in rotated
                         if _validate_technique_id(t["id"])]  # OWASP A04
        logger.debug("mitre_mapped", ioc_type=event.type, techniques=technique_ids)
        return technique_ids

    @classmethod
    def map_tactics(cls, event: CorrelatedEvent) -> List[str]:
        """Map event to MITRE ATT&CK tactics (all unique tactics for this IOC type)."""
        techniques = cls.TECHNIQUE_MAPPING.get(event.type, [])
        tactics = list(set(t["tactic"] for t in techniques))
        logger.debug("mitre_tactics_mapped", ioc_type=event.type, tactics=tactics)
        return tactics

    @classmethod
    def get_technique_details(cls, technique_id: str) -> Dict[str, Any]:
        """Get details for a specific MITRE technique."""
        # OWASP A04: validate before lookup
        if not _validate_technique_id(technique_id):
            logger.warning("invalid_technique_id_lookup", technique_id=technique_id)
            return {}
        for techniques in cls.TECHNIQUE_MAPPING.values():
            for tech in techniques:
                if tech["id"] == technique_id:
                    return tech
        return {}

    @classmethod
    def enrich_with_mitre(cls, event: CorrelatedEvent) -> CorrelatedEvent:
        """Enrich event with MITRE ATT&CK mappings."""
        techniques = cls.map_techniques(event)
        event_data = event.model_dump()
        event_data["mitre_techniques"] = techniques
        return CorrelatedEvent(**event_data)
