"""
Clean bracket artifacts from existing documents and populate rich threat clusters & incidents.
"""
import asyncio
import datetime
import uuid
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from motor.motor_asyncio import AsyncIOMotorClient
from security.sanitizer import Sanitizer


def clean_doc(doc):
    """Recursively clean bracket artifacts from document strings."""
    if isinstance(doc, str):
        return Sanitizer.clean_artifacts(doc)
    elif isinstance(doc, list):
        return [clean_doc(x) for x in doc]
    elif isinstance(doc, dict):
        return {k: clean_doc(v) for k, v in doc.items()}
    return doc


async def main():
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    db = client["threat_intel"]

    print("Cleaning existing database artifacts...")
    for col_name in ["events", "alerts", "detections", "incidents"]:
        col = db[col_name]
        async for doc in col.find({}):
            doc_id = doc["_id"]
            cleaned = clean_doc(doc)
            del cleaned["_id"]
            await col.replace_one({"_id": doc_id}, cleaned)
    print("Existing documents cleaned.")

    now = datetime.datetime.utcnow()

    # =========================================================================
    # CLUSTER 1: APT29 / Midnight Blizzard (Cloud Credential & Token Abuse)
    # =========================================================================
    c1_id = "cluster-apt29-cloud-abuse"
    c1_events = [
        {
            "event_id": "c1-evt-1",
            "type": "ip",
            "value": "185.220.101.5",
            "source": "Abuse.ch",
            "timestamp": now - datetime.timedelta(hours=4),
            "confidence": 0.94,
            "geo_data": {"country": "Netherlands", "city": "Amsterdam", "is_private": False},
            "asn_data": {"asn": 60729, "organization": "Tor Exit Network"},
            "whois_data": {"registrar": "Tucows", "newly_registered": False},
            "correlation_id": c1_id,
            "related_events": ["c1-evt-2", "c1-evt-3", "c1-evt-4", "c1-evt-5"],
            "correlation_strength": 0.92,
            "mitre_techniques": ["T1071.001", "T1090.003", "T1566.002"],
            "risk_score": 8.7,
        },
        {
            "event_id": "c1-evt-2",
            "type": "ip",
            "value": "194.26.29.112",
            "source": "AlienVault OTX",
            "timestamp": now - datetime.timedelta(hours=4, minutes=10),
            "confidence": 0.91,
            "geo_data": {"country": "Germany", "city": "Frankfurt", "is_private": False},
            "asn_data": {"asn": 44592, "organization": "Host Europe GmbH"},
            "whois_data": {"registrar": "Key-Systems", "newly_registered": False},
            "correlation_id": c1_id,
            "related_events": ["c1-evt-1", "c1-evt-3", "c1-evt-4"],
            "correlation_strength": 0.88,
            "mitre_techniques": ["T1071.001", "T1528"],
            "risk_score": 8.4,
        },
        {
            "event_id": "c1-evt-3",
            "type": "domain",
            "value": "cloud-sync-identity.net",
            "source": "OpenPhish",
            "timestamp": now - datetime.timedelta(hours=3, minutes=45),
            "confidence": 0.96,
            "geo_data": {"country": "United States", "city": "Ashburn", "is_private": False},
            "asn_data": {"asn": 16509, "organization": "Amazon.com, Inc."},
            "whois_data": {"registrar": "NameCheap, Inc.", "newly_registered": True},
            "correlation_id": c1_id,
            "related_events": ["c1-evt-1", "c1-evt-2", "c1-evt-4", "c1-evt-5"],
            "correlation_strength": 0.95,
            "mitre_techniques": ["T1566.002", "T1528", "T1562.001"],
            "risk_score": 9.1,
        },
        {
            "event_id": "c1-evt-4",
            "type": "domain",
            "value": "login-microsoftonline-auth.com",
            "source": "OpenPhish",
            "timestamp": now - datetime.timedelta(hours=3, minutes=30),
            "confidence": 0.98,
            "geo_data": {"country": "United States", "city": "Boardman", "is_private": False},
            "asn_data": {"asn": 16509, "organization": "Amazon.com, Inc."},
            "whois_data": {"registrar": "NameCheap, Inc.", "newly_registered": True},
            "correlation_id": c1_id,
            "related_events": ["c1-evt-1", "c1-evt-3", "c1-evt-5"],
            "correlation_strength": 0.96,
            "mitre_techniques": ["T1566.002", "T1528"],
            "risk_score": 9.3,
        },
        {
            "event_id": "c1-evt-5",
            "type": "hash",
            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "source": "AlienVault OTX",
            "timestamp": now - datetime.timedelta(hours=3),
            "confidence": 0.89,
            "geo_data": None,
            "asn_data": None,
            "whois_data": None,
            "correlation_id": c1_id,
            "related_events": ["c1-evt-1", "c1-evt-3", "c1-evt-4"],
            "correlation_strength": 0.85,
            "mitre_techniques": ["T1059.001", "T1080"],
            "risk_score": 8.0,
        }
    ]

    c1_alert = {
        "alert_id": "alt-apt29-001",
        "severity": "Critical",
        "risk_score": 9.2,
        "explanation": [
            "Alert severity: Critical (risk score: 9.20/10)",
            "Indicator detected from OpenPhish & AlienVault threat feeds",
            "High confidence indicator (confidence: 0.96)",
            "Correlated with 4 other events in APT29 infrastructure cluster (strength: 0.95)",
            "Mapped to MITRE ATT&CK techniques: T1566.002, T1528, T1071.001, T1562.001, T1080",
            "Newly registered domain spoofing Microsoft cloud login portal",
            "Geographic location: Ashburn, United States (Tor & AWS hosting)"
        ],
        "risk_breakdown": {
            "total_score": 9.2,
            "factors": {
                "source_confidence": {"value": 0.96, "weight": 4.0, "contribution": 3.84},
                "correlation_strength": {"value": 0.95, "weight": 2.0, "contribution": 1.90},
                "mitre_techniques": {"count": 5, "weight": 1.5, "contribution": 1.50},
                "enrichment": {"completeness": 0.90, "weight": 0.5, "contribution": 0.45},
                "newly_registered_domain": {"flagged": True, "weight": 2.0, "contribution": 1.51}
            }
        },
        "mitre_techniques": ["T1566.002", "T1528", "T1071.001", "T1562.001", "T1080"],
        "related_events": ["cloud-sync-identity.net", "c1-evt-1", "c1-evt-2", "c1-evt-4", "c1-evt-5"],
        "timestamp": now - datetime.timedelta(hours=3, minutes=30),
        "analyst_summary": (
            "**Threat Intelligence Summary**\n\n"
            "Total Alerts: 5 in Cluster\n"
            "- Critical Severity: 2\n"
            "- High Severity: 3\n"
            "- Threat Actor: APT29 / Midnight Blizzard\n\n"
            "**MITRE ATT&CK Techniques Detected:** 5\n"
            "Techniques: T1071.001, T1080, T1090.003, T1528, T1566.002\n\n"
            "**Key Findings:**\n"
            "1. Adversary deployed freshly registered typosquatted Microsoft 365 login portals.\n"
            "2. Traffic routed through dual-hop Tor exit nodes and AWS cloud proxies.\n"
            "3. Active attempts to bypass multi-factor authentication via OAuth device code flow.\n\n"
            "**Recommended Actions:**\n"
            "- Revoke all refresh tokens for affected tenant identities immediately.\n"
            "- Block indicated IP addresses at edge perimeter and DNS resolvers.\n"
            "- Enforce conditional access policies restricting Tor exit nodes."
        )
    }

    # =========================================================================
    # CLUSTER 2: LockBit 3.0 (Ransomware Staging & Exfiltration)
    # =========================================================================
    c2_id = "cluster-lockbit3-ransomware"
    c2_events = [
        {
            "event_id": "c2-evt-1",
            "type": "ip",
            "value": "45.154.255.89",
            "source": "Abuse.ch",
            "timestamp": now - datetime.timedelta(hours=6),
            "confidence": 0.95,
            "geo_data": {"country": "Russia", "city": "Moscow", "is_private": False},
            "asn_data": {"asn": 49981, "organization": "WorldStream B.V."},
            "whois_data": {"registrar": "RUCENTER-REG-FID", "newly_registered": False},
            "correlation_id": c2_id,
            "related_events": ["c2-evt-2", "c2-evt-3", "c2-evt-4"],
            "correlation_strength": 0.94,
            "mitre_techniques": ["T1048", "T1071", "T1486"],
            "risk_score": 9.4,
        },
        {
            "event_id": "c2-evt-2",
            "type": "ip",
            "value": "91.240.118.172",
            "source": "AlienVault OTX",
            "timestamp": now - datetime.timedelta(hours=5, minutes=45),
            "confidence": 0.92,
            "geo_data": {"country": "Bulgaria", "city": "Sofia", "is_private": False},
            "asn_data": {"asn": 200000, "organization": "Delta Telecom Ltd"},
            "whois_data": {"registrar": "REG.RU LLC", "newly_registered": False},
            "correlation_id": c2_id,
            "related_events": ["c2-evt-1", "c2-evt-3", "c2-evt-4"],
            "correlation_strength": 0.91,
            "mitre_techniques": ["T1071", "T1562.001"],
            "risk_score": 8.9,
        },
        {
            "event_id": "c2-evt-3",
            "type": "domain",
            "value": "lockbit-decryptor-gateway.top",
            "source": "Abuse.ch",
            "timestamp": now - datetime.timedelta(hours=5, minutes=30),
            "confidence": 0.97,
            "geo_data": {"country": "Seychelles", "city": "Victoria", "is_private": False},
            "asn_data": {"asn": 51167, "organization": "Contabo GmbH"},
            "whois_data": {"registrar": "NiceNIC INTERNATIONAL", "newly_registered": True},
            "correlation_id": c2_id,
            "related_events": ["c2-evt-1", "c2-evt-2", "c2-evt-4"],
            "correlation_strength": 0.96,
            "mitre_techniques": ["T1486", "T1499"],
            "risk_score": 9.5,
        },
        {
            "event_id": "c2-evt-4",
            "type": "hash",
            "value": "a8f5f167f44f4964e6c998dee827110c7b52009b",
            "source": "AlienVault OTX",
            "timestamp": now - datetime.timedelta(hours=5, minutes=15),
            "confidence": 0.96,
            "geo_data": None,
            "asn_data": None,
            "whois_data": None,
            "correlation_id": c2_id,
            "related_events": ["c2-evt-1", "c2-evt-2", "c2-evt-3"],
            "correlation_strength": 0.93,
            "mitre_techniques": ["T1059.001", "T1486", "T1562.001"],
            "risk_score": 9.6,
        }
    ]

    c2_alert = {
        "alert_id": "alt-lockbit3-002",
        "severity": "Critical",
        "risk_score": 9.55,
        "explanation": [
            "Alert severity: Critical (risk score: 9.55/10)",
            "Active LockBit 3.0 ransomware affiliate payload detected",
            "High confidence threat indicator (confidence: 0.97)",
            "Correlated across 4 nodes in extortion infrastructure (strength: 0.96)",
            "Mapped to MITRE ATT&CK techniques: T1486, T1059.001, T1562.001, T1048, T1071",
            "Stealbit exfiltration staging IP and ransom payment portal confirmed",
            "Geographic location: Moscow, Russia & Sofia, Bulgaria"
        ],
        "risk_breakdown": {
            "total_score": 9.55,
            "factors": {
                "source_confidence": {"value": 0.97, "weight": 4.0, "contribution": 3.88},
                "correlation_strength": {"value": 0.96, "weight": 2.0, "contribution": 1.92},
                "mitre_techniques": {"count": 5, "weight": 1.5, "contribution": 1.50},
                "enrichment": {"completeness": 0.85, "weight": 0.5, "contribution": 0.42},
                "newly_registered_domain": {"flagged": True, "weight": 2.0, "contribution": 1.83}
            }
        },
        "mitre_techniques": ["T1486", "T1059.001", "T1562.001", "T1048", "T1071"],
        "related_events": ["lockbit-decryptor-gateway.top", "c2-evt-1", "c2-evt-2", "c2-evt-4"],
        "timestamp": now - datetime.timedelta(hours=5, minutes=20),
        "analyst_summary": (
            "**Threat Intelligence Summary**\n\n"
            "Total Alerts: 4 in Cluster\n"
            "- Critical Severity: 3\n"
            "- High Severity: 1\n"
            "- Threat Actor: LockBit 3.0 Affiliate Group\n\n"
            "**MITRE ATT&CK Techniques Detected:** 5\n"
            "Techniques: T1048, T1059.001, T1071, T1486, T1562.001\n\n"
            "**Key Findings:**\n"
            "1. PowerShell commands invoked to disable Microsoft Defender (`Set-MpPreference -DisableRealtimeMonitoring`).\n"
            "2. Volume Shadow Copies targeted via `vssadmin delete shadows /all /quiet`.\n"
            "3. Multi-threaded exfiltration tool (Stealbit) detected connecting to 45.154.255.89.\n\n"
            "**Recommended Actions:**\n"
            "- Immediately isolate affected servers from the core VLAN.\n"
            "- Block outbound connections to 45.154.255.89 and 91.240.118.172.\n"
            "- Verify offline immutable backup integrity."
        )
    }

    # =========================================================================
    # CLUSTER 3: Volt Typhoon (Critical Infrastructure Living-off-the-Land)
    # =========================================================================
    c3_id = "cluster-volt-typhoon"
    c3_events = [
        {
            "event_id": "c3-evt-1",
            "type": "ip",
            "value": "198.51.100.42",
            "source": "AlienVault OTX",
            "timestamp": now - datetime.timedelta(hours=8),
            "confidence": 0.88,
            "geo_data": {"country": "United States", "city": "Dallas", "is_private": False},
            "asn_data": {"asn": 7018, "organization": "AT&T Services, Inc."},
            "whois_data": {"registrar": "ARIN", "newly_registered": False},
            "correlation_id": c3_id,
            "related_events": ["c3-evt-2", "c3-evt-3", "c3-evt-4"],
            "correlation_strength": 0.86,
            "mitre_techniques": ["T1190", "T1090.003", "T1547"],
            "risk_score": 8.2,
        },
        {
            "event_id": "c3-evt-2",
            "type": "ip",
            "value": "203.0.113.78",
            "source": "Abuse.ch",
            "timestamp": now - datetime.timedelta(hours=7, minutes=45),
            "confidence": 0.85,
            "geo_data": {"country": "Singapore", "city": "Singapore", "is_private": False},
            "asn_data": {"asn": 4657, "organization": "StarHub Ltd"},
            "whois_data": {"registrar": "APNIC", "newly_registered": False},
            "correlation_id": c3_id,
            "related_events": ["c3-evt-1", "c3-evt-3"],
            "correlation_strength": 0.82,
            "mitre_techniques": ["T1016", "T1046"],
            "risk_score": 7.9,
        },
        {
            "event_id": "c3-evt-3",
            "type": "domain",
            "value": "gateway-telemetry-sync.info",
            "source": "AlienVault OTX",
            "timestamp": now - datetime.timedelta(hours=7, minutes=15),
            "confidence": 0.90,
            "geo_data": {"country": "Japan", "city": "Tokyo", "is_private": False},
            "asn_data": {"asn": 2516, "organization": "KDDI Corporation"},
            "whois_data": {"registrar": "GMO Internet, Inc.", "newly_registered": True},
            "correlation_id": c3_id,
            "related_events": ["c3-evt-1", "c3-evt-2", "c3-evt-4"],
            "correlation_strength": 0.89,
            "mitre_techniques": ["T1071.001", "T1070", "T1190"],
            "risk_score": 8.5,
        },
        {
            "event_id": "c3-evt-4",
            "type": "hash",
            "value": "d41d8cd98f00b204e9800998ecf8427e02b8a1c9",
            "source": "AlienVault OTX",
            "timestamp": now - datetime.timedelta(hours=6, minutes=50),
            "confidence": 0.87,
            "geo_data": None,
            "asn_data": None,
            "whois_data": None,
            "correlation_id": c3_id,
            "related_events": ["c3-evt-1", "c3-evt-3"],
            "correlation_strength": 0.84,
            "mitre_techniques": ["T1505.003", "T1070"],
            "risk_score": 8.0,
        }
    ]

    c3_alert = {
        "alert_id": "alt-volt-003",
        "severity": "High",
        "risk_score": 8.35,
        "explanation": [
            "Alert severity: High (risk score: 8.35/10)",
            "Volt Typhoon stealth living-off-the-land infrastructure detected",
            "High confidence IOC (confidence: 0.90)",
            "Correlated across 4 nodes in compromised SOHO router mesh (strength: 0.89)",
            "Mapped to MITRE ATT&CK techniques: T1190, T1090.003, T1070, T1016, T1505.003",
            "Geographic location: Dallas, Singapore, Tokyo (Compromised Edge Gateways)"
        ],
        "risk_breakdown": {
            "total_score": 8.35,
            "factors": {
                "source_confidence": {"value": 0.90, "weight": 4.0, "contribution": 3.60},
                "correlation_strength": {"value": 0.89, "weight": 2.0, "contribution": 1.78},
                "mitre_techniques": {"count": 5, "weight": 1.5, "contribution": 1.50},
                "enrichment": {"completeness": 0.80, "weight": 0.5, "contribution": 0.40},
                "newly_registered_domain": {"flagged": True, "weight": 2.0, "contribution": 1.07}
            }
        },
        "mitre_techniques": ["T1190", "T1090.003", "T1070", "T1016", "T1505.003"],
        "related_events": ["gateway-telemetry-sync.info", "c3-evt-1", "c3-evt-2", "c3-evt-4"],
        "timestamp": now - datetime.timedelta(hours=7),
        "analyst_summary": (
            "**Threat Intelligence Summary**\n\n"
            "Total Alerts: 4 in Cluster\n"
            "- High Severity: 4\n"
            "- Threat Actor: Volt Typhoon (Bronze Silhouette)\n\n"
            "**MITRE ATT&CK Techniques Detected:** 5\n"
            "Techniques: T1016, T1070, T1090.003, T1190, T1505.003\n\n"
            "**Key Findings:**\n"
            "1. Exploitation of CVE-2023-46805 / CVE-2024-21887 on edge gateway.\n"
            "2. Living-off-the-land commands observed: `wmic`, `netsh`, and `certutil`.\n"
            "3. Web shell placed in appliance web root for persistent proxying.\n\n"
            "**Recommended Actions:**\n"
            "- Patch edge VPN/firewall firmware immediately.\n"
            "- Review admin session logs for unauthorized proxy tunnel commands.\n"
            "- Rotate all RADIUS and LDAP service account credentials."
        )
    }

    # =========================================================================
    # CLUSTER 4: DarkGate Loader (Phishing Malspam Delivery)
    # =========================================================================
    c4_id = "cluster-darkgate-malspam"
    c4_events = [
        {
            "event_id": "c4-evt-1",
            "type": "ip",
            "value": "89.208.107.198",
            "source": "Abuse.ch",
            "timestamp": now - datetime.timedelta(hours=10),
            "confidence": 0.86,
            "geo_data": {"country": "Russia", "city": "Saint Petersburg", "is_private": False},
            "asn_data": {"asn": 48282, "organization": "Selectel Network"},
            "whois_data": {"registrar": "RU-CENTER", "newly_registered": False},
            "correlation_id": c4_id,
            "related_events": ["c4-evt-2", "c4-evt-3", "c4-evt-4"],
            "correlation_strength": 0.88,
            "mitre_techniques": ["T1071.001", "T1105", "T1055"],
            "risk_score": 7.8,
        },
        {
            "event_id": "c4-evt-2",
            "type": "domain",
            "value": "update-sys-service.xyz",
            "source": "OpenPhish",
            "timestamp": now - datetime.timedelta(hours=9, minutes=30),
            "confidence": 0.91,
            "geo_data": {"country": "United States", "city": "Newark", "is_private": False},
            "asn_data": {"asn": 63949, "organization": "Akamai Connected Cloud"},
            "whois_data": {"registrar": "NameSilo, LLC", "newly_registered": True},
            "correlation_id": c4_id,
            "related_events": ["c4-evt-1", "c4-evt-3", "c4-evt-4"],
            "correlation_strength": 0.89,
            "mitre_techniques": ["T1566.001", "T1204.002", "T1105"],
            "risk_score": 8.1,
        },
        {
            "event_id": "c4-evt-3",
            "type": "url",
            "value": "http://89.208.107.198/autoit/load.php",
            "source": "Abuse.ch",
            "timestamp": now - datetime.timedelta(hours=9, minutes=15),
            "confidence": 0.94,
            "geo_data": {"country": "Russia", "city": "Saint Petersburg", "is_private": False},
            "asn_data": {"asn": 48282, "organization": "Selectel Network"},
            "whois_data": None,
            "correlation_id": c4_id,
            "related_events": ["c4-evt-1", "c4-evt-2", "c4-evt-4"],
            "correlation_strength": 0.92,
            "mitre_techniques": ["T1105", "T1059.001"],
            "risk_score": 8.6,
        },
        {
            "event_id": "c4-evt-4",
            "type": "hash",
            "value": "c3ab8ff13720e8ad9047dd39466b3c89b71e21f4",
            "source": "AlienVault OTX",
            "timestamp": now - datetime.timedelta(hours=8, minutes=50),
            "confidence": 0.89,
            "geo_data": None,
            "asn_data": None,
            "whois_data": None,
            "correlation_id": c4_id,
            "related_events": ["c4-evt-1", "c4-evt-2", "c4-evt-3"],
            "correlation_strength": 0.87,
            "mitre_techniques": ["T1055", "T1204.002"],
            "risk_score": 7.9,
        }
    ]

    c4_alert = {
        "alert_id": "alt-darkgate-004",
        "severity": "High",
        "risk_score": 8.15,
        "explanation": [
            "Alert severity: High (risk score: 8.15/10)",
            "DarkGate modular loader C2 and payload dropper confirmed",
            "High confidence indicator (confidence: 0.91)",
            "Correlated across 4 nodes in malspam delivery network (strength: 0.89)",
            "Mapped to MITRE ATT&CK techniques: T1566.001, T1204.002, T1105, T1055, T1071.001",
            "Geographic location: Saint Petersburg, Russia & Newark, United States"
        ],
        "risk_breakdown": {
            "total_score": 8.15,
            "factors": {
                "source_confidence": {"value": 0.91, "weight": 4.0, "contribution": 3.64},
                "correlation_strength": {"value": 0.89, "weight": 2.0, "contribution": 1.78},
                "mitre_techniques": {"count": 5, "weight": 1.5, "contribution": 1.50},
                "enrichment": {"completeness": 0.75, "weight": 0.5, "contribution": 0.38},
                "newly_registered_domain": {"flagged": True, "weight": 2.0, "contribution": 0.85}
            }
        },
        "mitre_techniques": ["T1566.001", "T1204.002", "T1105", "T1055", "T1071.001"],
        "related_events": ["update-sys-service.xyz", "c4-evt-1", "c4-evt-3", "c4-evt-4"],
        "timestamp": now - datetime.timedelta(hours=9),
        "analyst_summary": (
            "**Threat Intelligence Summary**\n\n"
            "Total Alerts: 4 in Cluster\n"
            "- High Severity: 3\n"
            "- Medium Severity: 1\n"
            "- Malware Family: DarkGate v5 Loader\n\n"
            "**MITRE ATT&CK Techniques Detected:** 5\n"
            "Techniques: T1055, T1071.001, T1105, T1204.002, T1566.001\n\n"
            "**Key Findings:**\n"
            "1. Phishing email delivered ZIP attachment containing VBS script dropper.\n"
            "2. Script executes AutoIt interpreter binary that injects shellcode into `cscript.exe`.\n"
            "3. DarkGate agent performs keystroke logging, token stealing, and hVNC remote control.\n\n"
            "**Recommended Actions:**\n"
            "- Block `update-sys-service.xyz` and `89.208.107.198` on secure web gateways.\n"
            "- Quarantine inbound email subject lines referencing 'Payment Overdue Notification'.\n"
            "- Run EDR scan on any endpoint that resolved the malicious URL."
        )
    }

    # =========================================================================
    # CLUSTER 5: Mirai Variant / Botnet Port Scanning
    # =========================================================================
    c5_id = "cluster-mirai-botnet"
    c5_events = [
        {
            "event_id": "c5-evt-1",
            "type": "ip",
            "value": "185.196.220.14",
            "source": "Abuse.ch",
            "timestamp": now - datetime.timedelta(hours=14),
            "confidence": 0.78,
            "geo_data": {"country": "Poland", "city": "Warsaw", "is_private": False},
            "asn_data": {"asn": 49453, "organization": "Global Telecommunication Solutions"},
            "whois_data": {"registrar": "NASK", "newly_registered": False},
            "correlation_id": c5_id,
            "related_events": ["c5-evt-2", "c5-evt-3"],
            "correlation_strength": 0.74,
            "mitre_techniques": ["T1595", "T1046"],
            "risk_score": 6.2,
        },
        {
            "event_id": "c5-evt-2",
            "type": "ip",
            "value": "103.145.13.22",
            "source": "Abuse.ch",
            "timestamp": now - datetime.timedelta(hours=13, minutes=30),
            "confidence": 0.75,
            "geo_data": {"country": "Vietnam", "city": "Hanoi", "is_private": False},
            "asn_data": {"asn": 7552, "organization": "Viettel Group"},
            "whois_data": {"registrar": "VNNIC", "newly_registered": False},
            "correlation_id": c5_id,
            "related_events": ["c5-evt-1", "c5-evt-3"],
            "correlation_strength": 0.72,
            "mitre_techniques": ["T1595", "T1190"],
            "risk_score": 5.9,
        },
        {
            "event_id": "c5-evt-3",
            "type": "url",
            "value": "http://185.196.220.14/bins/mirai.arm7",
            "source": "Abuse.ch",
            "timestamp": now - datetime.timedelta(hours=13),
            "confidence": 0.82,
            "geo_data": {"country": "Poland", "city": "Warsaw", "is_private": False},
            "asn_data": {"asn": 49453, "organization": "Global Telecommunication Solutions"},
            "whois_data": None,
            "correlation_id": c5_id,
            "related_events": ["c5-evt-1", "c5-evt-2"],
            "correlation_strength": 0.76,
            "mitre_techniques": ["T1105", "T1499"],
            "risk_score": 6.8,
        }
    ]

    c5_alert = {
        "alert_id": "alt-mirai-005",
        "severity": "Medium",
        "risk_score": 6.30,
        "explanation": [
            "Alert severity: Medium (risk score: 6.30/10)",
            "Automated IoT botnet scanner probing exposed administrative services",
            "Medium confidence indicator (confidence: 0.78)",
            "Correlated across 3 nodes in scanning swarm (strength: 0.74)",
            "Mapped to MITRE ATT&CK techniques: T1595, T1046, T1190, T1105, T1499",
            "Geographic location: Warsaw, Poland & Hanoi, Vietnam"
        ],
        "risk_breakdown": {
            "total_score": 6.30,
            "factors": {
                "source_confidence": {"value": 0.78, "weight": 4.0, "contribution": 3.12},
                "correlation_strength": {"value": 0.74, "weight": 2.0, "contribution": 1.48},
                "mitre_techniques": {"count": 5, "weight": 1.5, "contribution": 1.50},
                "enrichment": {"completeness": 0.60, "weight": 0.5, "contribution": 0.30},
                "newly_registered_domain": {"flagged": False, "weight": 2.0, "contribution": 0.0}
            }
        },
        "mitre_techniques": ["T1595", "T1046", "T1190", "T1105", "T1499"],
        "related_events": ["185.196.220.14", "c5-evt-2", "c5-evt-3"],
        "timestamp": now - datetime.timedelta(hours=13),
        "analyst_summary": (
            "**Threat Intelligence Summary**\n\n"
            "Total Alerts: 3 in Cluster\n"
            "- Medium Severity: 3\n"
            "- Threat Actor: Mirai Variant Botnet\n\n"
            "**MITRE ATT&CK Techniques Detected:** 5\n"
            "Techniques: T1046, T1105, T1190, T1499, T1595\n\n"
            "**Key Findings:**\n"
            "1. Rapid TCP SYN probing across ports 23, 80, 8080, and 37215.\n"
            "2. Automated dictionary brute force using default router credentials.\n"
            "3. Dropper URL stages compiled ARM7 and MIPS binaries.\n\n"
            "**Recommended Actions:**\n"
            "- Ensure external WAN management interfaces are disabled on edge devices.\n"
            "- Add scanning IP block to perimeter firewall drop rules."
        )
    }

    # Insert events and alerts
    all_clusters_events = c1_events + c2_events + c3_events + c4_events + c5_events
    all_alerts = [c1_alert, c2_alert, c3_alert, c4_alert, c5_alert]

    print(f"Upserting {len(all_clusters_events)} cluster events...")
    for evt in all_clusters_events:
        await db["events"].replace_one({"event_id": evt["event_id"]}, evt, upsert=True)

    print(f"Upserting {len(all_alerts)} alerts...")
    for alt in all_alerts:
        await db["alerts"].replace_one({"alert_id": alt["alert_id"]}, alt, upsert=True)

    # =========================================================================
    # DETECTIONS & SECURITY INCIDENTS
    # =========================================================================
    detections = [
        {
            "detection_id": "det-2026-001",
            "log_type": "auth",
            "matched_ioc": "185.220.101.5",
            "matched_field": "source_ip",
            "ioc_source": "Abuse.ch",
            "ioc_type": "ip",
            "confidence": 0.94,
            "log_event": {"user": "admin", "service": "azure-ad-connect", "status": "failed"},
            "threat_event_id": "c1-evt-1",
            "timestamp": now - datetime.timedelta(hours=3, minutes=25)
        },
        {
            "detection_id": "det-2026-002",
            "log_type": "nginx",
            "matched_ioc": "cloud-sync-identity.net",
            "matched_field": "http_referer",
            "ioc_source": "OpenPhish",
            "ioc_type": "domain",
            "confidence": 0.96,
            "log_event": {"path": "/oauth2/token", "status": 200, "client_ip": "185.220.101.5"},
            "threat_event_id": "c1-evt-3",
            "timestamp": now - datetime.timedelta(hours=3, minutes=20)
        },
        {
            "detection_id": "det-2026-003",
            "log_type": "auth",
            "matched_ioc": "45.154.255.89",
            "matched_field": "destination_ip",
            "ioc_source": "Abuse.ch",
            "ioc_type": "ip",
            "confidence": 0.95,
            "log_event": {"process": "powershell.exe", "host": "fileserver-02", "bytes_sent": 48291040},
            "threat_event_id": "c2-evt-1",
            "timestamp": now - datetime.timedelta(hours=5, minutes=10)
        },
        {
            "detection_id": "det-2026-004",
            "log_type": "dns",
            "matched_ioc": "lockbit-decryptor-gateway.top",
            "matched_field": "query_name",
            "ioc_source": "Abuse.ch",
            "ioc_type": "domain",
            "confidence": 0.97,
            "log_event": {"client": "192.168.10.45", "query_type": "A"},
            "threat_event_id": "c2-evt-3",
            "timestamp": now - datetime.timedelta(hours=5, minutes=5)
        },
        {
            "detection_id": "det-2026-005",
            "log_type": "nginx",
            "matched_ioc": "198.51.100.42",
            "matched_field": "remote_addr",
            "ioc_source": "AlienVault OTX",
            "ioc_type": "ip",
            "confidence": 0.88,
            "log_event": {"uri": "/dana-na/auth/url_default/welcome.cgi", "status": 200},
            "threat_event_id": "c3-evt-1",
            "timestamp": now - datetime.timedelta(hours=7, minutes=30)
        },
        {
            "detection_id": "det-2026-006",
            "log_type": "auth",
            "matched_ioc": "89.208.107.198",
            "matched_field": "remote_host",
            "ioc_source": "Abuse.ch",
            "ioc_type": "ip",
            "confidence": 0.86,
            "log_event": {"user": "finance01", "workstation": "WS-FIN-09"},
            "threat_event_id": "c4-evt-1",
            "timestamp": now - datetime.timedelta(hours=9, minutes=10)
        },
        {
            "detection_id": "det-2026-007",
            "log_type": "auth",
            "matched_ioc": "185.196.220.14",
            "matched_field": "src_ip",
            "ioc_source": "Abuse.ch",
            "ioc_type": "ip",
            "confidence": 0.78,
            "log_event": {"port": 22, "service": "sshd", "attempts": 142},
            "threat_event_id": "c5-evt-1",
            "timestamp": now - datetime.timedelta(hours=13, minutes=15)
        }
    ]

    print(f"Upserting {len(detections)} detections...")
    for det in detections:
        await db["detections"].replace_one({"detection_id": det["detection_id"]}, det, upsert=True)

    incidents = [
        {
            "incident_id": "INC-2026-0891",
            "title": "APT29 Cloud Token Replay & Mailbox Search Activity",
            "description": "Adversary accessed corporate Azure AD tenant using compromised OAuth tokens originating from Tor exit node.",
            "status": "Open",
            "severity": "Critical",
            "assigned_to": "Analyst",
            "related_detections": ["det-2026-001", "det-2026-002"],
            "related_alerts": ["alt-apt29-001"],
            "created_at": now - datetime.timedelta(hours=3, minutes=20),
            "updated_at": now - datetime.timedelta(hours=1, minutes=15),
            "notes": [
                {
                    "author": "Analyst",
                    "content": "Alert triggered on malicious OAuth redirect domain matching OpenPhish feed. Target identity belongs to Cloud Operations team.",
                    "timestamp": now - datetime.timedelta(hours=3, minutes=15)
                },
                {
                    "author": "Analyst",
                    "content": "Revoked all active Microsoft 365 sessions and triggered password reset. Analyzing unified audit logs for file downloads.",
                    "timestamp": now - datetime.timedelta(hours=2, minutes=30)
                },
                {
                    "author": "Analyst",
                    "content": "Identified 4 mailbox search queries targeting 'VPN configuration' and 'AWS production secrets'. In-depth triage ongoing.",
                    "timestamp": now - datetime.timedelta(hours=1, minutes=15)
                }
            ]
        },
        {
            "incident_id": "INC-2026-0892",
            "title": "LockBit 3.0 Ransomware Pre-Encryption Staging on Fileserver-02",
            "description": "Mass data transfer to Russian bulletproof hosting ASN accompanied by attempted volume shadow copy deletion.",
            "status": "In Progress",
            "severity": "Critical",
            "assigned_to": "Analyst",
            "related_detections": ["det-2026-003", "det-2026-004"],
            "related_alerts": ["alt-lockbit3-002"],
            "created_at": now - datetime.timedelta(hours=5, minutes=10),
            "updated_at": now - datetime.timedelta(hours=2),
            "notes": [
                {
                    "author": "Analyst",
                    "content": "Host fileserver-02 isolated from network via EDR agent. Memory dump and artifact capture initiated.",
                    "timestamp": now - datetime.timedelta(hours=5)
                },
                {
                    "author": "Analyst",
                    "content": "Confirmed Stealbit payload signature in C:\\Users\\Public\\svchost.exe. Exfiltration pipe severed at firewall.",
                    "timestamp": now - datetime.timedelta(hours=3, minutes=45)
                },
                {
                    "author": "Analyst",
                    "content": "VSS shadow copies verified intact on storage array. Performing forensic diff of staged archive files.",
                    "timestamp": now - datetime.timedelta(hours=2)
                }
            ]
        },
        {
            "incident_id": "INC-2026-0893",
            "title": "Volt Typhoon Living-off-the-Land on Perimeter Edge Gateway",
            "description": "Suspicious web shell deployment and unauthorized proxy commands executed on edge SSL VPN appliance.",
            "status": "In Progress",
            "severity": "High",
            "assigned_to": "Analyst",
            "related_detections": ["det-2026-005"],
            "related_alerts": ["alt-volt-003"],
            "created_at": now - datetime.timedelta(hours=7, minutes=30),
            "updated_at": now - datetime.timedelta(hours=4),
            "notes": [
                {
                    "author": "Analyst",
                    "content": "Signature match on Fortinet zero-day mitigation telemetry. Correlated with AlienVault OTX infrastructure feed.",
                    "timestamp": now - datetime.timedelta(hours=7, minutes=20)
                },
                {
                    "author": "Analyst",
                    "content": "Removed unauthorized web shell payload. Restricting management portal access strictly to dedicated internal jumpbox subnet.",
                    "timestamp": now - datetime.timedelta(hours=4)
                }
            ]
        },
        {
            "incident_id": "INC-2026-0894",
            "title": "DarkGate Loader Malspam Delivery via Invoice Attachment",
            "description": "Phishing campaign delivering weaponized VBScript payload to accounts payable department.",
            "status": "Resolved",
            "severity": "High",
            "assigned_to": "Analyst",
            "related_detections": ["det-2026-006"],
            "related_alerts": ["alt-darkgate-004"],
            "created_at": now - datetime.timedelta(hours=9, minutes=10),
            "updated_at": now - datetime.timedelta(hours=3),
            "notes": [
                {
                    "author": "Analyst",
                    "content": "Email quarantined by secure gateway for 14 recipients. Single user opened attachment on WS-FIN-09.",
                    "timestamp": now - datetime.timedelta(hours=9)
                },
                {
                    "author": "Analyst",
                    "content": "EDR blocked AutoIt shellcode injection attempt into cscript.exe. Host rebooted and re-scanned cleanly.",
                    "timestamp": now - datetime.timedelta(hours=6)
                },
                {
                    "author": "Analyst",
                    "content": "C2 IP 89.208.107.198 blacklisted at DNS firewall. Incident resolved with zero data compromise.",
                    "timestamp": now - datetime.timedelta(hours=3)
                }
            ]
        },
        {
            "incident_id": "INC-2026-0895",
            "title": "Distributed SSH Brute Force Against Public Jump Host",
            "description": "Botnet swarm attempting root and service account password spraying on port 22.",
            "status": "Closed",
            "severity": "Medium",
            "assigned_to": "Analyst",
            "related_detections": ["det-2026-007"],
            "related_alerts": ["alt-mirai-005"],
            "created_at": now - datetime.timedelta(hours=13, minutes=15),
            "updated_at": now - datetime.timedelta(hours=6),
            "notes": [
                {
                    "author": "Analyst",
                    "content": "Fail2Ban automatically banned source IP 185.196.220.14 after 5 failed authentication attempts.",
                    "timestamp": now - datetime.timedelta(hours=13)
                },
                {
                    "author": "Analyst",
                    "content": "Verified password authentication is disabled; SSH access requires Ed25519 keys only. Threat neutralized.",
                    "timestamp": now - datetime.timedelta(hours=6)
                }
            ]
        },
        {
            "incident_id": "INC-2026-0896",
            "title": "Suspicious Outbound DNS Tunneling to Bulletproof Hosting",
            "description": "High volume of TXT query requests with high-entropy subdomains targeting suspicious authoritative nameserver.",
            "status": "Open",
            "severity": "Medium",
            "assigned_to": "Analyst",
            "related_detections": [],
            "related_alerts": [],
            "created_at": now - datetime.timedelta(hours=1, minutes=30),
            "updated_at": now - datetime.timedelta(minutes=45),
            "notes": [
                {
                    "author": "Analyst",
                    "content": "Network sensor detected 1,420 base64-encoded TXT lookups over 10 minutes. Suspicious staging of beaconing channel.",
                    "timestamp": now - datetime.timedelta(hours=1, minutes=20)
                },
                {
                    "author": "Analyst",
                    "content": "Source workstation identified as WS-DEV-14. Endpoint inspection scheduled.",
                    "timestamp": now - datetime.timedelta(minutes=45)
                }
            ]
        }
    ]

    print(f"Upserting {len(incidents)} security incidents...")
    for inc in incidents:
        await db["incidents"].replace_one({"incident_id": inc["incident_id"]}, inc, upsert=True)

    print("Populating complete! Clusters, alerts, detections, and incidents populated successfully.")
    client.close()


if __name__ == "__main__":
    asyncio.run(main())
