"""
Populate massive clusters with 110+ nodes and rich correlation networks in MongoDB.
"""
import asyncio
import datetime
import hashlib
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from motor.motor_asyncio import AsyncIOMotorClient


async def populate():
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    db = client["threat_intel"]
    now = datetime.datetime.utcnow()

    # Clear existing events and alerts to have clean, rich, massive clusters
    await db["events"].delete_many({})
    await db["alerts"].delete_many({})

    events = []
    alerts = []

    # =========================================================================
    # CLUSTER 1: APT29 / Midnight Blizzard (Cloud OAuth & Identity Abuse) - 24 nodes
    # =========================================================================
    c1_id = "cluster-apt29-identity"
    c1_nodes = [
        ("ip", "185.220.101.5", "Abuse.ch", 0.95, "Netherlands", "Tor Exit", ["T1071.001", "T1090.003"], 8.9),
        ("ip", "185.220.101.12", "Abuse.ch", 0.94, "Netherlands", "Tor Exit", ["T1090.003"], 8.6),
        ("ip", "194.26.29.112", "AlienVault", 0.92, "Germany", "Host Europe", ["T1071.001", "T1528"], 8.4),
        ("ip", "194.26.29.118", "AlienVault", 0.90, "Germany", "Host Europe", ["T1071.001"], 8.2),
        ("ip", "45.142.212.89", "AlienVault", 0.91, "Sweden", "GleSYS AB", ["T1071", "T1566.002"], 8.5),
        ("domain", "login-microsoftonline-auth.com", "OpenPhish", 0.98, "United States", "AWS Cloud", ["T1566.002", "T1528"], 9.4),
        ("domain", "cloud-sync-identity.net", "OpenPhish", 0.96, "United States", "AWS Cloud", ["T1566.002", "T1528", "T1562"], 9.2),
        ("domain", "ms-token-verify.com", "OpenPhish", 0.97, "United States", "Cloudflare", ["T1566.002", "T1528"], 9.3),
        ("domain", "tenant-entra-auth.org", "OpenPhish", 0.95, "Germany", "Hetzner", ["T1528"], 8.8),
        ("domain", "azure-session-manager.info", "AlienVault", 0.93, "Finland", "Hetzner", ["T1071.001"], 8.7),
        ("domain", "oauth-device-consent.net", "OpenPhish", 0.96, "United States", "DigitalOcean", ["T1528", "T1566.002"], 9.1),
        ("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "AlienVault", 0.90, None, None, ["T1059.001", "T1080"], 8.1),
        ("hash", "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0", "AlienVault", 0.88, None, None, ["T1059.001"], 7.9),
        ("hash", "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8fa7834c40e2fc", "AlienVault", 0.92, None, None, ["T1080", "T1055"], 8.4),
        ("hash", "7d441f27d441f27d441f27d441f27d441f27d441f27d441f27d441f27d441f27", "AlienVault", 0.89, None, None, ["T1562.001"], 8.0),
        ("url", "https://login-microsoftonline-auth.com/oauth2/v2.0/token", "OpenPhish", 0.97, "United States", "AWS", ["T1528", "T1071.001"], 9.5),
        ("url", "https://cloud-sync-identity.net/devicecode/verify", "OpenPhish", 0.96, "United States", "AWS", ["T1528"], 9.2),
        ("url", "https://ms-token-verify.com/api/refresh", "OpenPhish", 0.95, "United States", "Cloudflare", ["T1528"], 9.1),
        ("ip", "89.248.165.74", "Abuse.ch", 0.89, "Seychelles", "Flyservers", ["T1071.001"], 8.1),
        ("ip", "193.32.162.190", "Abuse.ch", 0.88, "Russia", "VDSina", ["T1090.003"], 8.0),
        ("domain", "corp-mail-exchange.link", "OpenPhish", 0.94, "United States", "AWS", ["T1566.002"], 8.9),
        ("domain", "sso-telemetry-endpoint.com", "AlienVault", 0.91, "United States", "Oracle", ["T1071.001"], 8.4),
        ("hash", "9e107d9d372bb6826bd81d3542a419d6b7b52009b4515425589a8f5f167f44f4", "AlienVault", 0.93, None, None, ["T1080", "T1528"], 8.6),
        ("url", "https://tenant-entra-auth.org/admin/authorize", "OpenPhish", 0.96, "Germany", "Hetzner", ["T1528", "T1566.002"], 9.3)
    ]

    c1_event_ids = [f"c1-evt-{i+1}" for i in range(len(c1_nodes))]
    for i, (ioc_type, val, src, conf, country, asn, mitre, risk) in enumerate(c1_nodes):
        eid = c1_event_ids[i]
        related = [other for other in c1_event_ids if other != eid][:8]
        events.append({
            "event_id": eid,
            "type": ioc_type,
            "value": val,
            "source": src,
            "confidence": conf,
            "timestamp": now - datetime.timedelta(hours=2, minutes=i*5),
            "geo_data": {"country": country, "is_private": False} if country else None,
            "asn_data": {"organization": asn} if asn else None,
            "whois_data": {"newly_registered": "domain" in ioc_type},
            "correlation_id": c1_id,
            "related_events": related,
            "correlation_strength": 0.92,
            "mitre_techniques": mitre,
            "risk_score": risk,
        })

    alerts.append({
        "alert_id": "alt-apt29-major",
        "severity": "Critical",
        "risk_score": 9.4,
        "explanation": [
            "Alert severity: Critical (risk score: 9.40/10)",
            "Active APT29 / Midnight Blizzard cloud credential exfiltration campaign",
            "High confidence threat feed correlation across 24 indicators",
            "Multiple typosquatted Microsoft Entra and OAuth device authorization endpoints",
            "Mapped to MITRE ATT&CK: T1566.002, T1528, T1071.001, T1090.003, T1562.001, T1080",
            "Hosting infrastructure spans Tor exit relays and AWS cloud proxies"
        ],
        "risk_breakdown": {
            "total_score": 9.4,
            "factors": {
                "source_confidence": {"value": 0.96, "weight": 4.0, "contribution": 3.84},
                "correlation_strength": {"value": 0.92, "weight": 2.0, "contribution": 1.84},
                "mitre_techniques": {"count": 6, "weight": 1.5, "contribution": 1.50},
                "enrichment": {"completeness": 0.95, "weight": 0.5, "contribution": 0.47},
                "newly_registered_domain": {"flagged": True, "weight": 2.0, "contribution": 1.75}
            }
        },
        "mitre_techniques": ["T1566.002", "T1528", "T1071.001", "T1090.003", "T1562.001", "T1080"],
        "related_events": ["login-microsoftonline-auth.com"] + c1_event_ids[:7],
        "timestamp": now - datetime.timedelta(hours=2),
        "analyst_summary": (
            "**Threat Intelligence Summary**\n\n"
            "Total Alerts: 24 Correlated Nodes\n"
            "- Critical Severity: 8\n"
            "- High Severity: 16\n"
            "- Threat Actor: APT29 (Midnight Blizzard / Nobelium)\n\n"
            "**MITRE ATT&CK Techniques Detected:** 6\n"
            "Techniques: T1055, T1071.001, T1080, T1090.003, T1528, T1566.002\n\n"
            "**Key Findings:**\n"
            "1. Spear-phishing and OAuth consent phishing targeting administrator identities.\n"
            "2. Reverse SOCKS proxy routing through multi-hop Tor exit nodes in Netherlands & Sweden.\n"
            "3. Active session token theft bypassing MFA requirements via device code grant.\n\n"
            "**Recommended Actions:**\n"
            "- Revoke all active refresh tokens for compromised tenant identities immediately.\n"
            "- Block indicated IP pool (185.220.101.0/24, 194.26.29.0/24) at perimeter.\n"
            "- Restrict application registration consents to approved SOC administrators."
        )
    })

    # =========================================================================
    # CLUSTER 2: LockBit 3.0 Ransomware (Stealbit & Extortion Staging) - 22 nodes
    # =========================================================================
    c2_id = "cluster-lockbit3-extortion"
    c2_nodes = [
        ("ip", "45.154.255.89", "Abuse.ch", 0.96, "Russia", "WorldStream", ["T1048", "T1486"], 9.5),
        ("ip", "45.154.255.94", "Abuse.ch", 0.94, "Russia", "WorldStream", ["T1048"], 9.1),
        ("ip", "91.240.118.172", "AlienVault", 0.93, "Bulgaria", "Delta Telecom", ["T1071", "T1562"], 8.9),
        ("ip", "91.240.118.180", "AlienVault", 0.91, "Bulgaria", "Delta Telecom", ["T1071"], 8.7),
        ("ip", "193.106.191.28", "Abuse.ch", 0.95, "Seychelles", "Biterika LLC", ["T1486"], 9.3),
        ("domain", "lockbit-decryptor-gateway.top", "Abuse.ch", 0.98, "Seychelles", "Contabo", ["T1486", "T1499"], 9.6),
        ("domain", "lockbit-affiliate-portal.cc", "AlienVault", 0.96, "Russia", "Selectel", ["T1071", "T1486"], 9.4),
        ("domain", "data-leak-showcase.xyz", "AlienVault", 0.94, "Iceland", "Flokinet", ["T1048"], 9.0),
        ("domain", "victim-negotiation-portal.bid", "Abuse.ch", 0.95, "Panama", "NameSilo", ["T1486"], 9.2),
        ("hash", "a8f5f167f44f4964e6c998dee827110c7b52009b", "AlienVault", 0.97, None, None, ["T1486", "T1059.001"], 9.7),
        ("hash", "b2c3d4e5f60718293a4b5c6d7e8f90123456789a", "AlienVault", 0.95, None, None, ["T1486", "T1562.001"], 9.5),
        ("hash", "c3d4e5f60718293a4b5c6d7e8f90123456789ab1", "AlienVault", 0.94, None, None, ["T1048", "T1059.001"], 9.2),
        ("hash", "d4e5f60718293a4b5c6d7e8f90123456789ab1c2", "AlienVault", 0.93, None, None, ["T1562.001"], 9.0),
        ("url", "http://45.154.255.89/upload/stealbit.php", "Abuse.ch", 0.97, "Russia", "WorldStream", ["T1048", "T1071"], 9.6),
        ("url", "http://91.240.118.172/gate/sync.php", "AlienVault", 0.94, "Bulgaria", "Delta Telecom", ["T1071"], 9.1),
        ("ip", "195.123.245.12", "Abuse.ch", 0.89, "Latvia", "Nano IT", ["T1071"], 8.5),
        ("ip", "194.87.139.102", "AlienVault", 0.92, "Russia", "FirstVDS", ["T1048"], 8.9),
        ("domain", "decrypt-key-store.online", "Abuse.ch", 0.94, "Belize", "Hostinger", ["T1486"], 9.0),
        ("hash", "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4", "AlienVault", 0.96, None, None, ["T1486"], 9.6),
        ("hash", "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5", "AlienVault", 0.91, None, None, ["T1059.001"], 8.8),
        ("url", "http://195.123.245.12/tor/proxy.html", "Abuse.ch", 0.93, "Latvia", "Nano IT", ["T1071"], 9.0),
        ("url", "http://45.154.255.94/api/ping", "Abuse.ch", 0.90, "Russia", "WorldStream", ["T1071"], 8.7)
    ]

    c2_event_ids = [f"c2-evt-{i+1}" for i in range(len(c2_nodes))]
    for i, (ioc_type, val, src, conf, country, asn, mitre, risk) in enumerate(c2_nodes):
        eid = c2_event_ids[i]
        related = [other for other in c2_event_ids if other != eid][:7]
        events.append({
            "event_id": eid,
            "type": ioc_type,
            "value": val,
            "source": src,
            "confidence": conf,
            "timestamp": now - datetime.timedelta(hours=4, minutes=i*6),
            "geo_data": {"country": country, "is_private": False} if country else None,
            "asn_data": {"organization": asn} if asn else None,
            "whois_data": {"newly_registered": "domain" in ioc_type},
            "correlation_id": c2_id,
            "related_events": related,
            "correlation_strength": 0.94,
            "mitre_techniques": mitre,
            "risk_score": risk,
        })

    alerts.append({
        "alert_id": "alt-lockbit-major",
        "severity": "Critical",
        "risk_score": 9.65,
        "explanation": [
            "Alert severity: Critical (risk score: 9.65/10)",
            "LockBit 3.0 ransomware staging and pre-encryption exfiltration detected",
            "High confidence IOC cluster correlated across 22 network nodes",
            "Stealbit exfiltration tool and volume shadow deletion commands identified",
            "Mapped to MITRE ATT&CK: T1486, T1048, T1059.001, T1562.001, T1071",
            "Primary C2 hosted in Moscow, Russia and Sofia, Bulgaria"
        ],
        "risk_breakdown": {
            "total_score": 9.65,
            "factors": {
                "source_confidence": {"value": 0.97, "weight": 4.0, "contribution": 3.88},
                "correlation_strength": {"value": 0.94, "weight": 2.0, "contribution": 1.88},
                "mitre_techniques": {"count": 5, "weight": 1.5, "contribution": 1.50},
                "enrichment": {"completeness": 0.90, "weight": 0.5, "contribution": 0.45},
                "newly_registered_domain": {"flagged": True, "weight": 2.0, "contribution": 1.94}
            }
        },
        "mitre_techniques": ["T1486", "T1048", "T1059.001", "T1562.001", "T1071"],
        "related_events": ["lockbit-decryptor-gateway.top"] + c2_event_ids[:6],
        "timestamp": now - datetime.timedelta(hours=3, minutes=30),
        "analyst_summary": (
            "**Threat Intelligence Summary**\n\n"
            "Total Alerts: 22 Correlated Nodes\n"
            "- Critical Severity: 12\n"
            "- High Severity: 10\n"
            "- Threat Actor: LockBit 3.0 (LockBit Black)\n\n"
            "**MITRE ATT&CK Techniques Detected:** 5\n"
            "Techniques: T1048, T1059.001, T1071, T1486, T1562.001\n\n"
            "**Key Findings:**\n"
            "1. Dual-extortion workflow staged via Stealbit tool pushing sensitive data to 45.154.255.89.\n"
            "2. Defender evasion: Real-time monitoring and BehaviorMonitor disabled via PowerShell.\n"
            "3. Ransom note wallpaper payload and negotiation gateway links confirmed.\n\n"
            "**Recommended Actions:**\n"
            "- Network-isolate all staged fileservers and databases.\n"
            "- Implement strict firewall drop rules for 45.154.255.0/24 and 91.240.118.0/24.\n"
            "- Validate offline cold backups and preserve memory dumps for forensic analysis."
        )
    })

    # =========================================================================
    # CLUSTER 3: Volt Typhoon (Critical Infrastructure Living-off-the-Land) - 18 nodes
    # =========================================================================
    c3_id = "cluster-volt-typhoon"
    c3_nodes = [
        ("ip", "198.51.100.42", "AlienVault", 0.90, "United States", "AT&T Dallas", ["T1190", "T1090.003"], 8.5),
        ("ip", "198.51.100.58", "AlienVault", 0.88, "United States", "AT&T Dallas", ["T1090.003"], 8.2),
        ("ip", "203.0.113.78", "Abuse.ch", 0.89, "Singapore", "StarHub", ["T1016", "T1046"], 8.4),
        ("ip", "203.0.113.92", "Abuse.ch", 0.87, "Singapore", "StarHub", ["T1046"], 8.0),
        ("ip", "118.27.120.44", "AlienVault", 0.91, "Japan", "GMO Internet", ["T1190", "T1547"], 8.6),
        ("domain", "gateway-telemetry-sync.info", "AlienVault", 0.93, "Japan", "KDDI Tokyo", ["T1071.001", "T1190"], 8.9),
        ("domain", "router-fw-update.org", "AlienVault", 0.91, "Singapore", "Singtel", ["T1071.001"], 8.7),
        ("domain", "vpn-edge-concentrator.net", "AlienVault", 0.92, "United States", "Lumen", ["T1190"], 8.8),
        ("hash", "d41d8cd98f00b204e9800998ecf8427e02b8a1c9", "AlienVault", 0.89, None, None, ["T1505.003", "T1070"], 8.3),
        ("hash", "e2f3a4b5c6d7e8f90123456789abcdef01234567", "AlienVault", 0.87, None, None, ["T1016"], 7.9),
        ("hash", "f3a4b5c6d7e8f90123456789abcdef0123456789", "AlienVault", 0.88, None, None, ["T1070"], 8.1),
        ("url", "https://198.51.100.42/dana-na/auth/url_default/welcome.cgi", "AlienVault", 0.94, "United States", "AT&T", ["T1190", "T1505.003"], 9.0),
        ("url", "https://203.0.113.78/remote/login", "Abuse.ch", 0.90, "Singapore", "StarHub", ["T1190"], 8.5),
        ("ip", "182.16.24.89", "AlienVault", 0.86, "Taiwan", "Chunghwa", ["T1090.003"], 8.1),
        ("domain", "sys-diag-mesh.link", "AlienVault", 0.89, "Taiwan", "Chunghwa", ["T1071.001"], 8.4),
        ("ip", "210.140.10.15", "AlienVault", 0.88, "Japan", "Softbank", ["T1016"], 8.2),
        ("hash", "a4b5c6d7e8f90123456789abcdef0123456789ab", "AlienVault", 0.86, None, None, ["T1505.003"], 8.0),
        ("url", "https://118.27.120.44/api/v1/health", "AlienVault", 0.89, "Japan", "GMO", ["T1071"], 8.3)
    ]

    c3_event_ids = [f"c3-evt-{i+1}" for i in range(len(c3_nodes))]
    for i, (ioc_type, val, src, conf, country, asn, mitre, risk) in enumerate(c3_nodes):
        eid = c3_event_ids[i]
        related = [other for other in c3_event_ids if other != eid][:6]
        events.append({
            "event_id": eid,
            "type": ioc_type,
            "value": val,
            "source": src,
            "confidence": conf,
            "timestamp": now - datetime.timedelta(hours=6, minutes=i*8),
            "geo_data": {"country": country, "is_private": False} if country else None,
            "asn_data": {"organization": asn} if asn else None,
            "whois_data": {"newly_registered": "domain" in ioc_type},
            "correlation_id": c3_id,
            "related_events": related,
            "correlation_strength": 0.88,
            "mitre_techniques": mitre,
            "risk_score": risk,
        })

    # =========================================================================
    # CLUSTER 4: BlackCat / ALPHV Ransomware Extortion Syndicate - 16 nodes
    # =========================================================================
    c4_id = "cluster-blackcat-alphv"
    c4_nodes = [
        ("ip", "185.176.27.112", "Abuse.ch", 0.95, "Switzerland", "PrivatLayer", ["T1486", "T1048"], 9.3),
        ("ip", "185.176.27.115", "Abuse.ch", 0.93, "Switzerland", "PrivatLayer", ["T1048"], 9.0),
        ("ip", "193.142.146.33", "AlienVault", 0.92, "Russia", "Mir Telematiki", ["T1071"], 8.8),
        ("domain", "alphv-leak-site.onion", "AlienVault", 0.98, "Tor Hidden Service", "Tor", ["T1486", "T1048"], 9.6),
        ("domain", "blackcat-payload-dist.top", "Abuse.ch", 0.96, "Iceland", "1337 Services", ["T1105", "T1486"], 9.4),
        ("domain", "alphv-recovery-portal.net", "Abuse.ch", 0.95, "Panama", "Tucows", ["T1486"], 9.2),
        ("hash", "7c4a8d9b1e2f3a4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c", "AlienVault", 0.96, None, None, ["T1486", "T1059.001"], 9.5),
        ("hash", "8d9b1e2f3a4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e", "AlienVault", 0.94, None, None, ["T1048"], 9.1),
        ("hash", "9b1e2f3a4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f", "AlienVault", 0.93, None, None, ["T1562.001"], 8.9),
        ("url", "https://blackcat-payload-dist.top/bin/encryptor.exe", "Abuse.ch", 0.97, "Iceland", "1337 Services", ["T1105", "T1486"], 9.6),
        ("url", "https://185.176.27.112/exfil/drop.php", "Abuse.ch", 0.94, "Switzerland", "PrivatLayer", ["T1048"], 9.2),
        ("ip", "46.246.120.55", "Abuse.ch", 0.89, "Sweden", "Portlane", ["T1071"], 8.4),
        ("domain", "alphv-cloud-s3.xyz", "AlienVault", 0.91, "United States", "AWS", ["T1048"], 8.7),
        ("hash", "1e2f3a4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a", "AlienVault", 0.92, None, None, ["T1486"], 9.0),
        ("ip", "194.36.177.40", "AlienVault", 0.88, "Cyprus", "PQ Hosting", ["T1071"], 8.3),
        ("url", "https://alphv-cloud-s3.xyz/health/check", "AlienVault", 0.90, "United States", "AWS", ["T1071"], 8.5)
    ]

    c4_event_ids = [f"c4-evt-{i+1}" for i in range(len(c4_nodes))]
    for i, (ioc_type, val, src, conf, country, asn, mitre, risk) in enumerate(c4_nodes):
        eid = c4_event_ids[i]
        related = [other for other in c4_event_ids if other != eid][:5]
        events.append({
            "event_id": eid,
            "type": ioc_type,
            "value": val,
            "source": src,
            "confidence": conf,
            "timestamp": now - datetime.timedelta(hours=8, minutes=i*7),
            "geo_data": {"country": country, "is_private": False} if country else None,
            "asn_data": {"organization": asn} if asn else None,
            "whois_data": {"newly_registered": "domain" in ioc_type},
            "correlation_id": c4_id,
            "related_events": related,
            "correlation_strength": 0.91,
            "mitre_techniques": mitre,
            "risk_score": risk,
        })

    # =========================================================================
    # CLUSTER 5: DarkGate Modular Loader Phishing Wave - 16 nodes
    # =========================================================================
    c5_id = "cluster-darkgate-malspam"
    c5_nodes = [
        ("ip", "89.208.107.198", "Abuse.ch", 0.92, "Russia", "Selectel", ["T1071.001", "T1105"], 8.6),
        ("ip", "89.208.107.202", "Abuse.ch", 0.90, "Russia", "Selectel", ["T1105"], 8.3),
        ("ip", "194.87.68.51", "AlienVault", 0.89, "Russia", "VDSina", ["T1071.001"], 8.1),
        ("domain", "update-sys-service.xyz", "OpenPhish", 0.93, "United States", "Akamai", ["T1566.001", "T1204"], 8.9),
        ("domain", "cdn-cloud-edge-cache.info", "OpenPhish", 0.91, "United States", "Cloudflare", ["T1105"], 8.5),
        ("domain", "invoice-secure-dl.net", "OpenPhish", 0.95, "Germany", "Hetzner", ["T1566.001"], 9.1),
        ("hash", "c3ab8ff13720e8ad9047dd39466b3c89b71e21f4", "AlienVault", 0.92, None, None, ["T1055", "T1204"], 8.7),
        ("hash", "d4bc9aa24831f9be0158ee40577c4d9ac82f32a5", "AlienVault", 0.90, None, None, ["T1055"], 8.4),
        ("hash", "e5cd0bb35942a0cf1269ff51688d5e0bd93a43b6", "AlienVault", 0.88, None, None, ["T1105"], 8.0),
        ("url", "http://89.208.107.198/autoit/load.php", "Abuse.ch", 0.96, "Russia", "Selectel", ["T1105", "T1059"], 9.2),
        ("url", "https://update-sys-service.xyz/msi/setup.exe", "OpenPhish", 0.94, "United States", "Akamai", ["T1566.001", "T1204"], 9.0),
        ("url", "https://invoice-secure-dl.net/doc/INV-88219.zip", "OpenPhish", 0.95, "Germany", "Hetzner", ["T1566.001"], 9.3),
        ("ip", "178.62.204.15", "AlienVault", 0.87, "United Kingdom", "DigitalOcean", ["T1071"], 7.9),
        ("domain", "auth-token-drop.org", "OpenPhish", 0.89, "United Kingdom", "DigitalOcean", ["T1071"], 8.2),
        ("hash", "f6de1cc46053b1d02370aa62799e6f1ce04b54c7", "AlienVault", 0.89, None, None, ["T1055"], 8.1),
        ("url", "http://178.62.204.15/vnc/connect", "AlienVault", 0.91, "United Kingdom", "DigitalOcean", ["T1071"], 8.6)
    ]

    c5_event_ids = [f"c5-evt-{i+1}" for i in range(len(c5_nodes))]
    for i, (ioc_type, val, src, conf, country, asn, mitre, risk) in enumerate(c5_nodes):
        eid = c5_event_ids[i]
        related = [other for other in c5_event_ids if other != eid][:5]
        events.append({
            "event_id": eid,
            "type": ioc_type,
            "value": val,
            "source": src,
            "confidence": conf,
            "timestamp": now - datetime.timedelta(hours=10, minutes=i*6),
            "geo_data": {"country": country, "is_private": False} if country else None,
            "asn_data": {"organization": asn} if asn else None,
            "whois_data": {"newly_registered": "domain" in ioc_type},
            "correlation_id": c5_id,
            "related_events": related,
            "correlation_strength": 0.89,
            "mitre_techniques": mitre,
            "risk_score": risk,
        })

    # =========================================================================
    # CLUSTER 6: Mirai & Mozi IoT Botnet Swarm - 16 nodes
    # =========================================================================
    c6_id = "cluster-mirai-mozi"
    c6_nodes = [
        ("ip", "185.196.220.14", "Abuse.ch", 0.86, "Poland", "GTS Warsaw", ["T1595", "T1046"], 6.8),
        ("ip", "185.196.220.22", "Abuse.ch", 0.84, "Poland", "GTS Warsaw", ["T1595"], 6.5),
        ("ip", "103.145.13.22", "Abuse.ch", 0.82, "Vietnam", "Viettel", ["T1595", "T1190"], 6.4),
        ("ip", "103.145.13.35", "Abuse.ch", 0.80, "Vietnam", "Viettel", ["T1046"], 6.2),
        ("ip", "41.223.118.90", "Abuse.ch", 0.81, "South Africa", "Liquid Telecom", ["T1595"], 6.3),
        ("ip", "177.54.148.12", "Abuse.ch", 0.83, "Brazil", "Telefonica", ["T1046", "T1190"], 6.6),
        ("url", "http://185.196.220.14/bins/mirai.arm7", "Abuse.ch", 0.88, "Poland", "GTS Warsaw", ["T1105", "T1499"], 7.4),
        ("url", "http://185.196.220.14/bins/mirai.mips", "Abuse.ch", 0.88, "Poland", "GTS Warsaw", ["T1105", "T1499"], 7.4),
        ("url", "http://103.145.13.22/d/bot.x86", "Abuse.ch", 0.86, "Vietnam", "Viettel", ["T1105"], 7.1),
        ("hash", "3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c", "AlienVault", 0.85, None, None, ["T1499"], 6.9),
        ("hash", "4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d", "AlienVault", 0.84, None, None, ["T1499"], 6.8),
        ("ip", "110.232.84.19", "Abuse.ch", 0.79, "Indonesia", "Telkom", ["T1595"], 6.1),
        ("ip", "190.14.88.42", "Abuse.ch", 0.81, "Colombia", "Claro", ["T1046"], 6.3),
        ("domain", "iot-prober-pool.xyz", "Abuse.ch", 0.82, "United States", "NameCheap", ["T1595"], 6.5),
        ("url", "http://41.223.118.90/sh/scan.sh", "Abuse.ch", 0.85, "South Africa", "Liquid Telecom", ["T1059.004"], 6.9),
        ("hash", "5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e", "AlienVault", 0.83, None, None, ["T1499"], 6.7)
    ]

    c6_event_ids = [f"c6-evt-{i+1}" for i in range(len(c6_nodes))]
    for i, (ioc_type, val, src, conf, country, asn, mitre, risk) in enumerate(c6_nodes):
        eid = c6_event_ids[i]
        related = [other for other in c6_event_ids if other != eid][:5]
        events.append({
            "event_id": eid,
            "type": ioc_type,
            "value": val,
            "source": src,
            "confidence": conf,
            "timestamp": now - datetime.timedelta(hours=14, minutes=i*10),
            "geo_data": {"country": country, "is_private": False} if country else None,
            "asn_data": {"organization": asn} if asn else None,
            "whois_data": {"newly_registered": False},
            "correlation_id": c6_id,
            "related_events": related,
            "correlation_strength": 0.78,
            "mitre_techniques": mitre,
            "risk_score": risk,
        })

    # Inter-cluster bridges (simulating complex APT infrastructure reuse)
    events[0]["related_events"].append(c2_event_ids[0])
    events[5]["related_events"].append(c5_event_ids[3])

    print(f"Inserting {len(events)} events across 6 massive clusters...")
    await db["events"].insert_many(events)

    print(f"Inserting {len(alerts)} alerts...")
    await db["alerts"].insert_many(alerts)

    print("Massive clusters populated successfully!")
    client.close()


if __name__ == "__main__":
    asyncio.run(populate())
