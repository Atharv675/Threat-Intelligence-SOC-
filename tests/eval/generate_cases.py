"""Generate the 10 evaluation cases for investigator eval suite."""
import json
from pathlib import Path

CASES_DIR = Path(__file__).resolve().parent / "cases"
CASES_DIR.mkdir(parents=True, exist_ok=True)

cases = [
    {
        "id": "case_01",
        "name": "SSH Brute Force from External IP",
        "description": "Repeated failed SSH logins from single external attacker IP",
        "incident": {
            "incident_id": "inc-eval-01",
            "title": "SSH Brute Force Attack",
            "description": "Multiple authentication failures detected on SSH port",
            "status": "Open",
            "severity": "High",
            "related_detections": ["det-eval-01a", "det-eval-01b"],
            "related_alerts": [],
            "created_at": "2026-10-17T10:00:00Z"
        },
        "detections": [
            {
                "detection_id": "det-eval-01a",
                "log_type": "auth",
                "matched_ioc": "198.51.100.22",
                "matched_field": "source_ip",
                "ioc_source": "Behavioral Heuristics Engine",
                "ioc_type": "ip",
                "confidence": 0.90,
                "mitre_techniques": ["T1110"],
                "rule_name": "SSH Brute Force Detected (T1110)",
                "log_event": {"source_ip": "198.51.100.22", "user": "root", "success": False},
                "timestamp": "2026-10-17T10:00:01Z"
            },
            {
                "detection_id": "det-eval-01b",
                "log_type": "auth",
                "matched_ioc": "198.51.100.22",
                "matched_field": "source_ip",
                "ioc_source": "Behavioral Heuristics Engine",
                "ioc_type": "ip",
                "confidence": 0.95,
                "mitre_techniques": ["T1110"],
                "rule_name": "SSH Brute Force Detected (T1110)",
                "log_event": {"source_ip": "198.51.100.22", "user": "admin", "success": False},
                "timestamp": "2026-10-17T10:00:05Z"
            }
        ],
        "events": [
            {"event_id": "evt-eval-01", "type": "ip", "value": "198.51.100.22", "source": "AlienVault", "risk_score": 8.0, "mitre_techniques": ["T1110"]}
        ],
        "expected": {
            "expected_entities": ["198.51.100.22", "root", "admin"],
            "expected_stage": "Credential Access",
            "expected_techniques": ["T1110"]
        }
    },
    {
        "id": "case_02",
        "name": "DGA Domain C2 Beaconing",
        "description": "Internal host querying algorithmically generated malicious domains",
        "incident": {
            "incident_id": "inc-eval-02",
            "title": "Suspected DGA C2 Activity",
            "description": "Endpoint generated high-entropy random domain queries",
            "status": "In Progress",
            "severity": "High",
            "related_detections": ["det-eval-02"],
            "related_alerts": [],
            "created_at": "2026-10-17T10:10:00Z"
        },
        "detections": [
            {
                "detection_id": "det-eval-02",
                "log_type": "dns",
                "matched_ioc": "xvz7q2mnd8k.biz",
                "matched_field": "domain",
                "ioc_source": "DGA ML Classifier",
                "ioc_type": "dga",
                "confidence": 0.98,
                "mitre_techniques": ["T1568.002"],
                "rule_name": "DGA Domain Detected - ML Classifier (T1568.002)",
                "log_event": {"client_ip": "10.0.0.45", "domain": "xvz7q2mnd8k.biz"},
                "timestamp": "2026-10-17T10:10:02Z"
            }
        ],
        "events": [
            {"event_id": "evt-eval-02", "type": "domain", "value": "xvz7q2mnd8k.biz", "source": "DGA Classifier", "risk_score": 9.2, "mitre_techniques": ["T1568.002"]}
        ],
        "expected": {
            "expected_entities": ["xvz7q2mnd8k.biz", "10.0.0.45"],
            "expected_stage": "Command and Control",
            "expected_techniques": ["T1568.002"]
        }
    },
    {
        "id": "case_03",
        "name": "Web Application Reconnaissance Scan",
        "description": "Multiple 403/404 scanning requests for sensitive administrative paths",
        "incident": {
            "incident_id": "inc-eval-03",
            "title": "Nginx Path Scanning",
            "description": "Attacker probing admin and configuration endpoints",
            "status": "Open",
            "severity": "Medium",
            "related_detections": ["det-eval-03"],
            "related_alerts": [],
            "created_at": "2026-10-17T10:20:00Z"
        },
        "detections": [
            {
                "detection_id": "det-eval-03",
                "log_type": "nginx",
                "matched_ioc": "203.0.113.15",
                "matched_field": "client_ip",
                "ioc_source": "Behavioral Heuristics Engine",
                "ioc_type": "behavioral",
                "confidence": 0.85,
                "mitre_techniques": ["T1595"],
                "rule_name": "Active Scanning Detected (T1595)",
                "log_event": {"client_ip": "203.0.113.15", "path": "/wp-login.php", "status": 403},
                "timestamp": "2026-10-17T10:20:01Z"
            }
        ],
        "events": [
            {"event_id": "evt-eval-03", "type": "ip", "value": "203.0.113.15", "source": "AbuseIPDB", "risk_score": 6.5, "mitre_techniques": ["T1595"]}
        ],
        "expected": {
            "expected_entities": ["203.0.113.15"],
            "expected_stage": "Reconnaissance",
            "expected_techniques": ["T1595"]
        }
    },
    {
        "id": "case_04",
        "name": "Spearphishing Link Click",
        "description": "User visited known malicious credential harvesting URL",
        "incident": {
            "incident_id": "inc-eval-04",
            "title": "Phishing Link Access",
            "description": "Outbound HTTP request to known credential harvesting domain",
            "status": "Open",
            "severity": "High",
            "related_detections": ["det-eval-04"],
            "related_alerts": [],
            "created_at": "2026-10-17T10:30:00Z"
        },
        "detections": [
            {
                "detection_id": "det-eval-04",
                "log_type": "nginx",
                "matched_ioc": "secure-login-update.com",
                "matched_field": "domain",
                "ioc_source": "OpenPhish",
                "ioc_type": "url",
                "confidence": 0.95,
                "mitre_techniques": ["T1566.002"],
                "rule_name": "Spearphishing Link Detected (T1566.002)",
                "log_event": {"client_ip": "192.168.1.102", "domain": "secure-login-update.com"},
                "timestamp": "2026-10-17T10:30:01Z"
            }
        ],
        "events": [
            {"event_id": "evt-eval-04", "type": "domain", "value": "secure-login-update.com", "source": "OpenPhish", "risk_score": 9.0, "mitre_techniques": ["T1566.002"]}
        ],
        "expected": {
            "expected_entities": ["secure-login-update.com", "192.168.1.102"],
            "expected_stage": "Initial Access",
            "expected_techniques": ["T1566.002"]
        }
    },
    {
        "id": "case_05",
        "name": "Lateral Movement with Compromised Credentials",
        "description": "Internal host authenticating across multiple internal servers using compromised admin account",
        "incident": {
            "incident_id": "inc-eval-05",
            "title": "Lateral Movement via SSH",
            "description": "Rapid internal SSH sessions using domain admin account",
            "status": "In Progress",
            "severity": "Critical",
            "related_detections": ["det-eval-05"],
            "related_alerts": [],
            "created_at": "2026-10-17T10:40:00Z"
        },
        "detections": [
            {
                "detection_id": "det-eval-05",
                "log_type": "auth",
                "matched_ioc": "198.51.100.77",
                "matched_field": "source_ip",
                "ioc_source": "Behavioral Heuristics Engine",
                "ioc_type": "ip",
                "confidence": 0.92,
                "mitre_techniques": ["T1078"],
                "rule_name": "Valid Accounts Abuse (T1078)",
                "log_event": {"source_ip": "198.51.100.77", "user": "corpadmin", "success": True},
                "timestamp": "2026-10-17T10:40:01Z"
            }
        ],
        "events": [
            {"event_id": "evt-eval-05", "type": "ip", "value": "198.51.100.77", "source": "AlienVault", "risk_score": 8.5, "mitre_techniques": ["T1078"]}
        ],
        "expected": {
            "expected_entities": ["198.51.100.77", "corpadmin"],
            "expected_stage": "Defense Evasion",
            "expected_techniques": ["T1078"]
        }
    },
    {
        "id": "case_06",
        "name": "Fast Flux Dynamic Resolution",
        "description": "High rate of changing DNS records pointing to resilient botnet C2",
        "incident": {
            "incident_id": "inc-eval-06",
            "title": "Fast Flux C2 Traffic",
            "description": "Rapid DNS resolution to fluctuating IP pool",
            "status": "Open",
            "severity": "High",
            "related_detections": ["det-eval-06"],
            "related_alerts": [],
            "created_at": "2026-10-17T10:50:00Z"
        },
        "detections": [
            {
                "detection_id": "det-eval-06",
                "log_type": "dns",
                "matched_ioc": "flux-gateway.net",
                "matched_field": "domain",
                "ioc_source": "Behavioral Heuristics Engine",
                "ioc_type": "domain",
                "confidence": 0.88,
                "mitre_techniques": ["T1568"],
                "rule_name": "Dynamic Resolution Detected (T1568)",
                "log_event": {"client_ip": "10.10.10.5", "domain": "flux-gateway.net"},
                "timestamp": "2026-10-17T10:50:01Z"
            }
        ],
        "events": [
            {"event_id": "evt-eval-06", "type": "domain", "value": "flux-gateway.net", "source": "ThreatIntel", "risk_score": 8.8, "mitre_techniques": ["T1568"]}
        ],
        "expected": {
            "expected_entities": ["flux-gateway.net", "10.10.10.5"],
            "expected_stage": "Command and Control",
            "expected_techniques": ["T1568"]
        }
    },
    {
        "id": "case_07",
        "name": "Endpoint Denial of Service Flooding",
        "description": "High rate volumetric HTTP requests overwhelming web services",
        "incident": {
            "incident_id": "inc-eval-07",
            "title": "Application Layer DoS",
            "description": "Severe request flood targeting web application endpoints",
            "status": "Open",
            "severity": "High",
            "related_detections": ["det-eval-07"],
            "related_alerts": [],
            "created_at": "2026-10-17T11:00:00Z"
        },
        "detections": [
            {
                "detection_id": "det-eval-07",
                "log_type": "nginx",
                "matched_ioc": "203.0.113.88",
                "matched_field": "client_ip",
                "ioc_source": "Behavioral Heuristics Engine",
                "ioc_type": "ip",
                "confidence": 0.90,
                "mitre_techniques": ["T1499"],
                "rule_name": "Endpoint Denial of Service (T1499)",
                "log_event": {"client_ip": "203.0.113.88", "path": "/api/search", "status": 503},
                "timestamp": "2026-10-17T11:00:01Z"
            }
        ],
        "events": [
            {"event_id": "evt-eval-07", "type": "ip", "value": "203.0.113.88", "source": "AbuseIPDB", "risk_score": 8.0, "mitre_techniques": ["T1499"]}
        ],
        "expected": {
            "expected_entities": ["203.0.113.88"],
            "expected_stage": "Impact",
            "expected_techniques": ["T1499"]
        }
    },
    {
        "id": "case_08",
        "name": "Malicious Command & Script Execution",
        "description": "Suspicious execution of script interpreter invoking obfuscated commands",
        "incident": {
            "incident_id": "inc-eval-08",
            "title": "Script Interpreter Abuse",
            "description": "PowerShell command execution with encoded arguments",
            "status": "In Progress",
            "severity": "Critical",
            "related_detections": ["det-eval-08"],
            "related_alerts": [],
            "created_at": "2026-10-17T11:10:00Z"
        },
        "detections": [
            {
                "detection_id": "det-eval-08",
                "log_type": "auth",
                "matched_ioc": "workstation-09.corp",
                "matched_field": "host",
                "ioc_source": "SIEM Collector",
                "ioc_type": "host",
                "confidence": 0.95,
                "mitre_techniques": ["T1059"],
                "rule_name": "Command and Scripting Interpreter (T1059)",
                "log_event": {"host": "workstation-09.corp", "user": "svc_backup"},
                "timestamp": "2026-10-17T11:10:01Z"
            }
        ],
        "events": [
            {"event_id": "evt-eval-08", "type": "host", "value": "workstation-09.corp", "source": "Internal", "risk_score": 9.0, "mitre_techniques": ["T1059"]}
        ],
        "expected": {
            "expected_entities": ["workstation-09.corp", "svc_backup"],
            "expected_stage": "Execution",
            "expected_techniques": ["T1059"]
        }
    },
    {
        "id": "case_09",
        "name": "Network Service Discovery Scan",
        "description": "Scanning probes identifying open internal ports across subnet",
        "incident": {
            "incident_id": "inc-eval-09",
            "title": "Port Sweep and Discovery",
            "description": "Rapid SYN sweeps across common service ports",
            "status": "Open",
            "severity": "Low",
            "related_detections": ["det-eval-09"],
            "related_alerts": [],
            "created_at": "2026-10-17T11:20:00Z"
        },
        "detections": [
            {
                "detection_id": "det-eval-09",
                "log_type": "nginx",
                "matched_ioc": "192.0.2.14",
                "matched_field": "client_ip",
                "ioc_source": "Behavioral Heuristics Engine",
                "ioc_type": "ip",
                "confidence": 0.75,
                "mitre_techniques": ["T1046"],
                "rule_name": "Network Service Discovery (T1046)",
                "log_event": {"client_ip": "192.0.2.14", "path": "/"},
                "timestamp": "2026-10-17T11:20:01Z"
            }
        ],
        "events": [
            {"event_id": "evt-eval-09", "type": "ip", "value": "192.0.2.14", "source": "AlienVault", "risk_score": 4.5, "mitre_techniques": ["T1046"]}
        ],
        "expected": {
            "expected_entities": ["192.0.2.14"],
            "expected_stage": "Discovery",
            "expected_techniques": ["T1046"]
        }
    },
    {
        "id": "case_10",
        "name": "High-Confidence Known C2 Infrastructure Match",
        "description": "Inbound connection from known state-sponsored C2 IP",
        "incident": {
            "incident_id": "inc-eval-10",
            "title": "Known APT C2 Communication",
            "description": "Direct traffic match against threat intelligence IOC feed",
            "status": "Open",
            "severity": "Critical",
            "related_detections": ["det-eval-10"],
            "related_alerts": [],
            "created_at": "2026-10-17T11:30:00Z"
        },
        "detections": [
            {
                "detection_id": "det-eval-10",
                "log_type": "auth",
                "matched_ioc": "185.220.101.5",
                "matched_field": "source_ip",
                "ioc_source": "AlienVault OTX",
                "ioc_type": "ip",
                "confidence": 0.99,
                "mitre_techniques": ["T1071"],
                "rule_name": "Known Malicious C2 IP (T1071)",
                "log_event": {"source_ip": "185.220.101.5", "user": "guest"},
                "timestamp": "2026-10-17T11:30:01Z"
            }
        ],
        "events": [
            {"event_id": "evt-eval-10", "type": "ip", "value": "185.220.101.5", "source": "AlienVault", "risk_score": 10.0, "mitre_techniques": ["T1071"]}
        ],
        "expected": {
            "expected_entities": ["185.220.101.5"],
            "expected_stage": "Command and Control",
            "expected_techniques": ["T1071"]
        }
    }
]

for c in cases:
    path = CASES_DIR / f"{c['id']}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(c, f, indent=2)

print(f"Generated {len(cases)} eval cases in {CASES_DIR}")
