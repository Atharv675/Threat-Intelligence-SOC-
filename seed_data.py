"""
Bulk data seeder — creates realistic incidents, detections and events
so the SOC dashboard charts are well-populated.
Run once from the project root (venv activated):
    python seed_data.py
"""
import asyncio
import random
import uuid
from datetime import datetime, timedelta, timezone

from storage.database import Database
from utils.config import settings
from utils.logger import setup_logging

setup_logging("ERROR")   # keep output clean

# ─── Scenario pool ───────────────────────────────────────────────────────────

ANALYSTS = [
    "Analyst",
]

STATUSES   = ["Open", "In Progress", "Resolved", "Closed"]
STATUS_W   = [0.30, 0.30, 0.25, 0.15]          # weights

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEV_W      = [0.18, 0.32, 0.35, 0.15]          # weights — realistic SOC distribution

MITRE_TACTICS = [
    "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion",
    "Discovery", "Command and Control", "Impact",
]

IOC_TYPES = ["ip", "domain", "url", "hash", "email"]
IOC_TYPE_W = [0.35, 0.25, 0.20, 0.12, 0.08]

INCIDENTS = [
    # (title_template, description, category)
    ("Brute-Force SSH Login from {ip}",
     "Multiple failed SSH authentication attempts detected from {ip}. "
     "Over 200 failed attempts in 5 minutes suggest automated credential stuffing.",
     "Unauthorized Access"),
    ("Malware C2 Beacon to {domain}",
     "Endpoint {host} established persistent outbound connections to known C2 domain {domain}. "
     "Traffic pattern matches Cobalt Strike beacon profile.",
     "Malware C2"),
    ("Phishing Email Campaign — {domain}",
     "Spear-phishing emails impersonating Microsoft O365 delivered to 14 mailboxes. "
     "Malicious link redirects to credential-harvesting page at {domain}.",
     "Phishing"),
    ("Ransomware Staging Detected on {host}",
     "Suspicious PowerShell execution and shadow copy deletion commands observed. "
     "File encryption activity starting on shared drives.",
     "Malware"),
    ("Lateral Movement via Pass-the-Hash from {ip}",
     "NTLM authentication anomaly detected. Attacker reusing harvested hash "
     "to pivot across {count} hosts within the internal network.",
     "Unauthorized Access"),
    ("Web Application SQLi Attack from {ip}",
     "Automated SQL injection probes targeting /api/login endpoint. "
     "{count} payloads detected in 10 minutes, some resulting in error-based data extraction.",
     "Web Attack"),
    ("DNS Exfiltration to {domain}",
     "High-frequency DNS TXT queries to {domain} carrying encoded data. "
     "Total exfiltrated payload estimated at {size} MB over last 2 hours.",
     "Malware C2"),
    ("Insider Threat — Bulk Data Download by {user}",
     "User {user} downloaded {size} GB of sensitive documents outside business hours. "
     "Activity correlates with recent HR exit processing.",
     "Unauthorized Access"),
    ("Zero-Day Exploit Attempt on {host}",
     "Exploit code matching CVE-2024-{cve} signature detected against {host}. "
     "Payload attempts to achieve remote code execution via memory corruption.",
     "Malware"),
    ("Cryptominer Deployed via {domain}",
     "XMRig cryptominer binary dropped via malicious npm package from {domain}. "
     "CPU utilisation spiked to 95% on {count} endpoints.",
     "Malware"),
    ("Exposed RDP Port Exploitation from {ip}",
     "BlueKeep/DejaBlue exploitation attempt on RDP port 3389. "
     "Attacker IP {ip} is a known Tor exit node.",
     "Unauthorized Access"),
    ("Supply-Chain Compromise via {domain}",
     "Trojanised update package from {domain} executed on build server. "
     "Backdoor grants persistent access to CI/CD pipeline.",
     "Malware"),
    ("Credential Dumping via LSASS on {host}",
     "Mimikatz-like memory read of lsass.exe detected. "
     "Attacker likely harvesting credentials for further lateral movement.",
     "Unauthorized Access"),
    ("Suspicious Outbound Data Transfer to {ip}",
     "Anomalous 4.2 GB upload to IP {ip} (geo: Russia) during off-hours. "
     "Data classified as sensitive PII based on DLP policy match.",
     "Malware C2"),
    ("Vulnerability Scan from {ip}",
     "Automated Nmap/Masscan sweep targeting internal subnet. "
     "Source {ip} is not in the approved pentest schedule.",
     "Web Attack"),
]

IPS = [
    "185.220.101.5", "194.165.16.10", "91.108.56.200", "45.33.32.156",
    "198.51.100.42", "203.0.113.99", "10.10.5.88", "172.16.200.12",
    "109.70.100.50", "5.188.206.14", "37.120.198.208", "195.123.245.14",
]
DOMAINS = [
    "login-microsoftonline-auth.com", "update-service-cdn.net",
    "analytics-tracker-cdn.io", "cdn-static-assets.xyz",
    "secure-bank-verify.ru", "pastebin-c2.onion.ws",
    "d3js-loader.github.evil", "npm-registry-mirror.tk",
]
HOSTS = [
    "WKSTN-0042", "SRV-DC01", "WKSTN-0117", "SRV-SQL02",
    "LAPTOP-DEV03", "SRV-WEB01", "WKSTN-0008", "SRV-BUILD01",
]
USERS = [
    "j.doe@corp.local", "a.smith@corp.local",
    "b.jones@corp.local", "m.lee@corp.local",
]

def rand_ip():     return random.choice(IPS)
def rand_domain(): return random.choice(DOMAINS)
def rand_host():   return random.choice(HOSTS)
def rand_count():  return random.randint(3, 47)
def rand_size():   return random.randint(1, 12)
def rand_user():   return random.choice(USERS)
def rand_cve():    return random.randint(10000, 49999)

def make_incident():
    template, desc_tmpl, category = random.choice(INCIDENTS)
    subs = dict(ip=rand_ip(), domain=rand_domain(), host=rand_host(),
                count=rand_count(), size=rand_size(), user=rand_user(), cve=rand_cve())
    title = template.format(**subs)
    description = desc_tmpl.format(**subs)

    severity = random.choices(SEVERITIES, weights=SEV_W)[0]
    status   = random.choices(STATUSES,   weights=STATUS_W)[0]
    analyst  = random.choice(ANALYSTS)
    tactic   = random.choice(MITRE_TACTICS)
    days_ago = random.randint(0, 30)
    created  = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=random.randint(0, 23))

    notes = []
    if status in ("In Progress", "Resolved", "Closed"):
        notes.append({
            "author": analyst,
            "content": f"Initial triage complete. Severity confirmed as {severity}. Escalation path follows standard playbook.",
            "timestamp": (created + timedelta(hours=random.randint(1, 4))).isoformat()
        })
    if status in ("Resolved", "Closed"):
        notes.append({
            "author": random.choice(ANALYSTS),
            "content": "Containment actions applied. Affected hosts isolated. IOCs submitted to block list.",
            "timestamp": (created + timedelta(hours=random.randint(5, 24))).isoformat()
        })

    return {
        "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
        "title": title,
        "description": description,
        "severity": severity,
        "status": status,
        "assigned_to": analyst,
        "mitre_tactic": tactic,
        "category": category,
        "created_at": created.isoformat(),
        "updated_at": (created + timedelta(hours=random.randint(1, 48))).isoformat(),
        "notes": notes,
        "tags": [category.lower().replace(" ", "-"), tactic.lower().replace(" ", "-")],
    }

def make_event():
    ioc_type = random.choices(IOC_TYPES, weights=IOC_TYPE_W)[0]
    tactic   = random.choice(MITRE_TACTICS)
    risk     = round(random.uniform(2.0, 9.9), 1)
    days_ago = random.randint(0, 14)
    created  = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=random.randint(0, 23))

    ioc_value = {
        "ip":     rand_ip(),
        "domain": rand_domain(),
        "url":    f"https://{rand_domain()}/payload/{uuid.uuid4().hex[:8]}",
        "hash":   uuid.uuid4().hex,
        "email":  f"no-reply@{rand_domain()}",
    }[ioc_type]

    return {
        "event_id": str(uuid.uuid4()),
        "type": ioc_type,
        "value": ioc_value,
        "mitre_tactic": tactic,
        "mitre_techniques": [f"T{random.randint(1000, 1999)}.{random.randint(1, 9):03d}"],
        "risk_score": risk,
        "source": random.choice(["AlienVault", "AbuseIPDB", "OpenPhish", "Internal"]),
        "created_at": created.isoformat(),
        "tags": [tactic.lower().replace(" ", "-"), ioc_type],
    }

async def main():
    print("Connecting to MongoDB…")
    await Database.connect()
    db = Database.get_database()

    # ── Incidents ─────────────────────────────────────────────────────────────
    inc_col = db["incidents"]
    incidents = [make_incident() for _ in range(80)]
    result = await inc_col.insert_many(incidents)
    print(f"✓  Inserted {len(result.inserted_ids)} incidents")

    # Severity breakdown summary
    from collections import Counter
    sev_counts = Counter(i["severity"] for i in incidents)
    for s in SEVERITIES:
        print(f"     {s:<10}: {sev_counts[s]}")

    # ── Events (IOCs) ─────────────────────────────────────────────────────────
    evt_col = db["events"]
    events = [make_event() for _ in range(200)]
    result2 = await evt_col.insert_many(events)
    print(f"✓  Inserted {len(result2.inserted_ids)} events/IOCs")

    ioc_counts = Counter(e["type"] for e in events)
    for t in IOC_TYPES:
        print(f"     {t:<8}: {ioc_counts[t]}")

    tactic_counts = Counter(e["mitre_tactic"] for e in events)
    print("\n  MITRE Tactic distribution:")
    for tac, cnt in sorted(tactic_counts.items(), key=lambda x: -x[1]):
        print(f"     {tac:<28}: {cnt}")

    await Database.disconnect()
    print("\n✅ Done — refresh your dashboard at http://localhost:8005/dashboard")

if __name__ == "__main__":
    asyncio.run(main())
