"""Stage 2 SOC Demo - Log Ingestion, Detection, and Incident Management.

Security: OWASP A01 (Access Control), A03 (Injection), A09 (Logging).
"""
import asyncio
import sys
from datetime import datetime, timezone
from typing import Optional

# Force UTF-8 output for Windows
sys.stdout.reconfigure(encoding='utf-8')

from storage.database import Database
from storage.repositories import EventRepository, DetectionRepository, IncidentRepository
from ingestion import LogParser, EventIngestor
from detection import DetectionEngine
from core.incident_manager import IncidentManager
from utils.logger import setup_logging, get_logger

setup_logging("INFO")
logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_auth_log(ip: str) -> str:
    """Build a syntactically valid SSH auth-failure log line."""
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    return f"{ts} soc-demo sshd[99999]: Failed password for root from {ip} port 22 ssh2"


def _make_nginx_log(ip: str) -> str:
    """Build a syntactically valid Nginx access log line."""
    ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "GET /admin HTTP/1.1" 403 512 "-" "ThreatBot/1.0"'


def _make_dns_log(domain: str, client_ip: str = "192.0.2.42") -> str:
    """Build a syntactically valid BIND-style DNS query log line."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return f"{ts} client {client_ip}#53 ({domain}): query: {domain} IN A"


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

async def demo_stage2() -> None:
    """Demonstrate Stage 2 SOC capabilities."""
    print("\n" + "=" * 80)
    print("STAGE 2 SOC DEMO - Log Ingestion, Detection & Incident Management")
    print("=" * 80 + "\n")

    try:
        # ── Connect ──────────────────────────────────────────────────────────
        print("📡 Connecting to MongoDB...")
        await Database.connect()
        db = Database.get_database()

        event_repo     = EventRepository(db)
        detection_repo = DetectionRepository(db)
        incident_repo  = IncidentRepository(db)
        detection_engine = DetectionEngine(db)
        incident_manager = IncidentManager(db)
        print("✅ Connected to database\n")

        # ── Fetch a REAL IOC from the Threat Intel DB ────────────────────────
        # OWASP A03: we read from DB and use the value as-is; we don't
        # interpolate user-supplied strings into queries.
        print("🔍 Loading threat intelligence from database...")
        all_events = await event_repo.find_all(skip=0, limit=500)

        # Pick first URL-type IOC and first IP-type IOC available
        real_url:    Optional[str] = None
        real_ip:     Optional[str] = None
        real_domain: Optional[str] = None

        for e in all_events:
            ioc_type  = e.get("type", "")
            ioc_value = e.get("value", "")
            if not ioc_value:
                continue
            if ioc_type == "url" and real_url is None:
                real_url = ioc_value
            if ioc_type == "ip" and real_ip is None:
                real_ip = ioc_value
            if ioc_type == "domain" and real_domain is None:
                real_domain = ioc_value
            if real_url and real_ip and real_domain:
                break

        if not (real_url or real_ip or real_domain):
            print("⚠️  No threat intel found in database.")
            print("   Run demo.py first to populate threat intelligence.\n")
            return

        print(f"   ✓ Found IOC (URL)    : {(real_url or 'n/a')[:60]}")
        print(f"   ✓ Found IOC (IP)     : {real_ip or 'n/a'}")
        print(f"   ✓ Found IOC (Domain) : {real_domain or 'n/a'}\n")

        # ── Build realistic log lines that CONTAIN the real IOCs ─────────────
        # This guarantees the detection engine will always find a match.
        SAMPLE_LOGS = []

        if real_ip:
            SAMPLE_LOGS.append(("auth",  _make_auth_log(real_ip)))
            SAMPLE_LOGS.append(("nginx", _make_nginx_log(real_ip)))

        if real_domain:
            SAMPLE_LOGS.append(("dns", _make_dns_log(real_domain)))

        # Add a benign baseline so the demo shows clean vs dirty traffic
        SAMPLE_LOGS += [
            ("auth",  _make_auth_log("10.0.0.1")),       # private IP – safe
            ("nginx", _make_nginx_log("127.0.0.1")),     # loopback – safe
        ]

        # Add stateful behavioral test sequence (3 failed logins from same clean IP)
        # This will trigger the SSH Brute Force behavioral rule!
        SAMPLE_LOGS += [
            ("auth",  _make_auth_log("192.168.1.100")),
            ("auth",  _make_auth_log("192.168.1.100")),
            ("auth",  _make_auth_log("192.168.1.100")),  # Third failed login triggers T1110
        ]

        # ── PART 1: Log Ingestion & Detection ────────────────────────────────
        print("─" * 80)
        print("PART 1: LOG INGESTION & DETECTION")
        print("─" * 80 + "\n")

        all_detections = []

        for log_type, raw_log in SAMPLE_LOGS:
            print(f"📝 [{log_type.upper()}] {raw_log[:70]}...")
            try:
                # Parse → validate (raw field stripped inside EventIngestor)
                validated = EventIngestor.ingest(raw_log, log_type=log_type)
                log_dict  = validated.model_dump()

                detection = await detection_engine.detect(log_dict)

                if detection:
                    det_id = await detection_repo.insert_one(detection)
                    all_detections.append(detection)
                    print(f"   🚨 THREAT DETECTED  : {detection['matched_ioc']}")
                    print(f"      Detection ID     : {det_id}")
                    print(f"      Source           : {detection['ioc_source']}")
                    print(f"      Confidence       : {detection['confidence']:.2f}\n")
                else:
                    print("   ✓ No threat matched (benign)\n")

            except ValueError as e:
                # OWASP A09: log error without exposing raw log content
                logger.warning("log_ingestion_failed", log_type=log_type,
                               error=str(e)[:120])
                print(f"   ✗ Validation error: {str(e)[:120]}\n")

        print(f"📊 Total detections this run: {len(all_detections)}\n")

        # ── PART 2: Detection Summary ─────────────────────────────────────────
        print("─" * 80)
        print("PART 2: DETECTION SUMMARY")
        print("─" * 80 + "\n")

        if all_detections:
            print("🔍 Detection Details:\n")
            for i, d in enumerate(all_detections, 1):
                print(f"  {i}. ID         : {d['detection_id']}")
                print(f"     Log Type   : {d['log_type']}")
                print(f"     Matched IOC: {d['matched_ioc']}")
                print(f"     IOC Type   : {d['ioc_type']}")
                print(f"     Source     : {d['ioc_source']}")
                print(f"     Confidence : {d['confidence']:.2f}\n")
        else:
            print("ℹ️  No detections this run.\n")

        # ── PART 3: Incident Management ───────────────────────────────────────
        print("─" * 80)
        print("PART 3: INCIDENT MANAGEMENT")
        print("─" * 80 + "\n")

        if all_detections:
            detection_ids = [d["detection_id"] for d in all_detections]

            print("📋 Creating security incident...")
            incident_id = await incident_manager.create_incident(
                title=f"Malicious IOC Detected in Logs ({len(all_detections)} hit(s))",
                description=(
                    f"The detection engine matched {len(all_detections)} log event(s) "
                    "against live threat intelligence from the OSINT pipeline."
                ),
                severity="High",
                detections=detection_ids,
                assigned_to="analyst@soc.local",
            )
            print(f"✅ Incident created: {incident_id}\n")

            print("🔄 Setting status → In Progress...")
            await incident_manager.update_status(
                incident_id=incident_id,
                new_status="In Progress",
                note="Triage started — cross-referencing with OSINT alerts.",
                author="analyst@soc.local",
            )
            print("✅ Status updated\n")

            print("📝 Adding investigation notes...")
            await incident_manager.add_note(
                incident_id=incident_id,
                author="analyst@soc.local",
                content="Confirmed IOC matches known threat actor infrastructure via OpenPhish feed.",
            )
            await incident_manager.add_note(
                incident_id=incident_id,
                author="analyst@soc.local",
                content="Blocked at perimeter firewall. Monitoring for lateral movement.",
            )
            print("✅ Notes added\n")

            incident = await incident_manager.get_incident(incident_id)
            print("📄 Incident Details:")
            print(f"   Title      : {incident['title']}")
            print(f"   Status     : {incident['status']}")
            print(f"   Severity   : {incident['severity']}")
            print(f"   Assigned   : {incident['assigned_to']}")
            print(f"   Detections : {len(incident['related_detections'])}")
            print(f"   Notes      : {len(incident['notes'])}")
            for note in incident["notes"]:
                ts = (note["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
                      if hasattr(note["timestamp"], "strftime")
                      else str(note["timestamp"]))
                print(f"     [{ts}] {note['author']}: {note['content']}")

            print(f"\n🔄 Closing incident...")
            await incident_manager.update_status(
                incident_id=incident_id,
                new_status="Resolved",
                note="All matched IOCs blocked. Incident closed.",
                author="analyst@soc.local",
            )
            print("✅ Incident resolved\n")
        else:
            print("ℹ️  No detections — skipping incident creation.\n")

        # ── PART 4: Statistics ────────────────────────────────────────────────
        print("─" * 80)
        print("PART 4: STATISTICS")
        print("─" * 80 + "\n")

        total_events     = await event_repo.count()
        total_detections = await detection_repo.count()
        total_incidents  = await incident_repo.count()

        print("📊 Database Statistics:")
        print(f"   Threat Intelligence Events : {total_events}")
        print(f"   Total Detections           : {total_detections}")
        print(f"   Total Incidents            : {total_incidents}\n")

        print("🔍 Detections by Log Type:")
        for lt in ["auth", "nginx", "dns"]:
            cnt = await detection_repo.count(log_type=lt)
            print(f"   {lt.upper():5s}: {cnt}")

        print("\n📋 Incidents by Status:")
        for status in ["Open", "In Progress", "Resolved", "Closed"]:
            cnt = await incident_repo.count(status=status)
            print(f"   {status}: {cnt}")

        print("\n" + "=" * 80)
        print("✅  STAGE 2 DEMO COMPLETED SUCCESSFULLY")
        print("=" * 80 + "\n")
        print("💡 Next Steps:")
        print("   1. Start the dashboard  : uvicorn main:app --reload")
        print("   2. Ingest via API       : POST /api/v1/ingest/{auth|nginx|dns}")
        print("   3. View detections      : GET /api/v1/detections")
        print("   4. Manage incidents     : GET /api/v1/incidents\n")

    except Exception as e:
        # OWASP A09: log full traceback internally, show generic message externally
        logger.error("demo_failed", error=str(e), exc_info=True)
        print(f"\n❌ Demo failed: {str(e)}")

    finally:
        await Database.disconnect()


if __name__ == "__main__":
    asyncio.run(demo_stage2())
