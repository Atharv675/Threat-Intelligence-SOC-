"""Demo script to test the Threat Intelligence Aggregator pipeline."""
import asyncio
import sys
from datetime import datetime

# Force UTF-8 output for Windows
sys.stdout.reconfigure(encoding='utf-8')

# Add parent directory to path
sys.path.insert(0, '.')

from collectors import AlienVaultCollector, AbuseDBCollector, OpenPhishCollector
from core import (
    Normalizer, Enrichment, CorrelationEngine, MITREMapper,
    RiskScoring, AlertGenerator, AnalystSummary
)
from storage import Database, EventRepository, AlertRepository
from utils.logger import setup_logging, get_logger
from utils.config import settings

# Setup logging
setup_logging("INFO")
logger = get_logger(__name__)


async def main():
    """Run the complete threat intelligence pipeline."""
    print("=" * 80)
    print("THREAT INTELLIGENCE AGGREGATOR - DEMO")
    print("=" * 80)
    print()
    
    try:
        # Connect to MongoDB
        print("[1/9] Connecting to MongoDB...")
        await Database.connect()
        db = Database.get_database()
        
        # Create repositories
        event_repo = EventRepository(db)
        alert_repo = AlertRepository(db)
        await event_repo.create_indexes()
        await alert_repo.create_indexes()
        print("✓ MongoDB connected\n")
        
        # Step 1: Collect from OSINT sources
        print("[2/9] Collecting threat intelligence from OSINT sources...")
        all_raw_data = []
        
        # OpenPhish (most reliable for demo)
        async with OpenPhishCollector() as collector:
            phish_data = await collector.collect(limit=5)
            all_raw_data.extend([{"source": "OpenPhish", "data": d} for d in phish_data])
            print(f"  - OpenPhish: {len(phish_data)} indicators")
        
        # Abuse.ch
        async with AbuseDBCollector() as collector:
            abuse_data = await collector.collect(limit=5)
            all_raw_data.extend([{"source": "Abuse.ch", "data": d} for d in abuse_data])
            print(f"  - Abuse.ch: {len(abuse_data)} indicators")
        
        print(f"✓ Collected {len(all_raw_data)} total indicators\n")
        
        if not all_raw_data:
            print("❌ No data collected. Exiting.")
            return
        
        # Step 2: Normalize
        print("[3/9] Normalizing data...")
        normalized_events = []
        for item in all_raw_data:
            normalized = Normalizer.normalize(item["data"], item["source"])
            normalized_events.append(normalized)
        print(f"✓ Normalized {len(normalized_events)} events\n")
        
        # Step 3: Enrich
        print("[4/9] Enriching events with GeoIP, ASN, WHOIS...")
        enrichment_engine = Enrichment()
        enriched_events = [enrichment_engine.enrich(event) for event in normalized_events]
        print(f"✓ Enriched {len(enriched_events)} events\n")
        
        # Step 4: Correlate
        print("[5/9] Running graph-based correlation...")
        correlation_engine = CorrelationEngine(time_window_minutes=60)
        correlated_events = correlation_engine.correlate(enriched_events)
        correlated_count = sum(1 for e in correlated_events if e.correlation_strength > 0)
        print(f"✓ Correlated events: {correlated_count}/{len(correlated_events)}\n")
        
        # Step 5: MITRE ATT&CK Mapping
        print("[6/9] Mapping to MITRE ATT&CK framework...")
        mitre_events = [MITREMapper.enrich_with_mitre(event) for event in correlated_events]
        total_techniques = sum(len(e.mitre_techniques) for e in mitre_events)
        print(f"✓ Mapped {total_techniques} MITRE techniques\n")
        
        # Step 6-7: Risk Scoring & Alert Generation
        print("[7/9] Generating alerts with risk scoring...")
        alerts = AlertGenerator.generate_alerts(mitre_events)
        high = sum(1 for a in alerts if a.severity.value == "High")
        medium = sum(1 for a in alerts if a.severity.value == "Medium")
        low = sum(1 for a in alerts if a.severity.value == "Low")
        print(f"✓ Generated {len(alerts)} alerts (High: {high}, Medium: {medium}, Low: {low})\n")
        
        # Step 8: Analyst Summary
        print("[8/9] Generating analyst summary...")
        summary = AnalystSummary.generate_summary(alerts)
        print("✓ Summary generated\n")
        
        # Step 9: Store in MongoDB
        print("[9/9] Storing results in MongoDB...")
        
        # Build value → (risk_score, severity) map from alerts so we can
        # stamp each event document with its risk score before storage.
        # Alerts store the IOC value as first element in related_events.
        value_to_risk: dict = {}
        for alert in alerts:
            rel = alert.related_events  # list; first element is the IOC value
            if rel:
                ioc_value = rel[0]
                value_to_risk[ioc_value] = {
                    "risk_score": alert.risk_score,
                    "severity": alert.severity.value,
                }
        
        event_docs = []
        for event in mitre_events:
            doc = event.model_dump()
            # Embed risk score and severity directly in the event document
            risk_info = value_to_risk.get(event.value, {})
            doc["risk_score"] = risk_info.get("risk_score", 0.0)
            doc["severity"]   = risk_info.get("severity", "Low")
            event_docs.append(doc)
        
        alert_docs = [alert.model_dump() for alert in alerts]
        
        # Add summary to alerts
        for alert_doc in alert_docs:
            alert_doc["analyst_summary"] = summary
        
        event_ids = await event_repo.insert_many(event_docs)
        alert_ids = await alert_repo.insert_many(alert_docs)
        print(f"✓ Stored {len(event_ids)} events and {len(alert_ids)} alerts\n")
        
        # Display results
        print("=" * 80)
        print("ANALYST SUMMARY")
        print("=" * 80)
        print(summary)
        print()
        
        print("=" * 80)
        print("SAMPLE ALERT DETAILS")
        print("=" * 80)
        if alerts:
            sample_alert = alerts[0]
            print(f"\nAlert ID: {sample_alert.alert_id}")
            print(f"Severity: {sample_alert.severity.value}")
            print(f"Risk Score: {sample_alert.risk_score}/10")
            print(f"MITRE Techniques: {', '.join(sample_alert.mitre_techniques)}")
            print(f"\nExplanations:")
            for explanation in sample_alert.explanation:
                print(f"  - {explanation}")
        
        print("\n" + "=" * 80)
        print("PIPELINE COMPLETE ✓")
        print("=" * 80)
        
    except Exception as e:
        logger.error("demo_failed", error=str(e))
        print(f"\n❌ Error: {str(e)}")
        raise
    
    finally:
        # Cleanup
        await Database.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
