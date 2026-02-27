"""Analyst summary generation for threat intelligence."""
from typing import List
from security.validation import Alert, SeverityLevel
from utils.logger import get_logger

logger = get_logger(__name__)


class AnalystSummary:
    """Generate analyst-friendly summaries from alerts."""
    
    @staticmethod
    def generate_summary(alerts: List[Alert]) -> str:
        """
        Generate executive summary for a batch of alerts.
        
        Args:
            alerts: List of alerts
            
        Returns:
            Human-readable summary
        """
        if not alerts:
            return "No threats detected."
        
        # Count by severity
        high_count = sum(1 for a in alerts if a.severity == SeverityLevel.HIGH)
        medium_count = sum(1 for a in alerts if a.severity == SeverityLevel.MEDIUM)
        low_count = sum(1 for a in alerts if a.severity == SeverityLevel.LOW)
        
        # Get unique MITRE techniques
        all_techniques = set()
        for alert in alerts:
            all_techniques.update(alert.mitre_techniques)
        
        # Build summary
        summary_parts = []
        
        # Overall statistics
        summary_parts.append(f"**Threat Intelligence Summary**")
        summary_parts.append(f"\nTotal Alerts: {len(alerts)}")
        summary_parts.append(f"- High Severity: {high_count}")
        summary_parts.append(f"- Medium Severity: {medium_count}")
        summary_parts.append(f"- Low Severity: {low_count}")
        
        # MITRE techniques
        if all_techniques:
            summary_parts.append(f"\n**MITRE ATT&CK Techniques Detected:** {len(all_techniques)}")
            summary_parts.append(f"Techniques: {', '.join(sorted(all_techniques))}")
        
        # Key findings (top 3 high-risk alerts)
        high_risk_alerts = sorted([a for a in alerts if a.severity == SeverityLevel.HIGH], 
                                 key=lambda x: x.risk_score, reverse=True)[:3]
        
        if high_risk_alerts:
            summary_parts.append(f"\n**Top Priority Alerts:**")
            for i, alert in enumerate(high_risk_alerts, 1):
                related_count = len(alert.related_events)
                summary_parts.append(f"{i}. Alert {alert.alert_id[:8]}... (Risk: {alert.risk_score}/10, Related Events: {related_count})")
        
        # Recommendations
        summary_parts.append(f"\n**Recommended Actions:**")
        if high_count > 0:
            summary_parts.append(f"- Investigate {high_count} high-severity alert(s) immediately")
        if medium_count > 0:
            summary_parts.append(f"- Review {medium_count} medium-severity alert(s) within 24 hours")
        if low_count > 0:
            summary_parts.append(f"- Monitor {low_count} low-severity alert(s) for patterns")
        
        if all_techniques:
            summary_parts.append(f"- Review MITRE ATT&CK techniques for threat actor TTPs")
        
        summary = "\n".join(summary_parts)
        logger.info("analyst_summary_generated", total_alerts=len(alerts))
        return summary
    
    @staticmethod
    def generate_alert_summary(alert: Alert) -> str:
        """
        Generate summary for a single alert.
        
        Args:
            alert: Alert to summarize
            
        Returns:
            Alert summary
        """
        summary = f"Alert {alert.alert_id} - {alert.severity.value} Severity\n"
        summary += f"Risk Score: {alert.risk_score}/10\n"
        summary += f"Related Events: {len(alert.related_events)}\n"
        summary += f"MITRE Techniques: {', '.join(alert.mitre_techniques) if alert.mitre_techniques else 'None'}\n"
        summary += f"\nKey Findings:\n"
        for explanation in alert.explanation:
            summary += f"- {explanation}\n"
        
        return summary
