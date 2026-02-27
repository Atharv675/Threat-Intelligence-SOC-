"""Alert generation with explanations and risk breakdown."""
from typing import List
from security.validation import Alert, SeverityLevel, CorrelatedEvent
from core.risk_scoring import RiskScoring
from utils.logger import get_logger
import uuid

logger = get_logger(__name__)


class AlertGenerator:
    """Generate explainable alerts from correlated events."""
    
    @staticmethod
    def _generate_explanations(event: CorrelatedEvent, risk_score: float, severity: SeverityLevel) -> List[str]:
        """
        Generate human-readable explanations for the alert.
        
        Args:
            event: Correlated event
            risk_score: Risk score
            severity: Severity level
            
        Returns:
            List of explanation strings
        """
        explanations = []
        
        # Severity explanation
        explanations.append(f"Alert severity: {severity.value} (risk score: {risk_score}/10)")
        
        # Source explanation
        explanations.append(f"Indicator detected from {event.source.value} threat intelligence feed")
        
        # Confidence explanation
        if event.confidence >= 0.8:
            explanations.append(f"High confidence indicator (confidence: {event.confidence:.2f})")
        elif event.confidence >= 0.5:
            explanations.append(f"Medium confidence indicator (confidence: {event.confidence:.2f})")
        else:
            explanations.append(f"Low confidence indicator (confidence: {event.confidence:.2f})")
        
        # Correlation explanation
        if event.correlation_strength > 0:
            explanations.append(f"Correlated with {len(event.related_events)} other event(s) (strength: {event.correlation_strength:.2f})")
        
        # MITRE explanation
        if event.mitre_techniques:
            techniques_str = ", ".join(event.mitre_techniques)
            explanations.append(f"Mapped to MITRE ATT&CK techniques: {techniques_str}")
        
        # Enrichment insights
        if event.geo_data and not event.geo_data.get("is_private"):
            country = event.geo_data.get("country", "Unknown")
            explanations.append(f"Geographic location: {country}")
        
        return explanations
    
    @classmethod
    def generate_alert(cls, event: CorrelatedEvent) -> Alert:
        """
        Generate an alert from a correlated event.
        
        Args:
            event: Correlated event with MITRE mappings
            
        Returns:
            Alert with explanations and risk breakdown
        """
        # Calculate risk
        risk_score = RiskScoring.calculate_risk_score(event)
        severity = RiskScoring.determine_severity(risk_score)
        risk_breakdown = RiskScoring.get_risk_breakdown(event, risk_score)
        
        # Generate explanations
        explanations = cls._generate_explanations(event, risk_score, severity)
        
        # Create alert
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            severity=severity,
            risk_score=risk_score,
            explanation=explanations,
            risk_breakdown=risk_breakdown,
            mitre_techniques=event.mitre_techniques,
            related_events=[event.value] + event.related_events,
        )
        
        logger.info("alert_generated", alert_id=alert.alert_id, severity=severity.value, risk_score=risk_score)
        return alert
    
    @classmethod
    def generate_alerts(cls, events: List[CorrelatedEvent]) -> List[Alert]:
        """
        Generate alerts from multiple correlated events.
        
        Args:
            events: List of correlated events
            
        Returns:
            List of alerts
        """
        alerts = []
        for event in events:
            try:
                alert = cls.generate_alert(event)
                alerts.append(alert)
            except Exception as e:
                logger.error("alert_generation_failed", error=str(e), event=event.value)
        
        logger.info("alerts_generated", count=len(alerts))
        return alerts
