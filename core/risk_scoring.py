"""Risk scoring engine with severity classification."""
from typing import Dict, Any, List
from security.validation import CorrelatedEvent, SeverityLevel
from utils.logger import get_logger

logger = get_logger(__name__)


class RiskScoring:
    """Calculate risk scores and severity levels for threat events."""

    # Risk factor weights — source_confidence is the dominant factor
    # so that it is primarily confidence that drives Low/Medium/High variation.
    WEIGHTS = {
        "source_confidence":      4.0,  # dominant — drives overall risk bucket
        "correlation_strength":   2.0,  # meaningful but not overriding
        "mitre_count":            1.5,  # reduced so 3 techniques alone ≠ instant High
        "enrichment_completeness": 0.5, # minor bonus for data richness
        "newly_registered_bonus":  2.0, # strong signal — newly registered domains are suspicious
    }

    @staticmethod
    def _calculate_enrichment_score(event: CorrelatedEvent) -> float:
        """
        Calculate enrichment completeness score.

        Returns:
            Enrichment score (0.0 to 1.0)
        """
        count = sum([
            bool(event.geo_data),
            bool(event.asn_data),
            bool(event.whois_data),
        ])
        return count / 3.0

    @staticmethod
    def _newly_registered_bonus(event: CorrelatedEvent) -> float:
        """Return 1.0 if WHOIS indicates a newly registered domain, else 0.0."""
        if event.whois_data and event.whois_data.get("newly_registered"):
            return 1.0
        return 0.0

    @classmethod
    def calculate_risk_score(cls, event: CorrelatedEvent) -> float:
        """
        Calculate risk score for an event.

        Args:
            event: Correlated event with MITRE mappings

        Returns:
            Risk score (0.0 to 10.0)
        """
        confidence_score     = event.confidence * cls.WEIGHTS["source_confidence"]
        correlation_score    = event.correlation_strength * cls.WEIGHTS["correlation_strength"]
        mitre_score          = min(len(event.mitre_techniques) / 3.0, 1.0) * cls.WEIGHTS["mitre_count"]
        enrichment_score     = cls._calculate_enrichment_score(event) * cls.WEIGHTS["enrichment_completeness"]
        new_domain_bonus     = cls._newly_registered_bonus(event) * cls.WEIGHTS["newly_registered_bonus"]

        total_weight = sum(cls.WEIGHTS.values())
        raw = confidence_score + correlation_score + mitre_score + enrichment_score + new_domain_bonus
        risk_score = (raw / total_weight) * 10.0

        risk_score = max(0.0, min(10.0, risk_score))
        logger.debug("risk_calculated", value=event.value, risk_score=risk_score)
        return round(risk_score, 2)

    @staticmethod
    def determine_severity(risk_score: float) -> SeverityLevel:
        """
        Determine severity level based on risk score.

        Thresholds:
          High   >= 6.5
          Medium >= 4.0
          Low    <  4.0
        """
        if risk_score >= 6.5:
            return SeverityLevel.HIGH
        elif risk_score >= 4.0:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    @classmethod
    def get_risk_breakdown(cls, event: CorrelatedEvent, risk_score: float) -> Dict[str, Any]:
        """
        Get detailed risk breakdown for analyst review.

        Args:
            event: Correlated event
            risk_score: Calculated risk score

        Returns:
            Risk breakdown dictionary
        """
        return {
            "total_score": risk_score,
            "factors": {
                "source_confidence": {
                    "value": event.confidence,
                    "weight": cls.WEIGHTS["source_confidence"],
                    "contribution": round(event.confidence * cls.WEIGHTS["source_confidence"], 3),
                },
                "correlation_strength": {
                    "value": event.correlation_strength,
                    "weight": cls.WEIGHTS["correlation_strength"],
                    "contribution": round(event.correlation_strength * cls.WEIGHTS["correlation_strength"], 3),
                },
                "mitre_techniques": {
                    "count": len(event.mitre_techniques),
                    "weight": cls.WEIGHTS["mitre_count"],
                    "contribution": round(
                        min(len(event.mitre_techniques) / 3.0, 1.0) * cls.WEIGHTS["mitre_count"], 3
                    ),
                },
                "enrichment": {
                    "completeness": round(cls._calculate_enrichment_score(event), 3),
                    "weight": cls.WEIGHTS["enrichment_completeness"],
                    "contribution": round(
                        cls._calculate_enrichment_score(event) * cls.WEIGHTS["enrichment_completeness"], 3
                    ),
                },
                "newly_registered_domain": {
                    "flagged": bool(cls._newly_registered_bonus(event)),
                    "weight": cls.WEIGHTS["newly_registered_bonus"],
                    "contribution": round(
                        cls._newly_registered_bonus(event) * cls.WEIGHTS["newly_registered_bonus"], 3
                    ),
                },
            },
        }
