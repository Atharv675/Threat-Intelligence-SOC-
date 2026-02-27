"""Graph-based correlation engine for threat events."""
from typing import List, Dict, Any, Set, Tuple
from security.validation import EnrichedEvent, CorrelatedEvent
from utils.logger import get_logger
from datetime import datetime, timedelta
import hashlib
import uuid

logger = get_logger(__name__)


class CorrelationEngine:
    """Graph-based correlation engine to find relationships between events."""

    def __init__(self, time_window_minutes: int = 60):
        """
        Initialize correlation engine.

        Args:
            time_window_minutes: Time window for temporal correlation
        """
        self.time_window = timedelta(minutes=time_window_minutes)

    @staticmethod
    def _generate_event_id(event: EnrichedEvent) -> str:
        """Generate a stable unique ID for an event based on value + source."""
        key = f"{event.value}:{event.source}:{event.type}"
        return hashlib.md5(key.encode()).hexdigest()[:16]

    @staticmethod
    def _generate_correlation_id(event_ids: List[str]) -> str:
        """Generate a correlation cluster ID for a set of event IDs."""
        combined = ":".join(sorted(event_ids))
        return hashlib.sha1(combined.encode()).hexdigest()[:16]

    def _find_related_event_ids(
        self,
        event: EnrichedEvent,
        event_id: str,
        other_events: List[Tuple[str, EnrichedEvent]],
    ) -> Tuple[Set[str], float]:
        """
        Find IDs of events related to this event and compute correlation strength.

        Args:
            event: The event to correlate
            event_id: The stable ID of this event
            other_events: List of (id, event) tuples to compare against

        Returns:
            (set of related event IDs, correlation strength 0-1)
        """
        weights = {
            "same_type": 0.4,
            "same_asn": 0.6,
            "same_country": 0.3,
            "same_source": 0.5,
        }

        related_ids: Set[str] = set()
        accumulated_weight = 0.0

        for other_id, other in other_events:
            if other_id == event_id:
                continue

            score = 0.0
            matched = False

            # Same IOC type (IP, URL, domain, etc.)
            if event.type == other.type:
                score += weights["same_type"]
                matched = True

            # Same source feed
            if event.source == other.source:
                score += weights["same_source"]
                matched = True

            # Same ASN (only for IP IOCs that have ASN data)
            if (
                event.asn_data
                and other.asn_data
                and event.asn_data.get("asn")
                and event.asn_data.get("asn") != "AS00000"
                and event.asn_data.get("asn") == other.asn_data.get("asn")
            ):
                score += weights["same_asn"]
                matched = True

            # Same country
            if (
                event.geo_data
                and other.geo_data
                and event.geo_data.get("country")
                and event.geo_data.get("country") not in ("Unknown", "Private Network")
                and event.geo_data.get("country") == other.geo_data.get("country")
            ):
                score += weights["same_country"]
                matched = True

            if matched and score > 0:
                related_ids.add(other_id)
                accumulated_weight = max(accumulated_weight, score)

        max_possible = sum(weights.values())
        strength = min(accumulated_weight / max_possible, 1.0)
        return related_ids, strength

    def correlate(self, events: List[EnrichedEvent]) -> List[CorrelatedEvent]:
        """
        Correlate events to find relationships and assign stable event IDs.

        Args:
            events: List of enriched events

        Returns:
            List of correlated events with proper event IDs in related_events
        """
        if not events:
            return []

        # Filter to recent events only for correlation
        now = datetime.utcnow()
        recent_events = [e for e in events if (now - e.timestamp) <= self.time_window]

        # Assign a stable ID to every event
        id_map: List[Tuple[str, EnrichedEvent]] = [
            (self._generate_event_id(e), e) for e in recent_events
        ]

        correlated_events: List[CorrelatedEvent] = []

        for event_id, event in id_map:
            related_ids, strength = self._find_related_event_ids(event, event_id, id_map)

            # Build correlation cluster ID when there are relationships
            correlation_id: str | None = None
            if related_ids:
                all_ids = list(related_ids) + [event_id]
                correlation_id = self._generate_correlation_id(all_ids)

            correlated_data = event.model_dump()
            correlated_data.update(
                {
                    "event_id": event_id,          # stable node ID for the graph
                    "correlation_id": correlation_id,
                    "related_events": list(related_ids),   # IDs, not values!
                    "correlation_strength": round(strength, 3),
                }
            )
            correlated_events.append(CorrelatedEvent(**correlated_data))

        n_correlated = sum(1 for e in correlated_events if e.correlation_strength > 0)
        n_edges = sum(len(e.related_events) for e in correlated_events)
        logger.info(
            "correlation_completed",
            total_events=len(events),
            correlated=n_correlated,
            total_edge_refs=n_edges,
        )
        return correlated_events
