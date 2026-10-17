"""Tests for DGA detection integration in detection/detection_engine.py.

We mock DGAClassifier.predict_proba so we do not need a trained model,
and we mock _load_ioc_cache so we do not need a real MongoDB connection.

Verifies:
  - A clearly random domain with score >= threshold triggers a T1568.002 detection.
  - A known-good domain (google.com) with a low score does NOT trigger a detection.
  - A domain already in the IOC cache is skipped (no double alert).
  - A domain in the allowlist is skipped even with a high score.
  - Detection dict contains the expected MITRE technique and dga_score field.
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_dns_event(domain: str, client_ip: str = "10.0.0.1") -> dict:
    return {
        "log_type": "dns",
        "domain": domain,
        "client_ip": client_ip,
        "query": domain,
        "query_type": "A",
        "timestamp": "2024-01-01 12:00:00",
        "raw": f"2024-01-01 12:00:00 client {client_ip}#12345 ({domain}): query: {domain} IN A",
    }


def _run(coro):
    """Run an async coroutine in a fresh event loop."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine():
    """DetectionEngine with a fake DB that never talks to MongoDB."""
    from detection.detection_engine import DetectionEngine

    fake_db = MagicMock()
    eng = DetectionEngine(db=fake_db)
    # Pre-fill IOC cache so _load_ioc_cache doesn't try to hit MongoDB.
    eng._ioc_cache = {}
    return eng


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDGADetectionIntegration:

    def test_random_domain_triggers_dga_detection(self, engine):
        """A clearly random domain with score 0.97 must produce a T1568.002 detection."""
        random_domain = "xvz7q2mnd8kfjq3.com"

        with patch(
            "detection.detection_engine._dga_classifier.predict_proba",
            return_value=0.97,
        ):
            result = _run(engine.detect(_make_dns_event(random_domain)))

        assert result is not None, "Expected a detection for a random-looking domain"
        assert "T1568.002" in result.get("mitre_techniques", [])
        assert result.get("ioc_type") == "dga"
        assert result.get("matched_ioc") == random_domain
        # Score must be carried in the details dict
        assert "details" in result
        assert "dga_score" in result["details"]
        assert abs(result["details"]["dga_score"] - 0.97) < 1e-4

    def test_legitimate_domain_does_not_trigger(self, engine):
        """google.com with score 0.05 must return None (no detection)."""
        with patch(
            "detection.detection_engine._dga_classifier.predict_proba",
            return_value=0.05,
        ):
            result = _run(engine.detect(_make_dns_event("google.com")))

        # The ML check should not fire; IOC cache is empty so IOC lookup also returns None.
        assert result is None, f"Expected no detection for google.com, got {result}"

    def test_domain_at_threshold_boundary_triggers(self, engine):
        """Score exactly equal to threshold should trigger."""
        from utils.config import settings
        threshold = settings.dga_threshold  # default 0.9

        with patch(
            "detection.detection_engine._dga_classifier.predict_proba",
            return_value=threshold,
        ):
            result = _run(engine.detect(_make_dns_event("xvz7q2.com")))

        assert result is not None, (
            f"Score == threshold ({threshold}) should trigger detection"
        )

    def test_domain_just_below_threshold_does_not_trigger(self, engine):
        """Score just below threshold must not fire."""
        from utils.config import settings
        just_below = settings.dga_threshold - 0.001

        with patch(
            "detection.detection_engine._dga_classifier.predict_proba",
            return_value=just_below,
        ):
            result = _run(engine.detect(_make_dns_event("xvz7q2.com")))

        assert result is None, (
            f"Score {just_below} < threshold should not trigger detection"
        )

    def test_domain_already_in_ioc_cache_skipped(self, engine):
        """Domains already in the IOC cache must not produce a second (DGA) alert."""
        domain = "alreadyflagged.com"
        engine._ioc_cache = {domain: {"source": "manual", "type": "domain"}}

        with patch(
            "detection.detection_engine._dga_classifier.predict_proba",
            return_value=0.99,
        ) as mock_clf:
            result = _run(engine.detect(_make_dns_event(domain)))

        # Either None (skipped DGA, no IOC match for domain in cache query path)
        # or an IOC detection — but the DGA classifier must NOT have been called
        # for this domain because it's already in the cache.
        # The IOC static-lookup path will find it and return an IOC detection.
        # Either way, predict_proba should NOT have been called.
        mock_clf.assert_not_called()

    def test_allowlisted_domain_not_scored(self, engine):
        """Domains in DGA_ALLOWLIST must not be scored even with high scores."""
        from utils.config import settings
        if not settings.dga_allowlist:
            pytest.skip("DGA_ALLOWLIST is empty — nothing to test")

        allowlisted = settings.dga_allowlist[0].lower()

        with patch(
            "detection.detection_engine._dga_classifier.predict_proba",
            return_value=0.99,
        ) as mock_clf:
            result = _run(engine.detect(_make_dns_event(allowlisted)))

        # DGA classifier should NOT have been called for the allowlisted domain.
        mock_clf.assert_not_called()
        # No DGA detection should be returned for an allowlisted domain.
        if result is not None:
            assert "T1568.002" not in result.get("mitre_techniques", [])

    def test_missing_model_does_not_crash_detection(self, engine):
        """If predict_proba returns None (model missing), detect() must return None gracefully."""
        with patch(
            "detection.detection_engine._dga_classifier.predict_proba",
            return_value=None,
        ):
            result = _run(engine.detect(_make_dns_event("xvz7q2mnd8.com")))

        # None score → no DGA detection; IOC cache empty → no IOC detection.
        assert result is None

    def test_detection_contains_required_fields(self, engine):
        """The DGA detection dict must contain all required fields."""
        required = {
            "detection_id",
            "log_type",
            "matched_ioc",
            "matched_field",
            "ioc_source",
            "ioc_type",
            "confidence",
            "log_event",
            "threat_event_id",
            "timestamp",
            "mitre_techniques",
            "mitre_tactic",
            "rule_name",
            "description",
            "details",
        }

        with patch(
            "detection.detection_engine._dga_classifier.predict_proba",
            return_value=0.97,
        ):
            result = _run(engine.detect(_make_dns_event("xvz7q2mnd8.com")))

        assert result is not None
        missing = required - set(result.keys())
        assert not missing, f"Detection dict missing fields: {missing}"

    def test_detect_does_not_raise_on_malformed_event(self, engine):
        """detect() must never propagate exceptions regardless of input."""
        bad_events = [
            {},
            {"log_type": "dns"},
            {"log_type": "dns", "domain": None, "client_ip": None},
            {"log_type": "dns", "domain": "", "client_ip": ""},
        ]
        for event in bad_events:
            result = _run(engine.detect(event))
            # Just must not raise; return value can be anything.
            assert result is None or isinstance(result, dict)
