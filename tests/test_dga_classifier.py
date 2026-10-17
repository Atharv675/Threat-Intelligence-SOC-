"""Tests for detection/dga_classifier.py.

Covers:
  - extract_features: normal, random, empty, IP, unicode, very-long input
  - DGAClassifier: missing model file returns None and does not raise
"""
import math
import os
import sys
from pathlib import Path

import pytest

# Make sure the project root is on sys.path regardless of where pytest is invoked.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from detection.dga_classifier import (
    DGAClassifier,
    _shannon_entropy,
    _longest_consonant_run,
    _bigram_score,
    extract_features,
    _extract_main_label,
)


# ---------------------------------------------------------------------------
# Helper / internal function unit tests
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_empty_string_returns_zero(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char_returns_zero(self):
        assert _shannon_entropy("a") == 0.0

    def test_two_identical_chars_returns_zero(self):
        assert _shannon_entropy("aa") == 0.0

    def test_two_distinct_chars_returns_one_bit(self):
        assert abs(_shannon_entropy("ab") - 1.0) < 1e-9

    def test_increases_with_randomness(self):
        # "google" should have lower entropy than a truly random string
        assert _shannon_entropy("google") < _shannon_entropy("xqzjkfvb")


class TestLongestConsonantRun:
    def test_all_vowels_returns_zero(self):
        assert _longest_consonant_run("aeiou") == 0

    def test_single_consonant(self):
        assert _longest_consonant_run("b") == 1

    def test_consecutive_consonants(self):
        assert _longest_consonant_run("strength") == 4  # "ngth"

    def test_mixed(self):
        assert _longest_consonant_run("xvz") == 3

    def test_empty(self):
        assert _longest_consonant_run("") == 0


class TestBigramScore:
    def test_short_string_returns_floor(self):
        from detection.dga_classifier import _BIGRAM_FLOOR
        assert _bigram_score("a") == _BIGRAM_FLOOR

    def test_common_english_bigrams_higher_than_floor(self):
        from detection.dga_classifier import _BIGRAM_FLOOR
        score = _bigram_score("the")
        assert score > _BIGRAM_FLOOR

    def test_random_string_near_floor(self):
        from detection.dga_classifier import _BIGRAM_FLOOR
        score = _bigram_score("xqzjkfvb")
        # Random strings have mostly unseen bigrams → close to floor
        assert score <= _BIGRAM_FLOOR + 0.5


# ---------------------------------------------------------------------------
# extract_features: main label extraction
# ---------------------------------------------------------------------------

class TestExtractMainLabel:
    def test_simple_domain(self):
        assert _extract_main_label("google.com") == "google"

    def test_www_stripped(self):
        assert _extract_main_label("www.google.com") == "google"

    def test_subdomain_stripped(self):
        assert _extract_main_label("abc.evil.co.uk") == "evil"

    def test_multi_part_suffix(self):
        assert _extract_main_label("example.co.uk") == "example"

    def test_ip_address_returns_none(self):
        assert _extract_main_label("192.168.1.1") == None

    def test_empty_string_returns_none(self):
        assert _extract_main_label("") == None

    def test_very_long_domain_returns_none(self):
        long_domain = "a" * 260 + ".com"
        assert _extract_main_label(long_domain) == None

    def test_trailing_dot_handled(self):
        # FQDN style
        result = _extract_main_label("google.com.")
        assert result == "google"


# ---------------------------------------------------------------------------
# extract_features: full function tests
# ---------------------------------------------------------------------------

class TestExtractFeatures:
    """Parametrised over a representative set of inputs."""

    def test_normal_domain_returns_seven_keys(self):
        feats = extract_features("google.com")
        assert feats is not None
        expected_keys = {
            "label_length", "shannon_entropy", "vowel_ratio",
            "digit_ratio", "longest_consonant_run", "digit_count",
            "bigram_score",
        }
        assert set(feats.keys()) == expected_keys

    def test_normal_domain_values_sensible(self):
        feats = extract_features("google.com")
        assert feats is not None
        assert feats["label_length"] == 6.0           # "google"
        assert 0.0 <= feats["vowel_ratio"] <= 1.0
        assert feats["digit_ratio"] == 0.0
        assert feats["digit_count"] == 0.0

    def test_random_looking_domain_high_entropy(self):
        feats = extract_features("xvz7q2mnd8k.com")
        assert feats is not None
        # Entropy should be higher than a clean English word
        assert feats["shannon_entropy"] > 2.5

    def test_random_domain_has_digits(self):
        feats = extract_features("abc123xyz.com")
        assert feats is not None
        assert feats["digit_count"] > 0
        assert feats["digit_ratio"] > 0.0

    def test_empty_string_returns_none(self):
        assert extract_features("") is None

    def test_whitespace_returns_none(self):
        assert extract_features("   ") is None

    def test_ip_address_returns_none(self):
        assert extract_features("10.0.0.1") is None

    def test_private_ip_returns_none(self):
        assert extract_features("192.168.100.1") is None

    def test_very_long_domain_returns_none(self):
        assert extract_features("a" * 260 + ".com") is None

    def test_unicode_domain_handled_without_crash(self):
        # Should either return features or None — must never raise.
        result = extract_features("bücher.de")
        # No assertion on value, only that it did not raise.
        assert result is None or isinstance(result, dict)

    def test_unicode_domain_with_valid_ascii_fallback(self):
        # "xn--bcher-kva.de" is the IDNA for "bücher.de"
        result = extract_features("xn--bcher-kva.de")
        assert result is None or isinstance(result, dict)

    def test_all_features_are_floats(self):
        feats = extract_features("randomdomain.net")
        assert feats is not None
        for key, val in feats.items():
            assert isinstance(val, float), f"{key} is not float: {val!r}"

    def test_vowel_ratio_in_range(self):
        feats = extract_features("amazon.com")
        assert feats is not None
        assert 0.0 <= feats["vowel_ratio"] <= 1.0

    def test_longest_consonant_run_non_negative(self):
        feats = extract_features("strength.com")
        assert feats is not None
        assert feats["longest_consonant_run"] >= 0

    @pytest.mark.parametrize("domain", [
        "google.com",
        "amazon.com",
        "microsoft.com",
        "github.com",
        "stackoverflow.com",
    ])
    def test_well_known_domains_do_not_crash(self, domain):
        """Well-known benign domains should return features without error."""
        result = extract_features(domain)
        assert result is not None

    @pytest.mark.parametrize("domain", [
        "xvz7q2mnd8k.com",
        "a3f9bq1zxy.net",
        "kdjfh3829dkf.org",
        "qzxkpvm82.io",
    ])
    def test_random_looking_domains_do_not_crash(self, domain):
        """Random-looking domains should return features without error."""
        result = extract_features(domain)
        assert result is not None


# ---------------------------------------------------------------------------
# DGAClassifier: missing model file behaviour
# ---------------------------------------------------------------------------

class TestDGAClassifierMissingModel:
    def test_returns_none_when_model_file_missing(self, tmp_path):
        """predict_proba must return None (not raise) if model file is absent."""
        missing_path = tmp_path / "nonexistent_model.joblib"
        clf = DGAClassifier(model_path=missing_path)
        result = clf.predict_proba("xvz7q2mnd8.com")
        assert result is None

    def test_does_not_raise_on_repeated_calls_without_model(self, tmp_path):
        """Subsequent calls after a missing-file failure must also not raise."""
        missing_path = tmp_path / "nonexistent_model.joblib"
        clf = DGAClassifier(model_path=missing_path)
        for _ in range(5):
            result = clf.predict_proba("xvz7q2mnd8.com")
            assert result is None

    def test_returns_none_for_empty_domain_without_model(self, tmp_path):
        missing_path = tmp_path / "nonexistent_model.joblib"
        clf = DGAClassifier(model_path=missing_path)
        assert clf.predict_proba("") is None

    def test_returns_none_for_ip_without_model(self, tmp_path):
        missing_path = tmp_path / "nonexistent_model.joblib"
        clf = DGAClassifier(model_path=missing_path)
        assert clf.predict_proba("192.168.1.1") is None

    def test_model_state_is_false_after_missing_file(self, tmp_path):
        """Internal sentinel must be False (not None) so we don't retry on each call."""
        missing_path = tmp_path / "nonexistent_model.joblib"
        clf = DGAClassifier(model_path=missing_path)
        clf.predict_proba("anyvalue.com")
        assert clf._model is False


# ---------------------------------------------------------------------------
# DGAClassifier: with a real (tiny) mock model
# ---------------------------------------------------------------------------

class TestDGAClassifierWithMockModel:
    """Verify the classifier works end-to-end when a model IS present."""

    @pytest.fixture()
    def mock_model_path(self, tmp_path):
        """Create a tiny but real scikit-learn model saved with joblib."""
        try:
            from sklearn.ensemble import RandomForestClassifier
            import joblib
            from detection.dga_classifier import extract_features, _FEATURE_ORDER
        except ImportError:
            pytest.skip("scikit-learn/joblib not installed")

        # Minimal training data: 4 benign + 4 random
        benign = ["google.com", "amazon.com", "github.com", "microsoft.com"]
        dga = ["xvz7q2mnd8.com", "a3f9bq1z.net", "kdjfh3829dkf.org", "qzxkpvm82.io"]
        X, y = [], []
        for d, lbl in [(x, 0) for x in benign] + [(x, 1) for x in dga]:
            f = extract_features(d)
            if f:
                X.append([f[k] for k in _FEATURE_ORDER])
                y.append(lbl)

        clf = RandomForestClassifier(n_estimators=10, random_state=42)
        clf.fit(X, y)

        path = tmp_path / "mock_model.joblib"
        joblib.dump(clf, path)
        return path

    def test_predict_proba_returns_float(self, mock_model_path):
        clf = DGAClassifier(model_path=mock_model_path)
        score = clf.predict_proba("xvz7q2mnd8.com")
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_predict_proba_returns_none_for_ip(self, mock_model_path):
        clf = DGAClassifier(model_path=mock_model_path)
        assert clf.predict_proba("192.168.1.1") is None

    def test_predict_proba_returns_none_for_empty(self, mock_model_path):
        clf = DGAClassifier(model_path=mock_model_path)
        assert clf.predict_proba("") is None
