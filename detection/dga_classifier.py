"""DGA (Domain Generation Algorithm) classifier for DNS log analysis.

Provides feature extraction from domain names and a lazy-loaded
scikit-learn classifier that scores a domain's DGA likelihood.
"""
from __future__ import annotations

import math
import re
import unicodedata
from pathlib import Path
from typing import Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_MODEL_PATH = _PROJECT_ROOT / "models" / "dga_model.joblib"

_MAX_LABEL_LEN = 253

_VOWELS = frozenset("aeiou")
_CONSONANTS = frozenset("bcdfghjklmnpqrstvwxyz")

# Reference English character-bigram log-probabilities (base-10).
# Derived from large English corpora; baked in so no extra file is needed.
_BIGRAM_LOG_PROBS: Dict[str, float] = {
    "th": -1.18, "he": -1.26, "in": -1.32, "er": -1.35, "an": -1.38,
    "re": -1.42, "on": -1.46, "en": -1.51, "at": -1.55, "es": -1.57,
    "ed": -1.60, "nd": -1.62, "to": -1.64, "or": -1.66, "ea": -1.68,
    "ti": -1.70, "ar": -1.72, "te": -1.74, "ng": -1.76, "al": -1.78,
    "it": -1.80, "as": -1.82, "is": -1.84, "ha": -1.86, "et": -1.88,
    "se": -1.90, "ou": -1.92, "of": -1.94, "le": -1.96, "sa": -1.98,
}
_BIGRAM_FLOOR = -3.5  # log-prob for unseen bigrams

# Detect bare IPv4 addresses.
_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Representative set of known two-part public suffixes.
_MULTI_SUFFIXES = frozenset({
    "co.uk", "org.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.in", "net.in", "org.in", "ac.in",
    "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.br", "net.br", "org.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "edu.cn",
    "co.za", "org.za", "net.za",
})

# Feature order must match the column order used during model training.
_FEATURE_ORDER: List[str] = [
    "label_length",
    "shannon_entropy",
    "vowel_ratio",
    "digit_ratio",
    "longest_consonant_run",
    "digit_count",
    "bigram_score",
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _to_ascii(domain: str) -> Optional[str]:
    """Convert an IDN/unicode domain to ASCII (IDNA) form."""
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        normalized = unicodedata.normalize("NFKD", domain)
        ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
        return ascii_only if ascii_only else None


def _extract_main_label(domain: str) -> Optional[str]:
    """Return the registrable (main) label of a domain.

    Examples::

        "www.google.com"       -> "google"
        "abc.evil.co.uk"       -> "evil"
        "xvz123.com"           -> "xvz123"
        "192.168.1.1"          -> None   (IP address)
        ""                     -> None
        "a" * 260 + ".com"     -> None   (too long)
    """
    if not domain:
        return None

    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return None

    domain_ascii = _to_ascii(domain)
    if not domain_ascii:
        return None

    if _IP_RE.match(domain_ascii):
        return None

    if len(domain_ascii) > _MAX_LABEL_LEN:
        return None

    parts = domain_ascii.split(".")
    if len(parts) < 2:
        return None

    candidate_suffix = ".".join(parts[-2:])
    if candidate_suffix in _MULTI_SUFFIXES and len(parts) >= 3:
        main_label = parts[-3]
    else:
        main_label = parts[-2]

    return main_label if main_label else None


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits) of string *s*."""
    if not s:
        return 0.0
    n = len(s)
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _longest_consonant_run(s: str) -> int:
    """Length of the longest consecutive run of consonant characters."""
    max_run = cur = 0
    for ch in s:
        if ch in _CONSONANTS:
            cur += 1
            if cur > max_run:
                max_run = cur
        else:
            cur = 0
    return max_run


def _bigram_score(s: str) -> float:
    """Mean English bigram log-probability (lower = more random)."""
    if len(s) < 2:
        return _BIGRAM_FLOOR
    bigrams = [s[i: i + 2] for i in range(len(s) - 1)]
    total = sum(_BIGRAM_LOG_PROBS.get(bg, _BIGRAM_FLOOR) for bg in bigrams)
    return total / len(bigrams)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_features(domain: str) -> Optional[Dict[str, float]]:
    """Extract seven numeric features from *domain* for DGA classification.

    Args:
        domain: A raw domain string (e.g. ``"www.google.com"``).

    Returns:
        Dict with seven float features, or ``None`` when the input is
        invalid (empty string, bare IP, excessively long, unresolvable
        unicode, etc.).

    Feature keys:
        * ``label_length``          – character count of the main label
        * ``shannon_entropy``       – Shannon entropy of the main label
        * ``vowel_ratio``           – fraction of vowels in the main label
        * ``digit_ratio``           – fraction of digits in the main label
        * ``longest_consonant_run`` – length of the longest consonant run
        * ``digit_count``           – absolute number of digit characters
        * ``bigram_score``          – mean English bigram log-probability
    """
    label = _extract_main_label(domain)
    if label is None:
        return None

    n = len(label)
    if n == 0:
        return None

    vowel_count = sum(1 for ch in label if ch in _VOWELS)
    digit_count = sum(1 for ch in label if ch.isdigit())

    return {
        "label_length": float(n),
        "shannon_entropy": _shannon_entropy(label),
        "vowel_ratio": vowel_count / n,
        "digit_ratio": digit_count / n,
        "longest_consonant_run": float(_longest_consonant_run(label)),
        "digit_count": float(digit_count),
        "bigram_score": _bigram_score(label),
    }


class DGAClassifier:
    """Lazy-loading wrapper around a persisted scikit-learn DGA model.

    The model file is loaded from disk on the first call to
    :meth:`predict_proba`.  If the file is missing the classifier logs a
    warning and returns ``None`` for every subsequent call — the rest of
    the application continues running normally.

    Usage::

        clf = DGAClassifier()
        score = clf.predict_proba("xvz7q2mnd8.com")  # float in [0,1] or None
    """

    def __init__(self, model_path: Optional[Path] = None) -> None:
        self._model_path: Path = Path(model_path) if model_path else _MODEL_PATH
        # Possible states:
        #   None  – not yet attempted
        #   False – attempted; file missing or load failed (do not retry)
        #   <obj> – loaded scikit-learn estimator
        self._model = None

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _load(self) -> bool:
        """Try to load the model from disk.  Returns True on success."""
        if not self._model_path.exists():
            logger.warning(
                "dga_model_not_found",
                path=str(self._model_path),
                hint="Run 'python scripts/train_dga.py' to generate the model.",
            )
            self._model = False
            return False
        try:
            import joblib  # deferred – only pay the import cost if the file exists

            self._model = joblib.load(self._model_path)
            logger.info("dga_model_loaded", path=str(self._model_path))
            return True
        except Exception as exc:
            logger.warning(
                "dga_model_load_failed",
                path=str(self._model_path),
                error=str(exc),
            )
            self._model = False
            return False

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def predict_proba(self, domain: str) -> Optional[float]:
        """Return the DGA probability for *domain*.

        Args:
            domain: Raw domain string to score.

        Returns:
            A float in ``[0, 1]`` representing the probability that the
            domain was DGA-generated, or ``None`` when:

            * the model file has not been trained / is missing,
            * the domain is invalid (empty, IP, too long, etc.), or
            * any unexpected error occurs.

            This method **never raises**.
        """
        try:
            if self._model is None:
                self._load()

            if self._model is False:
                return None

            feats = extract_features(domain)
            if feats is None:
                return None

            X = [[feats[k] for k in _FEATURE_ORDER]]
            # predict_proba returns shape (n_samples, n_classes).
            # Index 1 is the DGA / positive class.
            proba = self._model.predict_proba(X)
            return float(proba[0][1])

        except Exception as exc:
            logger.warning("dga_predict_failed", domain=domain, error=str(exc))
            return None
