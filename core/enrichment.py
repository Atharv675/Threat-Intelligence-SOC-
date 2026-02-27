"""Enrichment layer for threat intelligence (GeoIP, ASN, WHOIS)."""
from typing import Dict, Any, Optional
from security.validation import EnrichedEvent, NormalizedEvent, IOCType
from utils.logger import get_logger
import re
import hashlib

logger = get_logger(__name__)


# Realistic-looking mock data pools keyed by hash bucket (deterministic variation)
_COUNTRIES = [
    "United States", "China", "Russia", "Germany", "Netherlands",
    "United Kingdom", "Brazil", "Ukraine", "Romania", "Iran",
    "South Korea", "Japan", "India", "Canada", "France",
]

_ORGS = [
    "AS-CHOOPA", "CHINANET", "ROSTELECOM", "HETZNER", "DIGITALOCEAN",
    "OVH SAS", "CLARO SA", "KYIVSTAR", "RCS-RDS", "DADEH GOSTAR ASR",
    "KAKAO", "NTT Communications", "TATA COMMUNICATIONS", "ROGERS",
    "ORANGE SA",
]

_ASNS = [
    "AS20473", "AS4134", "AS12389", "AS24940", "AS14061",
    "AS16276", "AS28573", "AS15895", "AS8708", "AS58224",
    "AS32010", "AS2527", "AS4755", "AS812", "AS5410",
]

_REGISTRARS = [
    "GoDaddy", "Namecheap", "Tucows", "Google Domains", "Enom",
    "Network Solutions", "MarkMonitor", "Name.com", "Hover", "Gandi",
]


def _bucket(value: str, n: int) -> int:
    """Hash value string into a 0..n-1 bucket deterministically."""
    h = int(hashlib.md5(value.encode()).hexdigest(), 16)
    return h % n


class Enrichment:
    """Enrich threat intelligence with contextual data."""

    def __init__(self):
        """Initialize enrichment modules."""
        pass

    @staticmethod
    def enrich_geoip(value: str, ioc_type: IOCType) -> Optional[Dict[str, Any]]:
        """
        Enrich IP address with GeoIP data.

        Uses deterministic hashing for demo variation — replace with
        MaxMind GeoIP2 in production.
        """
        if ioc_type != IOCType.IP:
            return None

        try:
            # Private IP ranges
            if (
                value.startswith("192.168.")
                or value.startswith("10.")
                or value.startswith("172.1")
                or value.startswith("172.2")
                or value.startswith("172.3")
                or value == "127.0.0.1"
            ):
                return {
                    "country": "Private Network",
                    "city": "Internal",
                    "latitude": 0.0,
                    "longitude": 0.0,
                    "is_private": True,
                }

            # Deterministic realistic country for public IPs
            country = _COUNTRIES[_bucket(value, len(_COUNTRIES))]
            # Rough lat/lon by country bucket (just for demo)
            lat_map = {
                "United States": 37.0902, "China": 35.8617, "Russia": 61.5240,
                "Germany": 51.1657, "Netherlands": 52.1326, "United Kingdom": 55.3781,
                "Brazil": -14.2350, "Ukraine": 48.3794, "Romania": 45.9432, "Iran": 32.4279,
                "South Korea": 35.9078, "Japan": 36.2048, "India": 20.5937,
                "Canada": 56.1304, "France": 46.2276,
            }
            lon_map = {
                "United States": -95.7129, "China": 104.1954, "Russia": 105.3188,
                "Germany": 10.4515, "Netherlands": 5.2913, "United Kingdom": -3.4360,
                "Brazil": -51.9253, "Ukraine": 31.1656, "Romania": 24.9668, "Iran": 53.6880,
                "South Korea": 127.7669, "Japan": 138.2529, "India": 78.9629,
                "Canada": -106.3468, "France": 2.2137,
            }

            return {
                "country": country,
                "city": "N/A",
                "latitude": round(lat_map.get(country, 0.0), 4),
                "longitude": round(lon_map.get(country, 0.0), 4),
                "is_private": False,
            }

        except Exception as e:
            logger.error("geoip_enrichment_failed", error=str(e), value=value)
            return None

    @staticmethod
    def enrich_asn(value: str, ioc_type: IOCType) -> Optional[Dict[str, Any]]:
        """
        Enrich IP address with ASN data.

        Uses deterministic hashing for demo variation.
        """
        if ioc_type != IOCType.IP:
            return None

        try:
            # Private IPs
            if (
                value.startswith("192.168.")
                or value.startswith("10.")
                or value == "127.0.0.1"
            ):
                return {
                    "asn": "AS00000",
                    "organization": "Private Network",
                    "network": "192.168.0.0/16",
                }

            idx = _bucket(value, len(_ASNS))
            return {
                "asn": _ASNS[idx],
                "organization": _ORGS[idx],
                "network": f"{value.rsplit('.', 1)[0]}.0/24",
            }

        except Exception as e:
            logger.error("asn_enrichment_failed", error=str(e), value=value)
            return None

    @staticmethod
    def enrich_whois(value: str, ioc_type: IOCType) -> Optional[Dict[str, Any]]:
        """
        Enrich domain/URL with WHOIS data.

        Uses deterministic hashing for demo variation.
        """
        if ioc_type not in [IOCType.DOMAIN, IOCType.URL]:
            return None

        try:
            domain = value
            if ioc_type == IOCType.URL:
                m = re.search(r"(?:https?://)?(?:www\.)?([^/?#]+)", value)
                if m:
                    domain = m.group(1)

            registrar = _REGISTRARS[_bucket(domain, len(_REGISTRARS))]

            # Vary "age" so some domains look newly registered (suspicious)
            age_bucket = _bucket(domain + "age", 5)
            age_years = [0, 0, 1, 3, 7][age_bucket]   # 0=brand-new, 7=established
            creation_hint = f"{2024 - age_years}-{((_bucket(domain, 12)) + 1):02d}-01"

            return {
                "domain": domain,
                "registrar": registrar,
                "creation_date": creation_hint,
                "expiration_date": None,
                "registrant": "REDACTED FOR PRIVACY",
                "newly_registered": age_years == 0,
            }

        except Exception as e:
            logger.error("whois_enrichment_failed", error=str(e), value=value)
            return None

    @classmethod
    def enrich(cls, event: NormalizedEvent) -> EnrichedEvent:
        """
        Enrich a normalized event with all applicable enrichment data.

        Args:
            event: Normalized event

        Returns:
            Enriched event with GeoIP, ASN, and WHOIS data where applicable
        """
        enriched_data = event.model_dump()

        geo_data   = cls.enrich_geoip(event.value, event.type)
        asn_data   = cls.enrich_asn(event.value, event.type)
        whois_data = cls.enrich_whois(event.value, event.type)

        enriched_data.update(
            {
                "geo_data": geo_data,
                "asn_data": asn_data,
                "whois_data": whois_data,
            }
        )

        enriched = EnrichedEvent(**enriched_data)
        logger.debug("event_enriched", value=event.value, ioc_type=event.type)
        return enriched
