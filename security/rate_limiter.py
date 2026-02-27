"""IP-based rate limiting for API endpoints."""
from slowapi import Limiter
from slowapi.util import get_remote_address
from utils.config import settings


# Initialize rate limiter with IP-based key function
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{settings.rate_limit_default}/minute"],
    storage_uri="memory://",
    strategy="fixed-window"
)


def get_limiter():
    """Get the rate limiter instance."""
    return limiter
