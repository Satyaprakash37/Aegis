"""Rate limiting configuration for AEGIS platform."""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Global limiter instance: 300 requests/minute general default
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["300/minute"],
)
