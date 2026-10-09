"""AEGIS v2.0 Attack Lab & Agent Services."""
from app.services.agent.msf_client import connect_msf, get_msf_status

__all__ = ["connect_msf", "get_msf_status"]
