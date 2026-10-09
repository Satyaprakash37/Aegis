"""Metasploit RPC Client Bridge for AEGIS v2.0 Attack Lab.

Provides isolated connection management to the containerized Metasploit
RPC daemon (msfrpcd) on the internal lab network.
"""

import logging
from typing import Any, Dict, Optional
from pymetasploit3.msfrpc import MsfRpcClient

from app.core.config import settings

logger = logging.getLogger("aegis.agent.msf_client")


def connect_msf(
    password: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    ssl: Optional[bool] = None,
) -> MsfRpcClient:
    """Connect to Metasploit RPC daemon.
    
    Args:
        password: RPC authentication password. Defaults to settings.MSF_RPC_PASSWORD.
        host: Metasploit host address. Defaults to settings.MSF_RPC_HOST.
        port: Metasploit RPC port. Defaults to settings.MSF_RPC_PORT.
        ssl: SSL enabled flag. Defaults to settings.MSF_RPC_SSL (False for lab).
        
    Returns:
        MsfRpcClient instance.
    """
    rpc_password = password or settings.MSF_RPC_PASSWORD
    rpc_host = host or settings.MSF_RPC_HOST
    rpc_port = port or settings.MSF_RPC_PORT
    rpc_ssl = settings.MSF_RPC_SSL if ssl is None else ssl

    logger.info("Connecting to Metasploit RPC daemon at %s:%s (ssl=%s)", rpc_host, rpc_port, rpc_ssl)
    
    # pymetasploit3 uses username='msf' by default which matches msfrpcd default
    client = MsfRpcClient(
        password=rpc_password,
        server=rpc_host,
        port=rpc_port,
        ssl=rpc_ssl,
        username="msf",
    )
    return client


def get_msf_status() -> Dict[str, Any]:
    """Check connectivity to msfrpcd and return daemon telemetry and module inventory.
    
    Returns:
        Dict containing connection status, version, and module counts or error details.
    """
    try:
        client = connect_msf()
        version_info = client.core.version
        stats_info = client.core.stats
        
        exploits_count = stats_info.get("exploits", 0)
        auxiliary_count = stats_info.get("auxiliary", 0)
        post_count = stats_info.get("post", 0)
        payloads_count = stats_info.get("payloads", 0)
        encoders_count = stats_info.get("encoders", 0)
        evasions_count = stats_info.get("evasions", 0)
        nops_count = stats_info.get("nops", 0)
        total_modules = exploits_count + auxiliary_count + post_count + payloads_count + encoders_count + evasions_count + nops_count
        
        msf_version_str = version_info.get("version", "Unknown") if isinstance(version_info, dict) else str(version_info)

        return {
            "connected": True,
            "status": "online",
            "version": msf_version_str,
            "modules_count": total_modules,
            "breakdown": {
                "exploits": exploits_count,
                "auxiliary": auxiliary_count,
                "post": post_count,
                "payloads": payloads_count,
                "encoders": encoders_count,
                "evasions": evasions_count,
                "nops": nops_count,
            },
            "summary": f"Msf version: {msf_version_str}, modules: {total_modules}+",
            "host": settings.MSF_RPC_HOST,
            "port": settings.MSF_RPC_PORT,
        }
    except Exception as exc:
        logger.warning("Metasploit RPC health check failed: %s", exc)
        return {
            "connected": False,
            "status": "offline",
            "error": f"Metasploit container not reachable or authentication failed: {str(exc)}",
            "host": settings.MSF_RPC_HOST,
            "port": settings.MSF_RPC_PORT,
            "version": None,
            "modules_count": 0,
        }
