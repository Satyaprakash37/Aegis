"""Nmap scanner runner service.

Executes asynchronous, threaded port scanning and service fingerprinting.
"""

import asyncio
import logging
from typing import Any, Dict, List
import nmap

logger = logging.getLogger("aegis.scanner")


class ScanExecutionError(Exception):
    """Raised when an Nmap scan fails due to target reachability or execution errors."""
    pass


def _execute_nmap_sync(ip_address: str, scan_type: str) -> List[Dict[str, Any]]:
    """Synchronous Nmap execution designed to run within a worker thread."""
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError as e:
        logger.error(f"Nmap binary not found or initialization error: {e}")
        raise ScanExecutionError(f"Nmap scanner initialization failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error initializing PortScanner: {e}")
        raise ScanExecutionError(f"Scanner engine initialization error: {e}")

    # Determine command arguments based on scan depth
    # -T4 provides aggressive timing without saturating networks
    # -sV probes open ports to determine service and version info
    scan_type_str = str(scan_type).lower()
    if "quick" in scan_type_str:
        args = "-sV --top-ports 100 -T4"
    else:
        args = "-sV -p 1-1000 -T4"

    try:
        logger.info(f"Starting Nmap scan on {ip_address} with arguments: '{args}'")
        nm.scan(hosts=ip_address, arguments=args)
    except Exception as e:
        logger.error(f"Nmap execution error on target {ip_address}: {e}")
        raise ScanExecutionError(f"Nmap execution failed: {e}")

    # Check if host responded
    all_hosts = nm.all_hosts()
    if not all_hosts:
        logger.warning(f"Target host {ip_address} produced no response or is offline")
        raise ScanExecutionError(f"Target host {ip_address} is offline or unreachable")

    host_key = ip_address if ip_address in all_hosts else all_hosts[0]
    host_state = nm[host_key].state()

    if host_state == "down":
        logger.warning(f"Target host {ip_address} marked as down by Nmap")
        raise ScanExecutionError(f"Target host {ip_address} is down or unreachable")

    open_ports: List[Dict[str, Any]] = []

    # Parse protocols and open port details
    for proto in nm[host_key].all_protocols():
        ports_dict = nm[host_key][proto]
        for port in sorted(ports_dict.keys()):
            port_info = ports_dict[port]
            if port_info.get("state") == "open":
                open_ports.append({
                    "port": int(port),
                    "protocol": proto,
                    "service": port_info.get("name", "") or "",
                    "version": port_info.get("version", "") or "",
                    "product": port_info.get("product", "") or "",
                    "extrainfo": port_info.get("extrainfo", "") or "",
                    "cpe": port_info.get("cpe", "") or "",
                })

    logger.info(f"Nmap scan completed for {ip_address}: {len(open_ports)} open port(s) detected")
    return open_ports


async def run_nmap_scan(ip_address: str, scan_type: str) -> List[Dict[str, Any]]:
    """Execute Nmap scan asynchronously in a worker thread to keep the event loop responsive."""
    return await asyncio.to_thread(_execute_nmap_sync, ip_address, scan_type)
