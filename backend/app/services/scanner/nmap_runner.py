"""Nmap scanner runner service.

Executes asynchronous, threaded port scanning and service fingerprinting
with non-root TCP connect mode (-sT), no-ping direct probing (-Pn),
automatic retry on transient failures, and unreachable host detection.
"""

import asyncio
import logging
import time
from typing import Any, Dict, List
import nmap

logger = logging.getLogger("aegis.scanner")


class ScanExecutionError(Exception):
    """Raised when an Nmap scan fails due to target reachability or execution errors."""
    pass


def _execute_nmap_sync(ip_address: str, scan_type: str) -> List[Dict[str, Any]]:
    """Synchronous Nmap execution designed to run within a worker thread.
    
    Includes 2-attempt retry logic, unprivileged TCP Connect (-sT), and
    no-ping (-Pn) mode to reliably scan firewalled and hardened targets.
    """
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError as e:
        logger.error(f"Nmap binary not found or initialization error: {e}")
        raise ScanExecutionError(f"Nmap scanner initialization failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error initializing PortScanner: {e}")
        raise ScanExecutionError(f"Scanner engine initialization error: {e}")

    # Determine command arguments based on scan depth
    # -sT: TCP connect scan (operates unprivileged as appuser without raw socket privileges)
    # -Pn: Skip host discovery ping (prevents false 2-second aborts on firewalled servers)
    # -sV: Probe open ports to determine service and product version
    # -T4: Aggressive timing without network flooding
    scan_type_str = str(scan_type).lower()
    if "quick" in scan_type_str:
        args = "-sT -sV -Pn --top-ports 100 -T4 --host-timeout 3m"
    else:
        args = "-sT -sV -Pn -p 1-1000 -T4 --host-timeout 5m"

    max_attempts = 2
    last_error: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(
                f"[Attempt {attempt}/{max_attempts}] Starting Nmap scan on {ip_address} "
                f"with arguments: '{args}'"
            )
            nm.scan(hosts=ip_address, arguments=args)

            # Check if host responded
            all_hosts = nm.all_hosts()
            if not all_hosts:
                logger.warning(f"Target host {ip_address} produced no response or is offline on attempt {attempt}")
                if attempt < max_attempts:
                    time.sleep(2)
                    continue
                raise ScanExecutionError(f"Target host {ip_address} is offline or unreachable")

            host_key = ip_address if ip_address in all_hosts else all_hosts[0]
            host_state = nm[host_key].state()

            if host_state == "down":
                logger.warning(f"Target host {ip_address} marked as down by Nmap on attempt {attempt}")
                if attempt < max_attempts:
                    time.sleep(2)
                    continue
                raise ScanExecutionError(f"Target host {ip_address} is down or unreachable")

            open_ports: List[Dict[str, Any]] = []
            all_ports_no_response = True
            total_probed = 0

            # Parse protocols and open port details
            for proto in nm[host_key].all_protocols():
                ports_dict = nm[host_key][proto]
                for port in sorted(ports_dict.keys()):
                    total_probed += 1
                    port_info = ports_dict[port]
                    state = port_info.get("state", "")
                    reason = port_info.get("reason", "")

                    if state == "open":
                        all_ports_no_response = False
                        open_ports.append({
                            "port": int(port),
                            "protocol": proto,
                            "service": port_info.get("name", "") or "",
                            "version": port_info.get("version", "") or "",
                            "product": port_info.get("product", "") or "",
                            "extrainfo": port_info.get("extrainfo", "") or "",
                            "cpe": port_info.get("cpe", "") or "",
                        })
                    elif state == "closed" or "refused" in reason:
                        # Received TCP RST: Host is alive and responsive even if port is closed
                        all_ports_no_response = False

            # If no open ports detected and no protocols responded or all ports timed out with no response
            if len(open_ports) == 0 and (len(nm[host_key].all_protocols()) == 0 or (total_probed > 0 and all_ports_no_response)):
                logger.warning(
                    f"Target host {ip_address}: zero responsive ports or protocols detected "
                    f"(all probed ports timed out) on attempt {attempt}"
                )
                if attempt < max_attempts:
                    time.sleep(2)
                    continue
                raise ScanExecutionError(
                    f"Target host {ip_address} is offline or unreachable - all probed ports timed out without response."
                )

            logger.info(
                f"Nmap scan completed successfully for {ip_address}: "
                f"{len(open_ports)} open port(s) detected (Attempt {attempt})"
            )
            return open_ports

        except ScanExecutionError as see:
            last_error = see
            if attempt < max_attempts:
                logger.warning(f"Retrying scan on {ip_address} due to: {see}")
                time.sleep(2)
                continue
            raise

        except Exception as e:
            last_error = e
            logger.error(f"Nmap execution error on target {ip_address} (attempt {attempt}): {e}")
            if attempt < max_attempts:
                time.sleep(2)
                continue
            raise ScanExecutionError(f"Nmap execution failed on {ip_address}: {e}")

    if last_error:
        raise ScanExecutionError(str(last_error))
    raise ScanExecutionError(f"Target host {ip_address} is offline or unreachable")


async def run_nmap_scan(ip_address: str, scan_type: str) -> List[Dict[str, Any]]:
    """Execute Nmap scan asynchronously in a worker thread to keep the event loop responsive."""
    return await asyncio.to_thread(_execute_nmap_sync, ip_address, scan_type)
