"""Nmap scanner runner service.

Executes asynchronous, threaded port scanning and deep service fingerprinting
with TCP connect mode (-sT), no-ping direct probing (-Pn), firewall evasion
flags (-f, --data-length 24, -T2 stealth retry), ARP ping bypass (--disable-arp-ping),
TCP ACK scan fallback (-sA), and targeted banner grabbing for MySQL/MariaDB, FTP, and HTTP.
"""

import asyncio
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
from typing import Any, Dict, List, Optional
import nmap

logger = logging.getLogger("aegis.scanner")

CRITICAL_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,"
    "1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,8888,9090,27017,61616"
)


class ScanExecutionError(Exception):
    """Raised when an Nmap scan fails due to target reachability or execution errors."""
    pass


def _probe_mysql_handshake(ip: str, port: int = 3306, timeout: float = 3.5) -> Dict[str, str]:
    """Parse MySQL/MariaDB initial handshake packet to extract greeting banner and exact version."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        data = s.recv(1024)
        s.close()
        if len(data) > 5 and data[4] == 10:  # Protocol::HandshakeV10
            raw_version = data[5:].split(b"\x00")[0].decode("utf-8", errors="ignore").strip()
            if raw_version:
                is_mariadb = "mariadb" in raw_version.lower()
                clean_ver = re.sub(r"^5\.5\.5-", "", raw_version, flags=re.IGNORECASE)
                m = re.search(r"(\d+(\.\d+)+)", clean_ver)
                ver_num = m.group(1) if m else clean_ver
                return {
                    "product": "MariaDB" if is_mariadb else "MySQL",
                    "version": ver_num,
                    "extrainfo": raw_version,
                }
    except Exception as e:
        logger.debug(f"MySQL handshake probe skipped or failed on {ip}:{port}: {e}")
    return {}


def _probe_ftp_banner(ip: str, port: int = 21, timeout: float = 3.5) -> Dict[str, str]:
    """Grab FTP 220 server greeting banner and identify daemon product and version."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        if banner.startswith("220"):
            res: Dict[str, str] = {"extrainfo": banner}
            for name in ["vsftpd", "ProFTPD", "Pure-FTPd", "FileZilla Server", "Microsoft FTP Service"]:
                if name.lower() in banner.lower():
                    res["product"] = name
                    m = re.search(rf"{re.escape(name)}\s*([0-9.]+)", banner, re.IGNORECASE)
                    if m:
                        res["version"] = m.group(1)
                    break
            return res
    except Exception as e:
        logger.debug(f"FTP banner probe skipped or failed on {ip}:{port}: {e}")
    return {}


def _probe_http_banner(ip: str, port: int, timeout: float = 4.0) -> Dict[str, str]:
    """Probe HTTP/HTTPS service for Server header and technology detection via socket and httpx."""
    use_ssl = port in (443, 8443)
    scheme = "https" if use_ssl else "http"
    res: Dict[str, str] = {}

    # 1. Direct socket HTTP HEAD / banner grab
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(sock)
        else:
            s = sock
        s.connect((ip, port))
        req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: AEGIS-Fingerprint\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        data = s.recv(2048).decode("utf-8", errors="ignore")
        s.close()
        for line in data.splitlines():
            if line.lower().startswith("server:"):
                server_val = line.split(":", 1)[1].strip()
                res["extrainfo"] = f"Server: {server_val}"
                parts = server_val.split("/", 1)
                res["product"] = parts[0].strip()
                if len(parts) > 1:
                    res["version"] = parts[1].split()[0].strip()
                break
    except Exception as e:
        logger.debug(f"HTTP socket banner grab failed on {ip}:{port}: {e}")

    # 2. If httpx binary is available and product is still missing, probe with httpx
    if not res.get("product"):
        httpx_bin = shutil.which("httpx") or "/usr/local/bin/httpx"
        if os.path.exists(httpx_bin):
            try:
                cmd = [
                    httpx_bin,
                    "-u", f"{scheme}://{ip}:{port}",
                    "-silent",
                    "-tech-detect",
                    "-webserver",
                    "-json",
                    "-timeout", "4",
                ]
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                if p.stdout.strip():
                    rec = json.loads(p.stdout.strip().splitlines()[0])
                    ws = rec.get("webserver")
                    if ws:
                        res["extrainfo"] = f"Server: {ws}"
                        parts = ws.split("/", 1)
                        res["product"] = parts[0].strip()
                        if len(parts) > 1:
                            res["version"] = parts[1].split()[0].strip()
            except Exception:
                pass
    return res


def _enrich_open_ports_fingerprint(ip_address: str, open_ports: List[Dict[str, Any]]) -> None:
    """Enrich open ports with deep targeted banner grabbing for unspecified/generic versions."""
    for p in open_ports:
        port_num = p.get("port")
        service = (p.get("service") or "").lower()
        version = p.get("version") or ""
        product = p.get("product") or ""

        # MariaDB / MySQL port 3306
        if port_num == 3306 or "mysql" in service or "mariadb" in service:
            if not version or "5.5.5" in version or not product or product.lower() in ("mysql", "mariadb"):
                extra = _probe_mysql_handshake(ip_address, port_num)
                if extra:
                    if extra.get("product"):
                        p["product"] = extra["product"]
                    if extra.get("version"):
                        p["version"] = extra["version"]
                    if extra.get("extrainfo"):
                        p["extrainfo"] = extra["extrainfo"]

        # FTP port 21
        elif port_num == 21 or "ftp" in service:
            if not version or not product:
                extra = _probe_ftp_banner(ip_address, port_num)
                if extra:
                    if extra.get("product"):
                        p["product"] = extra["product"]
                    if extra.get("version"):
                        p["version"] = extra["version"]
                    if extra.get("extrainfo"):
                        p["extrainfo"] = extra["extrainfo"]

        # HTTP / HTTPS ports
        elif port_num in (80, 443, 8080, 8443) or "http" in service:
            if not version or not product:
                extra = _probe_http_banner(ip_address, port_num)
                if extra:
                    if extra.get("product") and not product:
                        p["product"] = extra["product"]
                    if extra.get("version") and not version:
                        p["version"] = extra["version"]
                    if extra.get("extrainfo"):
                        p["extrainfo"] = f"{p.get('extrainfo', '')} {extra['extrainfo']}".strip()


def _execute_tcp_ack_fallback(nm: nmap.PortScanner, ip_address: str) -> int:
    """Execute TCP ACK scan (-sA) to map filtered vs unfiltered ports through stateful packet filters.
    
    Returns the count of unfiltered ports detected (which proves host reachability).
    """
    ack_args = "-sA -Pn --top-ports 100 --disable-arp-ping -T4 --host-timeout 2m"
    try:
        logger.info(f"Executing TCP ACK fallback scan on {ip_address} with arguments: '{ack_args}'")
        nm.scan(hosts=ip_address, arguments=ack_args)
        all_hosts = nm.all_hosts()
        if not all_hosts:
            return 0
        host_key = ip_address if ip_address in all_hosts else all_hosts[0]
        unfiltered_count = 0
        for proto in nm[host_key].all_protocols():
            for _, pinfo in nm[host_key][proto].items():
                if pinfo.get("state") == "unfiltered":
                    unfiltered_count += 1
        logger.info(f"TCP ACK scan on {ip_address} identified {unfiltered_count} unfiltered port(s)")
        return unfiltered_count
    except Exception as e:
        logger.warning(f"TCP ACK scan fallback encountered error on {ip_address}: {e}")
        return 0


def _execute_nmap_sync(ip_address: str, scan_type: str) -> List[Dict[str, Any]]:
    """Synchronous Nmap execution designed to run within a worker thread.
    
    Features:
    - Smart Host Discovery with -Pn and --disable-arp-ping fallback
    - Firewall Evasion with -f, --data-length 24, -T2 stealth retry
    - Deep Version Fingerprinting with --version-intensity 7 and socket/httpx banner grabs
    - TCP ACK scan (-sA) reachability fallback
    """
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError as e:
        logger.error(f"Nmap binary not found or initialization error: {e}")
        raise ScanExecutionError(f"Nmap scanner initialization failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error initializing PortScanner: {e}")
        raise ScanExecutionError(f"Scanner engine initialization error: {e}")

    scan_type_str = str(scan_type).lower()
    is_quick = "quick" in scan_type_str

    # Build scan command variations for initial attempt and stealth retry
    # Attempt 1: Standard high-speed scan
    if is_quick:
        args_attempt1 = "-sT -sV -Pn --top-ports 100 -T4 --version-intensity 7 --host-timeout 5m"
        args_attempt2 = "-sT -sV -Pn --top-ports 100 -T3 --disable-arp-ping --version-intensity 7 --host-timeout 5m"
    else:
        args_attempt1 = (
            f"-sT -sV -Pn -p 1-1000,{CRITICAL_PORTS} -T4 -f --data-length 24 "
            f"--version-intensity 7 --script-timeout 30s --host-timeout 6m"
        )
        args_attempt2 = (
            f"-sT -sV -Pn -p 1-1000,{CRITICAL_PORTS} -T2 --disable-arp-ping -f --data-length 24 "
            f"--version-intensity 7 --script-timeout 30s --host-timeout 8m"
        )

    attempts = [
        (1, args_attempt1),
        (2, args_attempt2),
    ]

    last_error: Optional[Exception] = None

    for attempt_num, args in attempts:
        try:
            logger.info(
                f"[Attempt {attempt_num}/{len(attempts)}] Starting Nmap scan on {ip_address} "
                f"with arguments: '{args}'"
            )
            nm.scan(hosts=ip_address, arguments=args)

            # Check if host responded
            all_hosts = nm.all_hosts()
            if not all_hosts:
                logger.warning(f"Target host {ip_address} produced no response or is offline on attempt {attempt_num}")
                if attempt_num < len(attempts):
                    time.sleep(2)
                    continue
                break

            host_key = ip_address if ip_address in all_hosts else all_hosts[0]
            host_state = nm[host_key].state()

            if host_state == "down":
                logger.warning(f"Target host {ip_address} marked as down by Nmap on attempt {attempt_num}")
                if attempt_num < len(attempts):
                    time.sleep(2)
                    continue
                break

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

            # If open ports found, enrich versions with targeted banner grabs and return
            if open_ports:
                logger.info(
                    f"Nmap scan completed for {ip_address}: {len(open_ports)} open port(s) detected. "
                    f"Initiating targeted version fingerprinting..."
                )
                _enrich_open_ports_fingerprint(ip_address, open_ports)
                logger.info(
                    f"Nmap scan + fingerprinting completed successfully for {ip_address}: "
                    f"{len(open_ports)} port(s) mapped."
                )
                return open_ports

            # If responsive RSTs observed but 0 open ports: target is alive but no ports open
            if not all_ports_no_response and len(open_ports) == 0:
                logger.info(f"Target host {ip_address} responded (alive) but no scanned ports are open.")
                return []

            # If all probed ports timed out without any response
            logger.warning(
                f"Target host {ip_address}: all {total_probed} probed ports timed out on attempt {attempt_num}"
            )
            if attempt_num < len(attempts):
                time.sleep(2)
                continue

        except ScanExecutionError as see:
            last_error = see
            if attempt_num < len(attempts):
                logger.warning(f"Retrying scan on {ip_address} due to: {see}")
                time.sleep(2)
                continue
            break

        except Exception as e:
            last_error = e
            logger.error(f"Nmap execution error on target {ip_address} (attempt {attempt_num}): {e}")
            if attempt_num < len(attempts):
                time.sleep(2)
                continue
            break

    # Host discovery fallback: execute TCP ACK scan to determine if target is alive behind firewall
    logger.info(f"Initiating TCP ACK discovery fallback for target {ip_address}...")
    unfiltered_ports = _execute_tcp_ack_fallback(nm, ip_address)
    if unfiltered_ports > 0:
        logger.info(
            f"Target host {ip_address} is ALIVE and reachable ({unfiltered_ports} unfiltered ports via TCP ACK), "
            f"but no open listening services were found on the scanned port range."
        )
        return []

    if last_error:
        raise ScanExecutionError(str(last_error))
    raise ScanExecutionError(
        f"Target host {ip_address} is offline or unreachable - all probed ports timed out without response."
    )


async def run_nmap_scan(ip_address: str, scan_type: str) -> List[Dict[str, Any]]:
    """Execute Nmap scan asynchronously in a worker thread to keep the event loop responsive."""
    return await asyncio.to_thread(_execute_nmap_sync, ip_address, scan_type)
