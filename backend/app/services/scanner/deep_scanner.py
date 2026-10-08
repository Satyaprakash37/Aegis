"""Deep Reconnaissance & Active Vulnerability Scanner (Phase 8.3).

Implements the 7-stage professional web reconnaissance and active verification engine:
- STAGE 1: Subdomain Discovery (subfinder)
- STAGE 2: Live Web Probing & Tech Stack Detection (httpx)
- STAGE 3: Smart Port Scanning (Nmap CDN-aware + NSE scripts)
- STAGE 4: Expanded Nuclei Active Web Exploitation
- STAGE 5: SSL/TLS Cryptographic Audit (testssl.sh)
- STAGE 6: Technology Version Vulnerability Analysis
- STAGE 7: Aggregation, Deduplication & Recon Inventory Summary
"""

import asyncio
import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import nmap

from app.core.config import settings
from app.models.vulnerability import VulnerabilitySeverity, VerificationType
from app.services.scanner.nmap_runner import (
    ScanExecutionError,
    CRITICAL_PORTS,
    _enrich_open_ports_fingerprint,
)

logger = logging.getLogger("aegis.scanner.deep")

CDN_CIDR_NETWORKS = [
    ipaddress.ip_network(cidr) for cidr in [
        # Cloudflare IPv4 ranges
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
        "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
        "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
        # Fastly
        "151.101.0.0/16", "199.232.0.0/16",
        # Akamai
        "23.0.0.0/12", "104.64.0.0/10",
        # AWS CloudFront / WAF
        "13.32.0.0/15", "13.35.0.0/16", "18.64.0.0/14", "52.84.0.0/15",
        "54.192.0.0/16", "54.230.0.0/16", "65.8.0.0/16", "65.9.0.0/16",
        "99.84.0.0/16", "99.86.0.0/16", "205.251.192.0/19",
    ]
]


def _is_cdn_ip(ip_str: str) -> bool:
    """Determine whether an IP address belongs to known CDN edge subnets."""
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in CDN_CIDR_NETWORKS:
            if ip_obj in net:
                return True
    except ValueError:
        pass
    return False

WAF_SIGNATURES: List[Tuple[str, str]] = [
    ("bitninja", "BitNinja WAF"),
    ("cloudflare", "Cloudflare WAF"),
    ("modsecurity", "ModSecurity WAF"),
    ("incapsula", "Imperva Incapsula WAF"),
    ("wordfence", "Wordfence WAF"),
    ("sucuri", "Sucuri CloudProxy WAF"),
    ("aws waf", "AWS WAF"),
    ("akamai", "Akamai Kona Site Defender"),
    ("f5 big-ip", "F5 BIG-IP ASM"),
]

# Mapping of known NSE scripts to CVEs and titles
NSE_SCRIPT_CVE_MAP: Dict[str, Dict[str, Any]] = {
    "smb-vuln-ms17-010": {
        "cve_id": "CVE-2017-0144",
        "title": "EternalBlue SMBv1 Remote Code Execution",
        "cvss_score": 8.1,
        "severity": VulnerabilitySeverity.high,
        "description": "Remote code execution flaw in Microsoft SMBv1 protocol actively verified by NSE script.",
    },
    "ssl-heartbleed": {
        "cve_id": "CVE-2014-0160",
        "title": "Heartbleed OpenSSL TLS Information Disclosure",
        "cvss_score": 7.5,
        "severity": VulnerabilitySeverity.high,
        "description": "OpenSSL TLS heartbeat extension memory leakage flaw actively verified by NSE probe.",
    },
    "http-vuln-cve2021-44228": {
        "cve_id": "CVE-2021-44228",
        "title": "Log4Shell Apache Log4j2 JNDI Remote Code Execution",
        "cvss_score": 10.0,
        "severity": VulnerabilitySeverity.critical,
        "description": "Apache Log4j2 JNDI injection vulnerability actively verified via HTTP probe.",
    },
    "rdp-vuln-ms12-020": {
        "cve_id": "CVE-2012-0002",
        "title": "MS12-020 Windows Remote Desktop RCE / DoS",
        "cvss_score": 9.3,
        "severity": VulnerabilitySeverity.critical,
        "description": "Remote Desktop Protocol vulnerability actively verified by NSE script.",
    },
    "http-shellshock": {
        "cve_id": "CVE-2014-6271",
        "title": "Shellshock GNU Bash Environment Variable Injection RCE",
        "cvss_score": 9.8,
        "severity": VulnerabilitySeverity.critical,
        "description": "GNU Bash trailing function definition vulnerability actively confirmed.",
    },
    "ssl-ccs-injection": {
        "cve_id": "CVE-2014-0224",
        "title": "OpenSSL ChangeCipherSpec Man-in-the-Middle Injection",
        "cvss_score": 7.4,
        "severity": VulnerabilitySeverity.high,
        "description": "OpenSSL Early CCS handshake flaw actively verified by TLS handshake probe.",
    },
    "ftp-vsftpd-backdoor": {
        "cve_id": "CVE-2011-2523",
        "title": "vsftpd 2.3.4 Smiley Face Backdoor Command Execution",
        "cvss_score": 10.0,
        "severity": VulnerabilitySeverity.critical,
        "description": "Compromised vsftpd source archive backdoor triggered on port 6200.",
    },
}

# Known vulnerable software technology patterns
TECH_VULN_CATALOG: List[Dict[str, Any]] = [
    {
        "pattern": r"wordpress(?::|\s+)?([3-5]\.[\d\.]+)?",
        "name": "WordPress",
        "cve_id": "CVE-2022-21661",
        "title": "WordPress Core Outdated Deployment - SQL Injection & RCE Risk",
        "cvss": 7.5,
        "severity": VulnerabilitySeverity.high,
        "description": "Detected outdated WordPress instance subject to multiple unpatched security advisories.",
        "remediation": "Update WordPress to the latest stable release (6.x+).",
    },
    {
        "pattern": r"php(?::|\s+)?([5-7]\.[0-2][\d\.]*)?",
        "name": "PHP",
        "cve_id": "CVE-2019-11043",
        "title": "End-of-Life PHP Runtime Detected",
        "cvss": 9.8,
        "severity": VulnerabilitySeverity.critical,
        "description": "Target server runs an unsupported, end-of-life PHP runtime vulnerable to remote code execution.",
        "remediation": "Upgrade PHP runtime to a supported version (PHP 8.2+).",
    },
    {
        "pattern": r"jquery(?::|\s+)?([1-2]\.[\d\.]+|3\.[0-4][\d\.]*)?",
        "name": "jQuery",
        "cve_id": "CVE-2020-11022",
        "title": "Outdated jQuery Core - Cross-Site Scripting / Prototype Pollution",
        "cvss": 6.1,
        "severity": VulnerabilitySeverity.medium,
        "description": "The client-side web application includes an outdated version of jQuery containing known XSS flaws.",
        "remediation": "Upgrade jQuery library to version 3.5.0 or later.",
    },
    {
        "pattern": r"apache(?::|\s+)?(2\.4\.49|2\.4\.50|2\.2[\d\.]*)?",
        "name": "Apache",
        "cve_id": "CVE-2021-41773",
        "title": "Outdated Apache HTTP Server - Path Traversal & RCE Advisory",
        "cvss": 7.5,
        "severity": VulnerabilitySeverity.high,
        "description": "Detected Apache HTTP Server banner matching vulnerable path traversal release branches.",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or higher.",
    },
    {
        "pattern": r"gunicorn(?::|\s+)?(19\.[\d\.]+|20\.0[\d\.]*)?",
        "name": "gunicorn",
        "cve_id": "CVE-2024-1135",
        "title": "Outdated Gunicorn WSGI Server - HTTP Request Smuggling Risk",
        "cvss": 6.5,
        "severity": VulnerabilitySeverity.medium,
        "description": "Target application is served by an outdated Gunicorn WSGI server susceptible to request smuggling.",
        "remediation": "Upgrade Gunicorn to version 22.0.0 or later.",
    },
]


COMMON_DNS_PREFIXES: List[str] = [
    "www", "mail", "webmail", "ftp", "smtp", "ns1", "ns2", "vpn",
    "api", "dev", "test", "staging", "portal", "erp", "crm", "admin",
    "cpanel", "webdisk", "autodiscover", "autoconfig", "campusone",
    "admission", "moodle", "app"
]


def _ensure_subfinder_config() -> Optional[str]:
    """Write ~/.config/subfinder/provider-config.yaml if API keys are configured."""
    vt_key = getattr(settings, "SUBFINDER_VIRUSTOTAL_KEY", "").strip()
    st_key = getattr(settings, "SUBFINDER_SECURITYTRAILS_KEY", "").strip()
    if not vt_key and not st_key:
        return None

    config_dir = os.path.expanduser("~/.config/subfinder")
    try:
        os.makedirs(config_dir, exist_ok=True)
        config_path = os.path.join(config_dir, "provider-config.yaml")
        lines = []
        if vt_key:
            lines.append("virustotal:")
            lines.append(f"  - {vt_key}")
        if st_key:
            lines.append("securitytrails:")
            lines.append(f"  - {st_key}")
        with open(config_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return config_path
    except Exception as e:
        logger.warning(f"[STAGE 1] Failed to write subfinder provider config: {e}")
        return None


def _run_subfinder_discovery(clean_domain: str) -> Set[str]:
    """Method 1: Subfinder discovery with -all, -max-time 1, -timeout 15 and retry logic."""
    subfinder_bin = shutil.which("subfinder") or "/usr/local/bin/subfinder"
    if not os.path.exists(subfinder_bin):
        logger.warning(f"[STAGE 1] subfinder binary not found at '{subfinder_bin}'. Skipping.")
        return set()

    cfg_path = _ensure_subfinder_config()
    cmd = [
        subfinder_bin,
        "-d", clean_domain,
        "-silent",
        "-all",
        "-max-time", "1",
        "-timeout", "15",
    ]
    if cfg_path and os.path.exists(cfg_path):
        cmd.extend(["-pc", cfg_path])

    for attempt in range(2):
        results: Set[str] = set()
        try:
            logger.info(f"[STAGE 1] Invoking subfinder (attempt {attempt + 1}): {' '.join(cmd)}")
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            for line in proc.stdout.splitlines():
                sub = line.strip().lower()
                if sub and (sub.endswith("." + clean_domain) or sub == clean_domain):
                    results.add(sub)
            if results or attempt == 1:
                return results
        except Exception as e:
            logger.warning(f"[STAGE 1] subfinder attempt {attempt + 1} error on {clean_domain}: {e}")
            if attempt == 0:
                time.sleep(5)
    return set()


def _run_crtsh_discovery(clean_domain: str) -> Set[str]:
    """Method 2: Certificate Transparency discovery via crt.sh with retry and HackerTarget fallback."""
    results: Set[str] = set()
    crt_url = f"https://crt.sh/?q=%25.{clean_domain}&output=json"

    # Attempt crt.sh with 1 retry
    for attempt in range(2):
        try:
            req = urllib.request.Request(
                crt_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    for entry in data:
                        name_val = entry.get("name_value", "")
                        for line in name_val.split("\n"):
                            sub = line.strip().lower()
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub and (sub.endswith("." + clean_domain) or sub == clean_domain):
                                results.add(sub)
                    if results:
                        logger.info(f"[STAGE 1] crt.sh discovered {len(results)} subdomains on attempt {attempt + 1}")
                        return results
        except Exception as e:
            logger.warning(f"[STAGE 1] crt.sh attempt {attempt + 1} failed for {clean_domain}: {e}")
            if attempt == 0:
                time.sleep(5)

    # Secondary CT / passive fallback: HackerTarget hostsearch
    ht_url = f"https://api.hackertarget.com/hostsearch/?q={clean_domain}"
    try:
        logger.info(f"[STAGE 1] Invoking secondary CT/passive fallback (HackerTarget) for {clean_domain}")
        req = urllib.request.Request(
            ht_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line and "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if sub and (sub.endswith("." + clean_domain) or sub == clean_domain):
                        results.add(sub)
        logger.info(f"[STAGE 1] Secondary passive source discovered {len(results)} subdomains for {clean_domain}")
    except Exception as e:
        logger.warning(f"[STAGE 1] Secondary passive source failed for {clean_domain}: {e}")

    return results


def _run_dns_brute_discovery(clean_domain: str) -> Set[str]:
    """Method 3: Active DNS brute-force discovery for common infrastructure prefixes."""
    discovered: Set[str] = set()

    def _resolve_prefix(prefix: str) -> Optional[str]:
        candidate = f"{prefix}.{clean_domain}"
        try:
            socket.gethostbyname(candidate)
            return candidate
        except Exception:
            return None

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_resolve_prefix, p) for p in COMMON_DNS_PREFIXES]
            for f in concurrent.futures.as_completed(futures):
                try:
                    res = f.result()
                    if res:
                        discovered.add(res)
                except Exception:
                    pass
        logger.info(f"[STAGE 1] DNS brute-force discovered {len(discovered)} subdomains for {clean_domain}")
    except Exception as e:
        logger.warning(f"[STAGE 1] DNS brute-force error on {clean_domain}: {e}")

    return discovered


def _run_stage1_subdomains(domain: str) -> Tuple[List[str], Dict[str, Any]]:
    """Stage 1: Multi-method layered subdomain discovery (Subfinder + CT Logs + DNS Brute)."""
    clean_domain = domain.split(":")[0].strip().lower()

    # 1. Run Subfinder
    subfinder_subs = _run_subfinder_discovery(clean_domain)

    # 2. Run CT Logs (crt.sh / HackerTarget fallback)
    crtsh_subs = _run_crtsh_discovery(clean_domain)

    # 3. Run DNS Brute-force
    brute_subs = _run_dns_brute_discovery(clean_domain)

    # Union all results + ensure apex domain is present
    all_discovered = subfinder_subs | crtsh_subs | brute_subs | {clean_domain}
    total_found = len(all_discovered)

    summary_str = f"subfinder: {len(subfinder_subs)}, crt.sh: {len(crtsh_subs)}, brute: {len(brute_subs)} → total {total_found}"
    logger.info(f"[STAGE 1] Layered subdomain discovery complete: {summary_str}")

    discovery_note = None
    if total_found <= 1:
        discovery_note = (
            "Limited subdomains discovered (<=1). Consider adding API keys in settings or "
            "verifying target is not a single-host deployment."
        )

    result_list = sorted(list(all_discovered))
    if len(result_list) > 100:
        logger.info(f"[STAGE 1] Capping discovered subdomains from {len(result_list)} to 100")
        result_list = result_list[:100]

    stats = {
        "subfinder_count": len(subfinder_subs),
        "crtsh_count": len(crtsh_subs),
        "dns_brute_count": len(brute_subs),
        "total": total_found,
        "summary": summary_str,
        "discovery_note": discovery_note,
    }

    return result_list, stats


def _run_stage2_live_probing(
    subdomains: List[str],
    domain: str,
    resolved_ip: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Stage 2: Live Web Probing and Technology Detection using httpx."""
    httpx_bin = shutil.which("httpx") or "/usr/local/bin/httpx"
    live_hosts: List[Dict[str, Any]] = []

    if not os.path.exists(httpx_bin):
        logger.warning(f"[STAGE 2] httpx binary not found at '{httpx_bin}'. Skipping.")
        return [{
            "url": f"https://{domain}",
            "title": domain,
            "status_code": 200,
            "tech": [],
            "host": domain,
            "ip": resolved_ip or "127.0.0.1",
            "cdn": False,
        }]

    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".txt") as tf:
        for sub in subdomains:
            tf.write(f"{sub}\n")
        temp_input_path = tf.name

    try:
        cmd = [
            httpx_bin,
            "-l", temp_input_path,
            "-silent",
            "-title",
            "-tech-detect",
            "-status-code",
            "-ip",
            "-follow-redirects",
            "-json",
            "-timeout", "8",
            "-retries", "1",
            "-threads", "30",
        ]
        logger.info(f"[STAGE 2] Invoking httpx: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
                url = rec.get("url", "")
                if not url:
                    continue

                cdn_name = rec.get("cdn_name") or ""
                cdn_type = rec.get("cdn_type") or ""
                webserver = (rec.get("webserver") or "").lower()
                is_cdn = bool(
                    cdn_name or cdn_type or
                    _is_cdn_ip(main_ip) or
                    any(_is_cdn_ip(aip) for aip in host_ips) or
                    any(c in webserver for c in ["cloudflare", "fastly", "akamai", "cloudfront", "incapsula"])
                )

                host_ips = rec.get("a") or []
                main_ip = rec.get("host_ip") or (host_ips[0] if host_ips else "")

                # Detect WAF signatures in webserver, cdn_name, or detected technologies
                host_waf = None
                combined_host_str = f"{webserver} {cdn_name} {' '.join(rec.get('tech') or [])}".lower()
                for sig_key, sig_label in WAF_SIGNATURES:
                    if sig_key in combined_host_str:
                        host_waf = sig_label
                        break

                live_hosts.append({
                    "url": url,
                    "title": rec.get("title") or rec.get("host") or domain,
                    "status_code": rec.get("status_code", 200),
                    "tech": rec.get("tech") or [],
                    "host": rec.get("host") or domain,
                    "ip": main_ip,
                    "all_ips": host_ips,
                    "cdn": is_cdn,
                    "cdn_name": cdn_name,
                    "webserver": rec.get("webserver") or "",
                    "waf": host_waf,
                })
            except Exception:
                continue
    except Exception as e:
        logger.error(f"[STAGE 2] httpx probing failed: {e}")
    finally:
        if os.path.exists(temp_input_path):
            os.remove(temp_input_path)

    # Fallback if no subdomains replied: probe domain directly
    if not live_hosts:
        logger.info(f"[STAGE 2] No subdomains responded. Using fallback host for {domain}")
        live_hosts.append({
            "url": f"https://{domain}",
            "title": domain,
            "status_code": 200,
            "tech": [],
            "host": domain,
            "ip": resolved_ip or "127.0.0.1",
            "all_ips": [resolved_ip] if resolved_ip else [],
            "cdn": False,
            "cdn_name": "",
            "webserver": "",
        })

    logger.info(f"[STAGE 2] Live web probing completed: {len(live_hosts)} active service(s) discovered")
    return live_hosts


def _resolve_and_verify_origin_infrastructure(
    live_hosts: List[Dict[str, Any]],
    subdomains: List[str],
    root_domain: str,
    resolved_ip: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Stage 3.5: Virtual Host Resolution & Origin Infrastructure Mapping.

    Identifies proxy-fronted domains, enumerates candidate origin server IPs via sibling
    subnet inference and direct-hosted DNS resolutions, and actively verifies origin hosting
    using standard virtual host routing (Host header probing).

    Returns:
        (origin_infrastructure_map, list_of_confirmed_origin_ips)
    """
    logger.info(f"[ORIGIN AUDIT] Initiating origin detection and vhost mapping for {root_domain}...")
    httpx_bin = shutil.which("httpx") or "/usr/local/bin/httpx"
    if not os.path.exists(httpx_bin):
        logger.warning(f"[ORIGIN AUDIT] httpx binary not found at '{httpx_bin}'. Skipping origin vhost verification.")
        return [], []

    # 1. Identify proxy-fronted hosts
    cdn_hosts: List[Dict[str, Any]] = []
    for h in live_hosts:
        hip = h.get("ip") or ""
        all_ips = h.get("all_ips") or []
        if h.get("cdn") or _is_cdn_ip(hip) or any(_is_cdn_ip(aip) for aip in all_ips):
            cdn_hosts.append(h)

    # If apex resolved IP is CDN, add root domain if not already in cdn_hosts
    if resolved_ip and _is_cdn_ip(resolved_ip):
        if not any(h.get("host") == root_domain for h in cdn_hosts):
            cdn_hosts.append({
                "host": root_domain,
                "ip": resolved_ip,
                "cdn_name": "Edge Proxy",
                "url": f"https://{root_domain}",
            })

    if not cdn_hosts:
        logger.info(f"[ORIGIN AUDIT] No CDN edge proxies detected on {root_domain}. Target is direct-hosted.")
        return [], []

    logger.info(f"[ORIGIN AUDIT] Detected {len(cdn_hosts)} CDN-fronted host(s). Enumerating candidate origin IPs...")

    # 2. Candidate Origin Gathering
    candidate_ips: Set[str] = set()

    # A. Sibling Subnet Inference from Direct-Hosted Subdomains
    direct_ips: Set[str] = set()
    for h in live_hosts:
        hip = h.get("ip") or ""
        if hip and hip != "127.0.0.1" and not _is_cdn_ip(hip):
            direct_ips.add(hip)
        for aip in h.get("all_ips") or []:
            if aip and aip != "127.0.0.1" and not _is_cdn_ip(aip):
                direct_ips.add(aip)

    # Also resolve top direct/internal subdomains to uncover non-CDN IPs
    for sub in subdomains[:40]:
        try:
            sip = socket.gethostbyname(sub)
            if sip and sip != "127.0.0.1" and not _is_cdn_ip(sip):
                direct_ips.add(sip)
        except Exception:
            pass

    # For every direct IP, add the IP itself and test adjacent sibling IPs in its /24
    for dip in direct_ips:
        candidate_ips.add(dip)
        parts = dip.split(".")
        if len(parts) == 4:
            prefix = ".".join(parts[:3])
            try:
                last_byte = int(parts[3])
                for delta in range(-6, 8):
                    b = last_byte + delta
                    if 1 <= b <= 254:
                        candidate_ips.add(f"{prefix}.{b}")
            except ValueError:
                pass

    # B. Private/Sandbox Network Support (e.g., Docker 172.20.0.x / 192.168.x / 10.x)
    for ch in cdn_hosts:
        cip = ch.get("ip") or ""
        if cip.startswith("172.") or cip.startswith("192.168.") or cip.startswith("10."):
            parts = cip.split(".")
            if len(parts) == 4:
                prefix = ".".join(parts[:3])
                for b in range(1, 15):
                    candidate_ips.add(f"{prefix}.{b}")

    # Exclude CDN IPs, loopbacks, and the proxy edge IPs themselves
    proxy_edge_ips = {ch.get("ip") for ch in cdn_hosts if ch.get("ip")}
    if resolved_ip:
        proxy_edge_ips.add(resolved_ip)

    filtered_candidates = [
        ip for ip in candidate_ips
        if not _is_cdn_ip(ip) and ip not in ("127.0.0.1", "0.0.0.0") and ip not in proxy_edge_ips
    ]
    # Prioritize exact direct IPs discovered first
    ordered_candidates = list(direct_ips.intersection(filtered_candidates)) + [
        ip for ip in filtered_candidates if ip not in direct_ips
    ]
    # Cap to top 25 candidates for swift execution
    ordered_candidates = ordered_candidates[:25]
    logger.info(f"[ORIGIN AUDIT] Testing {len(ordered_candidates)} candidate origin IPs across virtual hosts...")

    # 3. Virtual Host Verification Probe
    origin_map: List[Dict[str, Any]] = []
    confirmed_origin_ips: Set[str] = set()

    # Target vhosts to test: primary apex and top 2 CDN subdomains
    target_vhosts = []
    seen_vhosts = set()
    for ch in cdn_hosts:
        vhost = ch.get("host") or root_domain
        if vhost not in seen_vhosts:
            seen_vhosts.add(vhost)
            target_vhosts.append(ch)
    target_vhosts = target_vhosts[:3]

    for vhost_entry in target_vhosts:
        vhost_domain = vhost_entry.get("host") or root_domain
        proxy_ip = vhost_entry.get("ip") or ""
        proxy_name = vhost_entry.get("cdn_name") or "Edge Proxy"

        # Determine ports to probe
        ports_to_probe = [443, 80]
        # In docker/private environments, include port 3000 (Juice Shop / internal services)
        if any(c.startswith("172.") or c.startswith("10.") or c.startswith("192.168.") for c in ordered_candidates):
            ports_to_probe.extend([3000, 8080])

        for cand_ip in ordered_candidates:
            for port in ports_to_probe:
                scheme = "https" if port in (443, 8443) else "http"
                target_url = f"{scheme}://{cand_ip}:{port}"
                cmd = [
                    httpx_bin,
                    "-u", target_url,
                    "-H", f"Host: {vhost_domain}",
                    "-status-code",
                    "-title",
                    "-tech-detect",
                    "-silent",
                    "-json",
                    "-timeout", "4",
                    "-retries", "1",
                ]
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
                    for line in proc.stdout.splitlines():
                        line = line.strip()
                        if not line.startswith("{"):
                            continue
                        try:
                            rec = json.loads(line)
                            sc = rec.get("status_code")
                            if not sc:
                                continue

                            title = rec.get("title") or ""
                            tech = rec.get("tech") or []
                            title_lower = title.lower()
                            domain_core = root_domain.split(".")[0].lower()

                            # Criteria for confirmed origin:
                            # 1) HTTP 200 with domain name or app in title
                            # 2) HTTP 200 without CDN error page
                            # 3) Redirect (301, 302, 307, 308) indicating vhost dispatching
                            is_confirmed = False
                            if sc == 200:
                                if (
                                    domain_core in title_lower or
                                    "centurion" in title_lower or
                                    "cutm" in title_lower or
                                    "juice shop" in title_lower or
                                    (title and "cloudflare" not in title_lower and "access denied" not in title_lower)
                                ):
                                    is_confirmed = True
                                elif len(rec.get("a") or []) > 0:
                                    is_confirmed = True
                            elif sc in (301, 302, 307, 308):
                                is_confirmed = True

                            confidence = "confirmed" if is_confirmed else "inferred"
                            if is_confirmed:
                                confirmed_origin_ips.add(cand_ip)

                            mapping_entry = {
                                "domain": vhost_domain,
                                "proxy_ip": proxy_ip,
                                "proxy_name": proxy_name,
                                "origin_ip": cand_ip,
                                "origin_port": port,
                                "scheme": scheme,
                                "confidence": confidence,
                                "status_code": sc,
                                "title": title or ("Active Service" if sc == 200 else f"HTTP {sc}"),
                                "tech": tech,
                                "routed_via": f"Host: {vhost_domain}",
                            }
                            # Deduplicate mapping entries
                            if not any(
                                m["domain"] == vhost_domain and m["origin_ip"] == cand_ip and m["origin_port"] == port
                                for m in origin_map
                            ):
                                origin_map.append(mapping_entry)
                                logger.info(
                                    f"[ORIGIN AUDIT] Discovered origin {cand_ip}:{port} for {vhost_domain} "
                                    f"({confidence.upper()} - HTTP {sc} '{title}')"
                                )
                        except json.JSONDecodeError:
                            continue
                except Exception as e:
                    logger.debug(f"[ORIGIN AUDIT] Probe exception for {target_url}: {e}")

    logger.info(
        f"[ORIGIN AUDIT] Mapping completed: {len(origin_map)} total origin mappings, "
        f"{len(confirmed_origin_ips)} confirmed origin IP(s) bypassing edge proxy."
    )
    return origin_map, list(confirmed_origin_ips)


def _run_stage3_port_scan_single_ip(
    ip: str,
    is_cdn: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Stage 3: Port and NSE scan on a single IP address."""
    nm = nmap.PortScanner()
    open_ports: List[Dict[str, Any]] = []
    nse_findings: List[Dict[str, Any]] = []

    try:
        # CDN IPs scanned light (top 100), real origin IPs scanned deep (top 1000 + critical port coverage)
        frag_flag = "-f " if (hasattr(os, "geteuid") and os.geteuid() == 0) else ""
        port_args = (
            "-sT -sV -Pn --top-ports 100 -T4 --version-intensity 7 --host-timeout 3m"
            if is_cdn
            else f"-sT -sV -Pn -p 1-1000,{CRITICAL_PORTS} -T4 {frag_flag}--data-length 24 --version-intensity 7 --script-timeout 30s --host-timeout 5m"
        )
        logger.info(f"[STAGE 3] Port scanning {ip} (is_cdn={is_cdn}, args='{port_args}')")
        nm.scan(hosts=ip, arguments=port_args)

        all_hosts = nm.all_hosts()
        if not all_hosts:
            return [], []

        host_key = ip if ip in all_hosts else all_hosts[0]
        for proto in nm[host_key].all_protocols():
            pdict = nm[host_key][proto]
            for port_num, pdata in pdict.items():
                if pdata.get("state") == "open":
                    open_ports.append({
                        "ip": ip,
                        "port": int(port_num),
                        "protocol": proto,
                        "service": pdata.get("name", "unknown"),
                        "version": pdata.get("version", ""),
                        "product": pdata.get("product", ""),
                        "extrainfo": pdata.get("extrainfo", ""),
                        "cpe": pdata.get("cpe", ""),
                    })

        # Deep version fingerprinting for unspecified/generic versions
        if open_ports:
            _enrich_open_ports_fingerprint(ip, open_ports)

        # Run NSE script vuln only on real backend servers with open ports
        if not is_cdn and open_ports:
            port_spec = ",".join(str(p["port"]) for p in open_ports[:15])
            nse_args = (
                f"-sT -sV -Pn --script vuln -p {port_spec} -T4 {frag_flag}--data-length 24 "
                f"--version-intensity 7 --host-timeout 5m --script-timeout 30s"
            )
            logger.info(f"[STAGE 3] Executing Nmap NSE scripts on {ip}:{port_spec}")
            nm.scan(hosts=ip, arguments=nse_args)

            if host_key in nm.all_hosts():
                for proto in nm[host_key].all_protocols():
                    for port_num, pdata in nm[host_key][proto].items():
                        script_results = pdata.get("script", {})
                        for script_id, script_output in script_results.items():
                            lower_out = script_output.lower()
                            if "vuln" in lower_out or "vulnerable" in lower_out or "exploitable" in lower_out:
                                meta = NSE_SCRIPT_CVE_MAP.get(script_id, {
                                    "cve_id": f"CVE-NSE-{script_id.upper().replace('-', '_')}",
                                    "title": f"Nmap NSE Detected Flaw: {script_id}",
                                    "cvss_score": 7.5,
                                    "severity": VulnerabilitySeverity.high,
                                    "description": f"Vulnerability detected by Nmap script {script_id}.",
                                })
                                nse_findings.append({
                                    "cve_id": meta["cve_id"],
                                    "title": meta["title"],
                                    "description": meta["description"],
                                    "cvss_score": meta["cvss_score"],
                                    "severity": meta["severity"],
                                    "port": int(port_num),
                                    "service": pdata.get("name", ""),
                                    "verification": VerificationType.nse_verified.value,
                                    "evidence": f"Target: {ip}:{port_num}\nNSE Script: {script_id}\nOutput:\n{script_output[:1000]}",
                                    "source": f"nse:{script_id}",
                                })
    except Exception as e:
        logger.error(f"[STAGE 3] Nmap scan failed for {ip}: {e}")

    return open_ports, nse_findings


def _parse_nuclei_record(
    record: Dict[str, Any],
    target_url: str,
    open_ports: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Convert raw Nuclei JSON match record to AEGIS vulnerability schema."""
    template_id = record.get("template-id", "unknown")
    info = record.get("info", {})
    name = info.get("name", template_id)
    description = info.get("description", name)
    severity_str = info.get("severity", "medium").lower()

    classification = info.get("classification", {}) or {}
    cve_field = classification.get("cve-id")
    cve_id = None
    if isinstance(cve_field, list) and cve_field:
        cve_id = str(cve_field[0]).upper()
    elif isinstance(cve_field, str) and cve_field:
        cve_id = cve_field.upper()
    else:
        cve_match = re.search(r"cve-\d{4}-\d{4,7}", template_id, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(0).upper()
        else:
            cve_id = f"CVE-ACTIVE-{template_id.upper().replace('-', '_')}"

    severity_map = {
        "critical": VulnerabilitySeverity.critical,
        "high": VulnerabilitySeverity.high,
        "medium": VulnerabilitySeverity.medium,
        "low": VulnerabilitySeverity.low,
        "info": VulnerabilitySeverity.low,
    }
    severity_enum = severity_map.get(severity_str, VulnerabilitySeverity.medium)

    cvss_val = classification.get("cvss-score")
    if cvss_val is not None:
        try:
            cvss_score = float(cvss_val)
        except (ValueError, TypeError):
            cvss_score = 6.0
    else:
        default_cvss = {
            VulnerabilitySeverity.critical: 9.5,
            VulnerabilitySeverity.high: 8.0,
            VulnerabilitySeverity.medium: 5.5,
            VulnerabilitySeverity.low: 3.5,
        }
        cvss_score = default_cvss.get(severity_enum, 5.0)

    matched_at = record.get("matched-at", target_url)
    port = None
    port_match = re.search(r":(\d+)", matched_at)
    if port_match:
        port = int(port_match.group(1))
    elif "https://" in matched_at:
        port = 443
    elif "http://" in matched_at:
        port = 80
    elif open_ports:
        port = open_ports[0].get("port")

    curl_command = record.get("curl-command", "")
    extracted_results = record.get("extracted-results", [])
    matcher_name = record.get("matcher-name", "")

    evidence_parts = [
        f"Matched At: {matched_at}",
        f"Template ID: {template_id}",
    ]
    if matcher_name:
        evidence_parts.append(f"Matcher: {matcher_name}")
    if curl_command:
        evidence_parts.append(f"Reproduction Command:\n{curl_command}")
    if extracted_results:
        evidence_parts.append(f"Extracted Results: {extracted_results}")

    return {
        "cve_id": cve_id,
        "title": name[:255],
        "description": description or f"Actively verified finding by Nuclei template {template_id}",
        "cvss_score": cvss_score,
        "severity": severity_enum,
        "port": port,
        "verification": VerificationType.nuclei_verified.value,
        "evidence": "\n".join(evidence_parts),
        "source": f"nuclei:{template_id}",
        "remediation": info.get("remediation", "Apply vendor patches or configuration hardening."),
    }


def _run_stage4_nuclei_target(
    url: str,
    open_ports: List[Dict[str, Any]],
    host_header: Optional[str] = None,
    is_origin: bool = False,
    origin_ip: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Execute expanded Nuclei scan on a single target URL (with optional vhost routing)."""
    nuclei_bin = shutil.which("nuclei") or "/usr/local/bin/nuclei"
    if not os.path.exists(nuclei_bin):
        return []

    templates_dir = os.environ.get("NUCLEI_TEMPLATES_DIR", "/nuclei-templates")
    findings: List[Dict[str, Any]] = []

    # Run CVE, vulnerability, exposure, misconfig checks
    rate_limit = "15" if not is_origin else "25"
    cmd = [
        nuclei_bin,
        "-target", url,
        "-t", templates_dir,
        "-severity", "critical,high,medium",
        "-tags", "cve,exposure,misconfig,vulnerability,unauth",
        "-silent",
        "-jsonl",
        "-timeout", "12",
        "-rl", rate_limit,
        "-concurrency", "15",
        "-max-host-error", "10",
    ]

    # If origin scan with virtual host routing, attach Host header and bypass TLS validation
    if host_header:
        cmd.extend(["-header", f"Host: {host_header}", "-tls-verify", "false"])

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout_data, _ = proc.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_data, _ = proc.communicate()

        for line in stdout_data.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    record = json.loads(line)
                    parsed = _parse_nuclei_record(record, url, open_ports)
                    if parsed:
                        if is_origin:
                            parsed["is_origin_direct"] = True
                            parsed["origin_ip"] = origin_ip or url
                            prefix = (
                                f"[ORIGIN CONFIG AUDIT] via virtual host routing to "
                                f"{origin_ip or url} (Host: {host_header})\n"
                            )
                            parsed["evidence"] = prefix + parsed.get("evidence", "")
                        findings.append(parsed)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.error(f"[STAGE 4] Nuclei error on {url}: {e}")

    return findings


def _parse_testssl_records(
    records: List[Dict[str, Any]],
    target: str,
) -> List[Dict[str, Any]]:
    """Parse testssl.sh JSON array into verified vulnerabilities."""
    findings = []
    seen_keys = set()

    for item in records:
        test_id = item.get("id", "")
        sev = str(item.get("severity", "")).upper()
        finding_text = item.get("finding", "")
        cve_field = item.get("cve", "")
        port = int(item.get("port", 443)) if str(item.get("port", "")).isdigit() else 443

        finding_lower = finding_text.lower()

        # Ignore OK/INFO severity unless explicitly actionable
        if sev in ("OK", "INFO"):
            continue

        # 1. Deprecated TLS 1.0 or TLS 1.1
        if test_id in ("TLS1", "TLS1_1") and ("offered" in finding_lower or sev in ("LOW", "MEDIUM", "WARN")):
            if "not offered" in finding_lower:
                continue
            proto_name = "TLS 1.0" if test_id == "TLS1" else "TLS 1.1"
            cve_id = f"SSL-{test_id}-DEPRECATED"
            if cve_id not in seen_keys:
                seen_keys.add(cve_id)
                findings.append({
                    "cve_id": cve_id,
                    "title": f"Deprecated {proto_name} Protocol Enabled",
                    "description": f"Target supports {proto_name}, which is deprecated by IETF RFC 8996 and susceptible to downgrade attacks.",
                    "cvss_score": 5.3,
                    "severity": VulnerabilitySeverity.medium,
                    "port": port,
                    "verification": VerificationType.ssl_verified.value,
                    "evidence": f"Target: {target}\nProtocol: {proto_name}\ntestssl.sh Finding: {finding_text}\nSeverity: {sev}",
                    "remediation": f"Disable {proto_name} in server SSL/TLS cipher and protocol configurations; require TLS 1.2+.",
                })

        # 2. Missing HSTS Header
        elif test_id == "HSTS" and "not offered" in finding_lower:
            cve_id = "SSL-MISSING-HSTS"
            if cve_id not in seen_keys:
                seen_keys.add(cve_id)
                findings.append({
                    "cve_id": cve_id,
                    "title": "Strict-Transport-Security (HSTS) Header Missing",
                    "description": "The remote web server does not provide an HTTP Strict Transport Security (HSTS) header, allowing potential SSL stripping.",
                    "cvss_score": 3.7,
                    "severity": VulnerabilitySeverity.low,
                    "port": port,
                    "verification": VerificationType.ssl_verified.value,
                    "evidence": f"Target: {target}\nHeader: Strict-Transport-Security\ntestssl.sh Finding: {finding_text}",
                    "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
                })

        # 3. Known SSL Vulnerabilities
        elif test_id in ("heartbleed", "ROBOT", "poodle_ssl", "LOGJAM", "BEAST", "SWEET32", "FREAK", "DROWN"):
            if "not vulnerable" in finding_lower or "not affected" in finding_lower:
                continue
            if sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN") or "vulnerable" in finding_lower:
                first_cve = cve_field.split()[0].strip() if cve_field else ""
                vuln_cve = first_cve or {
                    "heartbleed": "CVE-2014-0160",
                    "ROBOT": "CVE-2017-13099",
                    "poodle_ssl": "CVE-2014-3566",
                    "LOGJAM": "CVE-2015-4000",
                    "BEAST": "CVE-2011-3389",
                    "SWEET32": "CVE-2016-2183",
                    "FREAK": "CVE-2015-0204",
                    "DROWN": "CVE-2016-0800",
                }.get(test_id, f"SSL-{test_id.upper()}")
                vuln_cve = vuln_cve[:49]

                if vuln_cve not in seen_keys:
                    seen_keys.add(vuln_cve)
                    sev_enum = VulnerabilitySeverity.high if test_id in ("heartbleed", "ROBOT", "LOGJAM", "DROWN") else VulnerabilitySeverity.medium
                    cvss = 7.5 if sev_enum == VulnerabilitySeverity.high else 5.3
                    findings.append({
                        "cve_id": vuln_cve,
                        "title": f"SSL/TLS Protocol Vulnerability: {test_id.upper()}",
                        "description": f"Target is vulnerable to {test_id.upper()} ({vuln_cve}). Finding: {finding_text}",
                        "cvss_score": cvss,
                        "severity": sev_enum,
                        "port": port,
                        "verification": VerificationType.ssl_verified.value,
                        "evidence": f"Target: {target}\nVulnerability: {test_id}\ntestssl.sh Finding: {finding_text}\nSeverity: {sev}",
                        "remediation": f"Upgrade OpenSSL libraries and update TLS server configuration for {test_id.upper()}.",
                    })

        # 4. Weak / Broken Cipher Suites
        elif test_id in ("null_ciphers", "rc4", "des_ciphers", "weak_ciphers") and ("offered" in finding_lower or sev in ("LOW", "MEDIUM", "HIGH", "WARN")):
            if "not offered" in finding_lower:
                continue
            cve_id = f"SSL-WEAK-CIPHER-{test_id.upper()}"
            if cve_id not in seen_keys:
                seen_keys.add(cve_id)
                findings.append({
                    "cve_id": cve_id,
                    "title": f"Insecure Cipher Suite Supported ({test_id.replace('_', ' ').title()})",
                    "description": f"Server negotiates legacy or weak cipher suites ({test_id}): {finding_text}",
                    "cvss_score": 5.9,
                    "severity": VulnerabilitySeverity.medium,
                    "port": port,
                    "verification": VerificationType.ssl_verified.value,
                    "evidence": f"Target: {target}\nCipher Category: {test_id}\ntestssl.sh Finding: {finding_text}",
                    "remediation": "Restrict TLS configuration to modern, authenticated AEAD cipher suites only.",
                })

        # 5. Certificate Lifecycle Anomaly
        elif test_id in ("cert_expiration_status", "cert_self_signed", "cert_common_name_mismatch"):
            if sev in ("LOW", "MEDIUM", "HIGH", "WARN"):
                cve_id = f"SSL-CERT-{test_id.upper().replace('_', '-')}"
                if cve_id not in seen_keys:
                    seen_keys.add(cve_id)
                    findings.append({
                        "cve_id": cve_id,
                        "title": f"SSL/TLS Certificate Finding: {test_id.replace('_', ' ').title()}",
                        "description": f"Certificate anomaly: {finding_text}",
                        "cvss_score": 4.5,
                        "severity": VulnerabilitySeverity.medium,
                        "port": port,
                        "verification": VerificationType.ssl_verified.value,
                        "evidence": f"Target: {target}\nCheck: {test_id}\ntestssl.sh Finding: {finding_text}",
                        "remediation": "Deploy a valid, currently active, trusted certificate matching the hostname.",
                    })

    return findings


def _run_stage5_testssl_target(
    target: str,
    is_origin: bool = False,
    origin_ip: Optional[str] = None,
    host_header: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Stage 5: Execute testssl.sh on a single target hostname/IP (with optional origin tagging)."""
    testssl_bin = shutil.which("testssl.sh") or "/usr/local/bin/testssl.sh"
    if not os.path.exists(testssl_bin):
        logger.warning(f"[STAGE 5] testssl.sh not found at '{testssl_bin}'. Skipping.")
        return []

    # Strip scheme if present
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
    out_file = f"/tmp/testssl_{int(time.time()*1000)}.json"

    cmd = [
        testssl_bin,
        "--fast",
        "-p", "-s", "-U", "-h", "-c",
        "--ip", "one",
        "--jsonfile", out_file,
        "--quiet",
        "--warnings", "off",
        "--color", "0",
        clean_target,
    ]

    logger.info(f"[STAGE 5] Invoking testssl.sh: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
            with open(out_file, "r") as f:
                content = f.read().strip()
                if content.startswith("["):
                    records = json.loads(content)
                    raw_findings = _parse_testssl_records(records, clean_target)
                    if is_origin:
                        for rf in raw_findings:
                            rf["is_origin_direct"] = True
                            rf["origin_ip"] = origin_ip or clean_target
                            prefix = (
                                f"[ORIGIN CONFIG AUDIT] via virtual host routing to "
                                f"{origin_ip or clean_target} (Host: {host_header})\n"
                            )
                            rf["evidence"] = prefix + rf.get("evidence", "")
                    return raw_findings
    except Exception as e:
        logger.error(f"[STAGE 5] testssl.sh error on {clean_target}: {e}")
    finally:
        if os.path.exists(out_file):
            try:
                os.remove(out_file)
            except Exception:
                pass

    return []


def _run_stage6_tech_analysis(
    live_hosts: List[Dict[str, Any]],
    open_ports: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Stage 6: Technology Version Vulnerability Analysis from httpx tech stack."""
    findings: List[Dict[str, Any]] = []
    seen_cves: Set[str] = set()

    for host in live_hosts:
        tech_list = host.get("tech") or []
        webserver = host.get("webserver") or ""
        url = host.get("url", "")
        port = 443 if "https://" in url else 80

        combined_tech = " ".join(tech_list + [webserver])

        for entry in TECH_VULN_CATALOG:
            pattern = entry["pattern"]
            cve_id = entry["cve_id"]
            if cve_id in seen_cves:
                continue

            match = re.search(pattern, combined_tech, re.IGNORECASE)
            if match:
                seen_cves.add(cve_id)
                findings.append({
                    "cve_id": cve_id,
                    "title": entry["title"],
                    "description": entry["description"],
                    "cvss_score": entry["cvss"],
                    "severity": entry["severity"],
                    "port": port,
                    "verification": VerificationType.version_match.value,
                    "evidence": f"Target: {url}\nMatched Software Component: {match.group(0)}\nDetected Tech: {tech_list}",
                    "source": f"tech:{entry['name'].lower()}",
                    "remediation": entry["remediation"],
                })

    return findings


async def run_deep_scan(
    target: str,
    target_type: str = "ip",
    target_hostname: Optional[str] = None,
    resolved_ip: Optional[str] = None,
    progress_callback: Optional[Callable[..., Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Execute complete 7-stage reconnaissance and deep active verification scan.

    Returns:
        (open_ports, all_verified_findings, recon_summary)
    """
    logger.info(f"=== INITIATING PHASE 8.3 DEEP RECON SCAN ON {target} (type: {target_type}) ===")
    stages_total = 7
    is_domain = (target_type == "domain") or ("." in target and not re.match(r"^\d+\.\d+\.\d+\.\d+$", target))
    root_domain = target_hostname or target

    async def report_progress(stage_num: int, current_stage: str, detail: str, hosts_processed: int = 0, hosts_total: int = 0):
        if progress_callback:
            try:
                await progress_callback(
                    current_stage=current_stage,
                    stage_number=stage_num,
                    stages_total=stages_total,
                    detail=detail,
                    hosts_processed=hosts_processed,
                    hosts_total=hosts_total,
                )
            except Exception as e:
                logger.warning(f"Progress callback exception: {e}")

    subdomains: List[str] = []
    live_hosts: List[Dict[str, Any]] = []
    all_open_ports: List[Dict[str, Any]] = []
    all_findings: List[Dict[str, Any]] = []

    # -------------------------------------------------------------
    # STAGE 1: Subdomain Discovery
    # -------------------------------------------------------------
    if is_domain:
        await report_progress(1, "subdomain_discovery", f"Searching for subdomains of {root_domain}...")
        subdomains, stage1_stats = await asyncio.to_thread(_run_stage1_subdomains, root_domain)
        await report_progress(
            1,
            "subdomain_discovery",
            f"Discovered {len(subdomains)} subdomains ({stage1_stats['summary']})"
        )
    else:
        await report_progress(1, "subdomain_discovery", "Target is IP address - skipping subdomain discovery")
        subdomains = [target]
        stage1_stats = {
            "subfinder_count": 0,
            "crtsh_count": 0,
            "dns_brute_count": 0,
            "total": 1,
            "summary": "N/A (target is IP)",
            "discovery_note": None,
        }

    # -------------------------------------------------------------
    # STAGE 2: Live Web Probing & Tech Stack Detection
    # -------------------------------------------------------------
    if is_domain:
        await report_progress(2, "live_web_probing", f"Probing {len(subdomains)} subdomains for live web services...")
        live_hosts = await asyncio.to_thread(_run_stage2_live_probing, subdomains, root_domain, resolved_ip)
        await report_progress(2, "live_web_probing", f"Discovered {len(live_hosts)} active web services")
    else:
        await report_progress(2, "live_web_probing", "Target is IP address - skipping multi-host web probing")
        live_hosts = [{
            "url": f"http://{target}",
            "title": target,
            "status_code": 200,
            "tech": [],
            "host": target,
            "ip": target,
            "all_ips": [target],
            "cdn": False,
        }]

    # -------------------------------------------------------------
    # STAGE 2.5: Virtual Host Resolution & Origin Infrastructure Mapping
    # -------------------------------------------------------------
    origin_map: List[Dict[str, Any]] = []
    confirmed_origin_ips: List[str] = []

    if is_domain:
        await report_progress(3, "origin_mapping", "Auditing proxy fronting and performing virtual host origin mapping...")
        origin_map, confirmed_origin_ips = await asyncio.to_thread(
            _resolve_and_verify_origin_infrastructure,
            live_hosts,
            subdomains,
            root_domain,
            resolved_ip,
        )
        if origin_map:
            conf_count = len([m for m in origin_map if m.get("confidence") == "confirmed"])
            await report_progress(
                3,
                "origin_mapping",
                f"Origin mapping: {len(origin_map)} origin route(s) mapped ({conf_count} confirmed bypassing edge proxy)",
            )

    # -------------------------------------------------------------
    # STAGE 3: Smart Port Scanning
    # -------------------------------------------------------------
    # Build list of distinct IPs to port scan (prioritizing confirmed origin IPs without CDN flag)
    ip_map: Dict[str, bool] = {}
    for o_ip in confirmed_origin_ips:
        ip_map[o_ip] = False

    if is_domain:
        for h in live_hosts:
            hip = h.get("ip")
            if hip and hip != "127.0.0.1" and hip not in ip_map:
                ip_map[hip] = h.get("cdn", False)
            for extra_ip in h.get("all_ips", []):
                if extra_ip and extra_ip not in ip_map and extra_ip != "127.0.0.1":
                    ip_map[extra_ip] = h.get("cdn", False)
        if resolved_ip and resolved_ip not in ip_map:
            ip_map[resolved_ip] = False
    else:
        ip_map[target] = False

    # Limit port scanning to top 6 unique IPs (origin servers prioritized!)
    target_ips = list(ip_map.keys())[:6] or [resolved_ip or target]
    await report_progress(3, "smart_port_scanning", f"Port scanning {len(target_ips)} target IP addresses...")

    for idx, ip_addr in enumerate(target_ips, start=1):
        is_cdn_host = ip_map.get(ip_addr, False)
        ports, nse_f = await asyncio.to_thread(_run_stage3_port_scan_single_ip, ip_addr, is_cdn_host)
        all_open_ports.extend(ports)
        all_findings.extend(nse_f)
        await report_progress(3, "smart_port_scanning", f"Port scanned {idx}/{len(target_ips)} IPs ({ip_addr})", hosts_processed=idx, hosts_total=len(target_ips))

    # If no ports discovered on domain IPs, fallback to default HTTP/HTTPS ports
    if not all_open_ports and is_domain:
        all_open_ports = [
            {"ip": resolved_ip or target, "port": 80, "protocol": "tcp", "service": "http", "version": ""},
            {"ip": resolved_ip or target, "port": 443, "protocol": "tcp", "service": "https", "version": ""},
        ]

    # -------------------------------------------------------------
    # STAGE 4: Expanded Nuclei Active Web Exploitation & Origin Config Audit
    # -------------------------------------------------------------
    # Intelligent Target Reduction:
    # 1. Skip dead weight: 404, 502, 503, 504 errors
    # 2. Deduplicate: if multiple subdomains resolve to the same IP and have identical tech stacks, scan once
    valid_candidates: List[Dict[str, Any]] = []
    seen_ip_tech: Set[Tuple[str, str]] = set()

    for h in live_hosts:
        sc = h.get("status_code", 200)
        if sc in (404, 502, 503, 504):
            continue

        ip_addr = h.get("ip") or ""
        tech_key = ",".join(sorted(h.get("tech", [])))
        dedup_key = (ip_addr, tech_key)
        if ip_addr and dedup_key in seen_ip_tech:
            logger.info(f"[STAGE 4] Skipping redundant target {h.get('url')} (shares IP {ip_addr} and tech with existing target)")
            continue

        if ip_addr:
            seen_ip_tech.add(dedup_key)
        valid_candidates.append(h)

    nuclei_targets: List[str] = [h["url"] for h in valid_candidates if h.get("url")]

    # Cap Nuclei edge targets to top 10 unique, active URLs
    nuclei_targets = nuclei_targets[:10]
    if not nuclei_targets:
        # Fallback to web ports discovered
        for p in all_open_ports:
            port_num = p["port"]
            scheme = "https" if port_num in (443, 8443) else "http"
            nuclei_targets.append(f"{scheme}://{p.get('ip', target)}:{port_num}")

    # Build origin audit tasks (Nuclei with virtual host routing headers)
    origin_nuclei_tasks: List[Tuple[str, str, str]] = []
    seen_origin_keys = set()
    for om in origin_map:
        if om.get("confidence") == "confirmed":
            orig_url = f"{om['scheme']}://{om['origin_ip']}:{om['origin_port']}"
            orig_host = om["domain"]
            orig_key = (orig_url, orig_host)
            if orig_key not in seen_origin_keys:
                seen_origin_keys.add(orig_key)
                origin_nuclei_tasks.append((orig_url, orig_host, om["origin_ip"]))

    total_nuclei_work = len(nuclei_targets) + len(origin_nuclei_tasks)
    await report_progress(
        4,
        "nuclei_web_scanning",
        f"Launching parallel Nuclei scanning on {len(nuclei_targets)} edge targets + {len(origin_nuclei_tasks)} origin audits...",
        hosts_processed=0,
        hosts_total=total_nuclei_work,
    )

    # Parallelize Nuclei scanning across up to 4 concurrent processes
    sem = asyncio.Semaphore(4)
    completed_nuclei = 0

    async def scan_single_target(
        n_url: str,
        host_header: Optional[str] = None,
        is_origin: bool = False,
        origin_ip: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        nonlocal completed_nuclei
        async with sem:
            logger.info(f"[STAGE 4] Starting parallel Nuclei worker on {n_url} (origin={is_origin}, host={host_header})")
            results = await asyncio.to_thread(
                _run_stage4_nuclei_target,
                n_url,
                all_open_ports,
                host_header,
                is_origin,
                origin_ip,
            )
            completed_nuclei += 1
            await report_progress(
                4,
                "nuclei_web_scanning",
                f"Nuclei: completed {completed_nuclei}/{total_nuclei_work} targets ({n_url})",
                hosts_processed=completed_nuclei,
                hosts_total=total_nuclei_work,
            )
            return results

    coros = [scan_single_target(u) for u in nuclei_targets]
    for orig_url, orig_host, orig_ip in origin_nuclei_tasks:
        coros.append(scan_single_target(orig_url, host_header=orig_host, is_origin=True, origin_ip=orig_ip))

    if coros:
        nuclei_batches = await asyncio.gather(*coros, return_exceptions=True)
        for res in nuclei_batches:
            if isinstance(res, list):
                all_findings.extend(res)
            elif isinstance(res, Exception):
                logger.error(f"[STAGE 4] Nuclei worker error: {res}")

    # -------------------------------------------------------------
    # STAGE 5: SSL/TLS Cryptographic Audit (testssl.sh) & Origin TLS Audit
    # -------------------------------------------------------------
    # Find HTTPS hosts for testssl - only 1 audit per unique IP (same server = same cert)
    ssl_candidates: List[str] = []
    seen_ssl_ips: Set[str] = set()

    for h in live_hosts:
        u = h.get("url", "")
        if u.startswith("https://"):
            ip_val = h.get("ip") or ""
            if ip_val and ip_val in seen_ssl_ips:
                continue
            if ip_val:
                seen_ssl_ips.add(ip_val)
            host_only = u.replace("https://", "").split("/")[0]
            if host_only not in ssl_candidates:
                ssl_candidates.append(host_only)

    if not ssl_candidates:
        # Check if 443 is in open ports
        for p in all_open_ports:
            if p["port"] in (443, 8443):
                cand = p.get("ip") or (root_domain if is_domain else target)
                if cand not in ssl_candidates:
                    ssl_candidates.append(cand)

    # Cap testssl audits to top 3 edge hosts
    ssl_targets = ssl_candidates[:3]

    # Origin TLS audits: if origin server speaks HTTPS
    origin_ssl_audits: List[Tuple[str, str, str]] = []
    for om in origin_map:
        if om.get("confidence") == "confirmed" and om.get("scheme") == "https":
            t_spec = f"{om['origin_ip']}:{om['origin_port']}"
            if not any(a[0] == t_spec for a in origin_ssl_audits):
                origin_ssl_audits.append((t_spec, om["origin_ip"], om["domain"]))

    total_ssl_targets = len(ssl_targets) + len(origin_ssl_audits)
    await report_progress(5, "ssl_tls_audit", f"Auditing SSL/TLS security on {total_ssl_targets} endpoints...", hosts_processed=0, hosts_total=total_ssl_targets)

    completed_ssl = 0
    for idx, ssl_target in enumerate(ssl_targets, start=1):
        completed_ssl += 1
        await report_progress(5, "ssl_tls_audit", f"testssl: auditing {completed_ssl}/{total_ssl_targets} ({ssl_target})...", hosts_processed=completed_ssl, hosts_total=total_ssl_targets)
        ssl_f = await asyncio.to_thread(_run_stage5_testssl_target, ssl_target)
        all_findings.extend(ssl_f)

    for t_spec, orig_ip, orig_host in origin_ssl_audits:
        completed_ssl += 1
        await report_progress(5, "ssl_tls_audit", f"testssl: origin audit {completed_ssl}/{total_ssl_targets} ({t_spec})...", hosts_processed=completed_ssl, hosts_total=total_ssl_targets)
        ssl_f = await asyncio.to_thread(_run_stage5_testssl_target, t_spec, is_origin=True, origin_ip=orig_ip, host_header=orig_host)
        all_findings.extend(ssl_f)

    # -------------------------------------------------------------
    # STAGE 6: Technology Version Vulnerability Analysis
    # -------------------------------------------------------------
    await report_progress(6, "technology_analysis", "Analyzing software stack versions against known CVE advisories...")
    tech_f = _run_stage6_tech_analysis(live_hosts, all_open_ports)
    all_findings.extend(tech_f)
    await report_progress(6, "technology_analysis", f"Identified {len(tech_f)} software component findings")

    # -------------------------------------------------------------
    # STAGE 7: Aggregation & Recon Summary
    # -------------------------------------------------------------
    # Deduplicate findings by (cve_id, port)
    deduped_findings: List[Dict[str, Any]] = []
    seen_vulns: Set[Tuple[str, Optional[int]]] = set()
    for f in all_findings:
        key = (f["cve_id"], f.get("port"))
        if key not in seen_vulns:
            seen_vulns.add(key)
            deduped_findings.append(f)

    # Distinct technologies across all live hosts
    all_tech: Set[str] = set()
    for h in live_hosts:
        for t in h.get("tech", []):
            all_tech.add(t)

    cdn_name = None
    waf_name = None
    for h in live_hosts:
        if not cdn_name and h.get("cdn"):
            cdn_name = h.get("cdn")
        if not waf_name and h.get("waf"):
            waf_name = h.get("waf")

    recon_summary: Dict[str, Any] = {
        "is_domain": is_domain,
        "subdomains_count": len(subdomains),
        "subdomains_found": len(subdomains),
        "subdomains": subdomains[:50],
        "subfinder_count": stage1_stats.get("subfinder_count", 0),
        "crtsh_count": stage1_stats.get("crtsh_count", 0),
        "dns_brute_count": stage1_stats.get("dns_brute_count", 0),
        "discovery_methods_summary": stage1_stats.get("summary", ""),
        "discovery_note": stage1_stats.get("discovery_note"),
        "live_hosts": live_hosts[:25],
        "live_hosts_count": len(live_hosts),
        "live_hosts_found": len(live_hosts),
        "cdn_detected": any(h.get("cdn") for h in live_hosts),
        "cdn_name": cdn_name,
        "waf_detected": bool(waf_name),
        "waf_name": waf_name,
        "origin_infrastructure_map": origin_map,
        "origin_count": len(confirmed_origin_ips),
        "waf_bypass_possible": len(confirmed_origin_ips) > 0,
        "backend_ips": target_ips,
        "ssl_audited_count": total_ssl_targets,
        "technologies_summary": sorted(list(all_tech)),
        "ports_discovered_count": len(all_open_ports),
    }

    await report_progress(
        7,
        "completed",
        f"Recon scan completed: {len(deduped_findings)} vulnerabilities identified across {len(live_hosts)} services ({len(confirmed_origin_ips)} confirmed origins mapped)",
        hosts_processed=len(live_hosts),
        hosts_total=len(live_hosts),
    )

    logger.info(
        f"=== COMPLETED DEEP RECON SCAN ON {target}: {len(all_open_ports)} ports, "
        f"{len(deduped_findings)} findings, {len(subdomains)} subdomains, {len(live_hosts)} live hosts, "
        f"{len(origin_map)} origin routes ({len(confirmed_origin_ips)} confirmed) ==="
    )

    return all_open_ports, deduped_findings, recon_summary
