"""Target resolver utility for IP addresses and domain names.

Parses, cleans, validates, and resolves asset targets including raw IPv4
addresses, domain names, and full URLs with automatic DNS resolution.
"""

import ipaddress
import logging
import re
import socket
from typing import Any, Dict, Optional

logger = logging.getLogger("aegis.target_resolver")

# Standard RFC hostname regex (labels 1-63 alphanumeric/hyphen, total length <= 253)
HOSTNAME_REGEX = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)


def clean_target_string(raw: Optional[str]) -> str:
    """Strip protocol schemes, paths, query parameters, ports, and trailing slashes."""
    if not raw:
        return ""

    cleaned = raw.strip()

    has_scheme = bool(re.match(r"^[a-zA-Z]+://", cleaned))
    # Strip scheme (http://, https://, ftp://, etc.)
    cleaned = re.sub(r"^[a-zA-Z]+://", "", cleaned)

    # Strip userinfo if scheme was present (user:pass@host)
    if has_scheme and "@" in cleaned and "/" not in cleaned.split("@")[0]:
        cleaned = cleaned.split("@", 1)[1]

    # Strip path, query params, fragments
    cleaned = re.split(r"[/?#]", cleaned)[0].strip()

    # Strip port if present (e.g. host:8080)
    if ":" in cleaned:
        parts = cleaned.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            cleaned = parts[0]

    # Strip trailing dot if present (e.g. example.com.)
    cleaned = cleaned.rstrip(".").strip()

    return cleaned


def resolve_target(input_string: Optional[str]) -> Dict[str, Any]:
    """Parse, validate, and resolve target input.

    Returns:
        dict: {
            "type": "ip" | "domain" | "invalid",
            "ip": resolved_ip_or_none,
            "hostname": domain_or_none,
            "target": cleaned_target,
            "original": input_string,
            "error": error_message_or_none,
        }
    """
    raw = input_string or ""
    original = raw

    cleaned = clean_target_string(raw)
    if not cleaned:
        return {
            "type": "invalid",
            "ip": None,
            "hostname": None,
            "target": "",
            "original": original,
            "error": "Target cannot be empty",
        }

    # Normalize to lower case for consistency
    cleaned_lower = cleaned.lower()

    # Check if target appears to be an IPv4 address (digits and dots)
    dot_parts = cleaned_lower.split(".")
    looks_like_ipv4 = len(dot_parts) > 1 and all(p.isdigit() for p in dot_parts)

    if looks_like_ipv4:
        try:
            ip_obj = ipaddress.IPv4Address(cleaned_lower)
            return {
                "type": "ip",
                "ip": str(ip_obj),
                "hostname": None,
                "target": str(ip_obj),
                "original": original,
                "error": None,
            }
        except ValueError:
            return {
                "type": "invalid",
                "ip": None,
                "hostname": None,
                "target": cleaned_lower,
                "original": original,
                "error": f"'{cleaned}' is not a valid IPv4 address (e.g. 192.168.1.1)",
            }

    # Try IPv4 address parser directly just in case (e.g. integer representation)
    try:
        ip_obj = ipaddress.IPv4Address(cleaned_lower)
        return {
            "type": "ip",
            "ip": str(ip_obj),
            "hostname": None,
            "target": str(ip_obj),
            "original": original,
            "error": None,
        }
    except ValueError:
        pass

    # Validate hostname / domain format
    if len(cleaned_lower) > 253 or not HOSTNAME_REGEX.match(cleaned_lower):
        return {
            "type": "invalid",
            "ip": None,
            "hostname": None,
            "target": cleaned_lower,
            "original": original,
            "error": f"'{cleaned}' is not a valid domain or IP address format",
        }

    # Attempt DNS resolution
    try:
        addr_info = socket.getaddrinfo(
            cleaned_lower, None, socket.AF_INET, socket.SOCK_STREAM
        )
        if not addr_info:
            return {
                "type": "invalid",
                "ip": None,
                "hostname": cleaned_lower,
                "target": cleaned_lower,
                "original": original,
                "error": f"Could not resolve domain '{cleaned_lower}': No IPv4 address found",
            }
        resolved_ip = addr_info[0][4][0]
        return {
            "type": "domain",
            "ip": resolved_ip,
            "hostname": cleaned_lower,
            "target": cleaned_lower,
            "original": original,
            "error": None,
        }
    except socket.gaierror as e:
        err_msg = e.strerror if hasattr(e, "strerror") and e.strerror else str(e)
        logger.warning(f"Primary DNS resolution failed for '{cleaned_lower}': {err_msg}. Attempting fallback...")

        # Secondary attempt: query via system nslookup using 8.8.8.8 if local container resolver failed
        fallback_ip = None
        try:
            import subprocess
            proc = subprocess.run(
                ["nslookup", cleaned_lower, "8.8.8.8"],
                capture_output=True,
                text=True,
                timeout=4,
            )
            if proc.returncode == 0:
                matches = re.findall(r"Address:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", proc.stdout)
                candidates = [m for m in matches if m != "8.8.8.8"]
                if candidates:
                    fallback_ip = candidates[0]
        except Exception as fb_err:
            logger.debug(f"Fallback DNS attempt error: {fb_err}")

        if fallback_ip:
            logger.info(f"Fallback DNS resolution succeeded for '{cleaned_lower}' -> {fallback_ip}")
            return {
                "type": "domain",
                "ip": fallback_ip,
                "hostname": cleaned_lower,
                "target": cleaned_lower,
                "original": original,
                "error": None,
            }

        return {
            "type": "invalid",
            "ip": None,
            "hostname": cleaned_lower,
            "target": cleaned_lower,
            "original": original,
            "error": f"Could not resolve domain '{cleaned_lower}': {err_msg}",
        }
    except Exception as e:
        logger.error(f"Unexpected error resolving '{cleaned_lower}': {e}")
        return {
            "type": "invalid",
            "ip": None,
            "hostname": cleaned_lower,
            "target": cleaned_lower,
            "original": original,
            "error": f"DNS resolution failed for '{cleaned_lower}': {str(e)}",
        }
