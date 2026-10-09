"""AEGIS Threat Intelligence Service Layer.

Integrates:
1. CISA KEV (Known Exploited Vulnerabilities) Catalog
2. FIRST Exploit Prediction Scoring System (EPSS)
3. Public Exploit Documentation Reference Intelligence

Computes unified threat levels:
  - ACTIVE-THREAT (red): Listed in KEV, public exploit references available, and EPSS >= 0.5
  - ELEVATED (orange): Listed in KEV, OR (public exploit available AND EPSS >= 0.1)
  - MODERATE (yellow): EPSS >= 0.1 OR public exploit reference available
  - LOW (gray): Default baseline
"""

import logging
from typing import Any, Dict, List, Optional

from app.services.threat_intel.kev import check_kev, download_kev_catalog, kev_stats
from app.services.threat_intel.epss import get_epss, get_epss_batch, interpret_epss_score
from app.services.threat_intel.exploit_refs import find_public_exploit_refs

logger = logging.getLogger("aegis.threat_intel")


def compute_threat_level(
    in_kev: bool,
    has_public_exploit: bool,
    epss_score: Optional[float],
) -> str:
    """Compute the multi-factor threat classification level.

    Logic:
      1. ACTIVE-THREAT:
         - in_kev is True AND has_public_exploit is True AND (epss_score is not None and epss_score >= 0.5)
         (Also if in_kev is True and epss_score >= 0.8)
      2. ELEVATED:
         - in_kev is True OR (has_public_exploit is True AND (epss_score is not None and epss_score >= 0.1))
      3. MODERATE:
         - (epss_score is not None and epss_score >= 0.1) OR has_public_exploit is True
      4. LOW:
         - Standard vulnerability without verified active exploitation telemetry.
    """
    score = epss_score if epss_score is not None else 0.0

    if in_kev and has_public_exploit and score >= 0.5:
        return "ACTIVE-THREAT"
    if in_kev and score >= 0.8:
        return "ACTIVE-THREAT"
    if in_kev or (has_public_exploit and score >= 0.1):
        return "ELEVATED"
    if score >= 0.1 or has_public_exploit:
        return "MODERATE"
    return "LOW"


async def get_threat_intel(cve_id: str) -> Dict[str, Any]:
    """Retrieve comprehensive threat intelligence for a single CVE ID."""
    clean_cve = (cve_id or "").strip().upper()

    # 1. CISA KEV lookup (offline local cache)
    kev_result = check_kev(clean_cve)
    in_kev = bool(kev_result.get("in_kev"))

    # 2. EPSS score lookup (live FIRST.org API)
    epss_result = await get_epss(clean_cve)
    epss_score = epss_result.get("epss_score")

    # 3. Exploit references classification
    refs_result = await find_public_exploit_refs(clean_cve)
    has_public_exploit = bool(refs_result.get("public_exploit_available"))

    # 4. Computed multi-factor threat level
    threat_level = compute_threat_level(
        in_kev=in_kev,
        has_public_exploit=has_public_exploit,
        epss_score=epss_score,
    )

    return {
        "cve_id": clean_cve,
        "threat_level": threat_level,
        "in_kev": in_kev,
        "kev": kev_result,
        "epss": epss_result,
        "epss_score": epss_score,
        "exploit_refs": refs_result,
        "public_exploit_available": has_public_exploit,
    }


__all__ = [
    "check_kev",
    "download_kev_catalog",
    "kev_stats",
    "get_epss",
    "get_epss_batch",
    "interpret_epss_score",
    "find_public_exploit_refs",
    "compute_threat_level",
    "get_threat_intel",
]
