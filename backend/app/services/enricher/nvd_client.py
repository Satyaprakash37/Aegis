"""NVD API 2.0 Client and CVE Enrichment Service.

Queries the National Vulnerability Database for identified service versions
with rate limiting, retries, and CVSS severity extraction.
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional
import httpx

from app.core.config import settings

logger = logging.getLogger("aegis.enricher")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def score_to_severity(score: float) -> str:
    """Map CVSS base score to standard severity enum value."""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0.0:
        return "low"
    return "none"


class NVDRateLimiter:
    """Sliding-window client-side rate limiter for NVD API 2.0 compliance."""

    def __init__(self, max_requests: int = 5, window_seconds: float = 30.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.timestamps: List[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Throttle execution if limit within window is reached."""
        async with self._lock:
            now = time.monotonic()
            # Evict timestamps older than sliding window
            self.timestamps = [t for t in self.timestamps if now - t < self.window_seconds]

            if len(self.timestamps) >= self.max_requests:
                sleep_time = self.window_seconds - (now - self.timestamps[0]) + 0.1
                if sleep_time > 0:
                    logger.info(f"NVD rate limiter throttling request for {sleep_time:.2f}s...")
                    await asyncio.sleep(sleep_time)
                # Re-clean window after awaiting
                now = time.monotonic()
                self.timestamps = [t for t in self.timestamps if now - t < self.window_seconds]

            self.timestamps.append(time.monotonic())


# Determine rate limit configuration: 50 req/30s with API key, 5 req/30s without key
max_reqs = 50 if bool(settings.NVD_API_KEY) else 5
rate_limiter = NVDRateLimiter(max_requests=max_reqs, window_seconds=30.0)


class NVDClient:
    """Asynchronous client interacting with the NVD REST API 2.0."""

    def __init__(self) -> None:
        self.headers: Dict[str, str] = {
            "User-Agent": "AEGIS-Vulnerability-Management-Platform/1.0",
            "Accept": "application/json",
        }
        if settings.NVD_API_KEY:
            self.headers["apiKey"] = settings.NVD_API_KEY

    def _parse_cve_item(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract CVE ID, English summary, and CVSS v3.1 metrics from an NVD record."""
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            return None

        # Extract English description
        descriptions = cve.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and descriptions:
            desc = descriptions[0].get("value", "")

        # Extract CVSS metrics (preference: v3.1 -> v3.0 -> v2.0)
        metrics = cve.get("metrics", {})
        cvss_score = 0.0
        severity = "none"

        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = float(data.get("baseScore", 0.0))
            raw_sev = str(data.get("baseSeverity", "")).lower()
            severity = raw_sev if raw_sev in ["critical", "high", "medium", "low", "none"] else score_to_severity(cvss_score)
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = float(data.get("baseScore", 0.0))
            raw_sev = str(data.get("baseSeverity", "")).lower()
            severity = raw_sev if raw_sev in ["critical", "high", "medium", "low", "none"] else score_to_severity(cvss_score)
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            v2_item = metrics["cvssMetricV2"][0]
            data = v2_item.get("cvssData", {})
            cvss_score = float(data.get("baseScore", 0.0))
            raw_sev = str(v2_item.get("baseSeverity", "")).lower()
            severity = raw_sev if raw_sev in ["critical", "high", "medium", "low", "none"] else score_to_severity(cvss_score)
        else:
            severity = score_to_severity(cvss_score)

        return {
            "cve_id": cve_id,
            "description": desc,
            "cvss_score": round(cvss_score, 1),
            "severity": severity,
        }

    async def _query_nvd(self, client: httpx.AsyncClient, keyword: str) -> List[Dict[str, Any]]:
        """Execute a single throttled request to NVD API with retry."""
        params: Dict[str, Any] = {
            "resultsPerPage": 5,
            "keywordSearch": keyword,
        }
        await rate_limiter.acquire()
        for attempt in range(2):
            try:
                logger.info(f"Querying NVD API for '{keyword}' (attempt {attempt + 1}/2)...")
                response = await client.get(
                    NVD_API_URL,
                    params=params,
                    headers=self.headers,
                )
                if response.status_code == 200:
                    payload = response.json()
                    vulnerabilities = payload.get("vulnerabilities", [])
                    results: List[Dict[str, Any]] = []
                    for v in vulnerabilities:
                        parsed = self._parse_cve_item(v)
                        if parsed:
                            results.append(parsed)
                    logger.info(f"NVD returned {len(results)} vulnerability candidate(s) for '{keyword}'")
                    return results
                elif response.status_code == 404:
                    return []
                elif response.status_code in [403, 429, 503]:
                    logger.warning(f"NVD API returned HTTP {response.status_code}. Throttling before retry.")
                    if attempt == 0:
                        await asyncio.sleep(2.0)
                        continue
                    return []
                else:
                    return []
            except httpx.RequestError as exc:
                logger.warning(f"NVD request exception on '{keyword}' (attempt {attempt + 1}/2): {exc}")
                if attempt == 0:
                    await asyncio.sleep(1.5)
                    continue
                return []
            except Exception as exc:
                logger.error(f"Unexpected error querying NVD for '{keyword}': {exc}")
                return []
        return []

    async def enrich_service(
        self,
        product: Optional[str] = None,
        service: Optional[str] = None,
        version: Optional[str] = None,
        cpe: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query NVD 2.0 for known CVE vulnerabilities associated with a service/version."""
        import re

        # Normalize product (e.g. "PostgreSQL DB" -> "PostgreSQL")
        clean_prod = re.sub(r'\s+(DB|database)$', '', (product or '').strip(), flags=re.IGNORECASE).strip()
        # Normalize version (e.g. "9.6.0 or later" -> "9.6.0")
        ver_cleaned = re.sub(r'\s*(or\s+later|or\s+newer|\+)\s*', '', (version or '').strip(), flags=re.IGNORECASE).strip()
        v_match = re.search(r'\d+(\.\d+)*', ver_cleaned)
        clean_ver = v_match.group(0) if v_match else ver_cleaned

        clean_serv = (service or '').strip()

        # Construct primary and fallback search keywords
        keywords_to_try: List[str] = []
        if clean_prod and clean_ver:
            keywords_to_try.append(f"{clean_prod} {clean_ver}")
            keywords_to_try.append(clean_prod)
        elif clean_serv and clean_ver:
            keywords_to_try.append(f"{clean_serv} {clean_ver}")
            keywords_to_try.append(clean_serv)
        elif clean_prod:
            keywords_to_try.append(clean_prod)
        elif clean_serv:
            keywords_to_try.append(clean_serv)

        if not keywords_to_try:
            return []

        async with httpx.AsyncClient(timeout=15.0) as client:
            for kw in keywords_to_try:
                findings = await self._query_nvd(client, kw)
                if findings:
                    return findings

        return []


nvd_client = NVDClient()
