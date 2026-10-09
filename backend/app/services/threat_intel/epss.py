"""FIRST Exploit Prediction Scoring System (EPSS) Integration.

Retrieves EPSS probability scores and percentiles via the public FIRST.org API.
Score thresholds:
  >= 0.5: very likely exploited
  >= 0.1: elevated
  < 0.1:  low
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("aegis.threat_intel.epss")

FIRST_EPSS_API_URL = "https://api.first.org/data/v1/epss"


def interpret_epss_score(score: Optional[float]) -> str:
    """Classify EPSS probability score according to FIRST guidance."""
    if score is None:
        return "unknown"
    if score >= 0.5:
        return "very likely exploited"
    elif score >= 0.1:
        return "elevated"
    return "low"


class EPSSService:
    """Client for FIRST.org EPSS API with batching and retry logic."""

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    async def get_epss(self, cve_id: str) -> Dict[str, Any]:
        """Fetch EPSS metrics for a single CVE ID."""
        clean_cve = (cve_id or "").strip().upper()
        if not clean_cve or not clean_cve.startswith("CVE-"):
            return {
                "cve": clean_cve,
                "epss_score": None,
                "epss_percentile": None,
                "date": None,
                "interpretation": "unknown",
            }

        batch_result = await self.get_epss_batch([clean_cve])
        if clean_cve in batch_result:
            return batch_result[clean_cve]

        return {
            "cve": clean_cve,
            "epss_score": None,
            "epss_percentile": None,
            "date": None,
            "interpretation": "unknown",
        }

    async def get_epss_batch(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """Fetch EPSS metrics for multiple CVE IDs in chunks of up to 100."""
        normalized: List[str] = []
        for c in cve_ids:
            clean = (c or "").strip().upper()
            if clean and clean.startswith("CVE-") and clean not in normalized:
                normalized.append(clean)

        if not normalized:
            return {}

        results: Dict[str, Dict[str, Any]] = {}
        chunk_size = 100

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for i in range(0, len(normalized), chunk_size):
                chunk = normalized[i : i + chunk_size]
                cve_param = ",".join(chunk)

                # Retry up to 2 attempts
                for attempt in range(2):
                    try:
                        logger.debug(f"Querying EPSS batch chunk {i // chunk_size + 1} ({len(chunk)} CVEs)...")
                        response = await client.get(
                            FIRST_EPSS_API_URL,
                            params={"cve": cve_param},
                        )
                        if response.status_code == 200:
                            payload = response.json()
                            data_items = payload.get("data", [])
                            for item in data_items:
                                cve = (item.get("cve") or "").strip().upper()
                                try:
                                    score = float(item.get("epss", 0.0))
                                except (ValueError, TypeError):
                                    score = None

                                try:
                                    percentile = float(item.get("percentile", 0.0))
                                except (ValueError, TypeError):
                                    percentile = None

                                results[cve] = {
                                    "cve": cve,
                                    "epss_score": round(score, 5) if score is not None else None,
                                    "epss_percentile": round(percentile, 5) if percentile is not None else None,
                                    "date": item.get("date"),
                                    "interpretation": interpret_epss_score(score),
                                }
                            break
                        else:
                            logger.warning(f"EPSS API returned status {response.status_code} (attempt {attempt + 1}/2)")
                            if attempt == 0:
                                await asyncio.sleep(0.5)
                    except Exception as exc:
                        logger.warning(f"EPSS API request error (attempt {attempt + 1}/2): {exc}")
                        if attempt == 0:
                            await asyncio.sleep(0.5)

                # Rate limiting spacing between chunk calls
                await asyncio.sleep(0.05)

        # Populate missing results with empty status
        for cve in normalized:
            if cve not in results:
                results[cve] = {
                    "cve": cve,
                    "epss_score": None,
                    "epss_percentile": None,
                    "date": None,
                    "interpretation": "unknown",
                }

        return results


epss_service = EPSSService()


async def get_epss(cve_id: str) -> Dict[str, Any]:
    return await epss_service.get_epss(cve_id)


async def get_epss_batch(cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    return await epss_service.get_epss_batch(cve_ids)
