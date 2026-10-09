"""CISA Known Exploited Vulnerabilities (KEV) Catalog Service.

Provides offline-first lookup and synchronization for CISA's official catalog
of actively exploited vulnerabilities in the wild.
Recommended refresh frequency: Monthly.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
import httpx

logger = logging.getLogger("aegis.threat_intel.kev")

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
KEV_CACHE_FILE = DATA_DIR / "kev_catalog.json"


class CISAKEVService:
    """Service for caching and querying the CISA KEV catalog."""

    def __init__(self, cache_file: Path = KEV_CACHE_FILE):
        self.cache_file = cache_file
        self._memory_cache: Optional[Dict[str, Dict[str, Any]]] = None
        self._metadata: Dict[str, Any] = {}

    def _ensure_loaded(self) -> None:
        """Load catalog from local cache file into memory if not already loaded."""
        if self._memory_cache is not None:
            return

        if not self.cache_file.exists():
            logger.info("KEV catalog local cache file not found. Initializing empty cache.")
            self._memory_cache = {}
            self._metadata = {"total_entries": 0, "last_synced": None}
            return

        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            vulns = data.get("vulnerabilities", [])
            cache: Dict[str, Dict[str, Any]] = {}
            for item in vulns:
                cve_id = (item.get("cveID") or "").strip().upper()
                if cve_id:
                    cache[cve_id] = {
                        "cve_id": cve_id,
                        "vendor_project": item.get("vendorProject"),
                        "product": item.get("product"),
                        "vulnerability_name": item.get("vulnerabilityName"),
                        "date_added": item.get("dateAdded"),
                        "due_date": item.get("dueDate"),
                        "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
                        "notes": item.get("notes"),
                        "required_action": item.get("requiredAction"),
                        "cwes": item.get("cwes", []),
                    }

            self._memory_cache = cache
            self._metadata = {
                "total_entries": len(cache),
                "catalog_version": data.get("catalogVersion"),
                "date_released": data.get("dateReleased"),
                "last_synced": data.get("_last_synced"),
            }
            logger.info(f"Loaded {len(cache)} KEV records from local cache ({self.cache_file}).")
        except Exception as exc:
            logger.error(f"Failed to read KEV catalog cache: {exc}")
            self._memory_cache = {}
            self._metadata = {"total_entries": 0, "last_synced": None}

    async def download_kev_catalog(self, timeout: float = 30.0) -> Dict[str, Any]:
        """Download fresh KEV catalog from CISA.gov and update local cache file."""
        logger.info(f"Downloading CISA KEV catalog from {CISA_KEV_FEED_URL}...")
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(CISA_KEV_FEED_URL)
                response.raise_for_status()
                data = response.json()

            vulns = data.get("vulnerabilities", [])
            now_iso = datetime.now(timezone.utc).isoformat()
            data["_last_synced"] = now_iso

            # Write atomically to cache file
            temp_file = self.cache_file.with_suffix(".tmp")
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            temp_file.replace(self.cache_file)

            # Invalidate in-memory cache to reload fresh records
            self._memory_cache = None
            self._ensure_loaded()

            stats = self.kev_stats()
            logger.info(
                f"Successfully synced KEV catalog: {stats.get('total_entries')} entries "
                f"(Catalog version: {stats.get('catalog_version')})."
            )
            return stats
        except Exception as exc:
            logger.error(f"Error downloading CISA KEV catalog: {exc}")
            # Ensure local cache remains usable if it exists
            self._ensure_loaded()
            raise

    def check_kev(self, cve_id: str) -> Dict[str, Any]:
        """Check whether a CVE is listed in CISA's Known Exploited Vulnerabilities catalog.

        Returns:
            Dict containing:
                in_kev: bool
                entry: dict or None
        """
        self._ensure_loaded()
        clean_cve = (cve_id or "").strip().upper()
        if not clean_cve:
            return {"in_kev": False, "entry": None}

        entry = self._memory_cache.get(clean_cve)
        return {
            "in_kev": entry is not None,
            "entry": entry,
        }

    def kev_stats(self) -> Dict[str, Any]:
        """Get summary statistics of the cached KEV catalog."""
        self._ensure_loaded()
        ransomware_count = 0
        if self._memory_cache:
            for item in self._memory_cache.values():
                use = (item.get("known_ransomware_campaign_use") or "").strip().lower()
                if use == "known":
                    ransomware_count += 1

        return {
            "total_entries": len(self._memory_cache or {}),
            "last_synced": self._metadata.get("last_synced"),
            "catalog_version": self._metadata.get("catalog_version"),
            "date_released": self._metadata.get("date_released"),
            "ransomware_used_count": ransomware_count,
            "cache_file": str(self.cache_file),
        }


# Singleton instance
kev_service = CISAKEVService()


async def download_kev_catalog() -> Dict[str, Any]:
    return await kev_service.download_kev_catalog()


def check_kev(cve_id: str) -> Dict[str, Any]:
    return kev_service.check_kev(cve_id)


def kev_stats() -> Dict[str, Any]:
    return kev_service.kev_stats()
