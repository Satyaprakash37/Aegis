#!/usr/bin/env python3
"""Synchronize CISA Known Exploited Vulnerabilities (KEV) Catalog.

Downloads and refreshes the local JSON cache from CISA.gov with graceful fallback.
Recommended execution: Monthly cron or manual execution.
"""

import asyncio
import sys
from pathlib import Path

# Add backend directory to PYTHONPATH
script_dir = Path(__file__).resolve().parent
sys.path.insert(0, "/app")
sys.path.insert(0, str(script_dir.parent))
sys.path.insert(0, str(script_dir.parent / "backend"))

from app.services.threat_intel.kev import download_kev_catalog, check_kev, kev_stats


async def main():
    print("==================================================")
    print("AEGIS Threat Intelligence: CISA KEV Catalog Sync")
    print("==================================================")
    try:
        stats = await download_kev_catalog()
        print(f"✓ Catalog synchronization successful!")
        print(f"  - Total KEV Entries:       {stats.get('total_entries')}")
        print(f"  - Catalog Version:         {stats.get('catalog_version')}")
        print(f"  - Date Released:           {stats.get('date_released')}")
        print(f"  - Known Ransomware Vector: {stats.get('ransomware_used_count')}")
        print(f"  - Last Synced:             {stats.get('last_synced')}")
        print(f"  - Cache Location:          {stats.get('cache_file')}")

        # Verification lookup
        test_cve = "CVE-2021-44228"
        lookup = check_kev(test_cve)
        print("\n--- Test Verification ---")
        print(f"Lookup {test_cve} (Log4Shell): in_kev = {lookup.get('in_kev')}")
        if lookup.get("entry"):
            print(f"  Product: {lookup['entry'].get('product')}")
            print(f"  Name:    {lookup['entry'].get('vulnerability_name')}")
            print(f"  Added:   {lookup['entry'].get('date_added')}")

    except Exception as exc:
        print(f"✗ Failed to sync KEV catalog: {exc}", file=sys.stderr)
        existing = kev_stats()
        print(f"  Preserving existing cache ({existing.get('total_entries')} entries).")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
