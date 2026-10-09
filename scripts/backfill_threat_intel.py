#!/usr/bin/env python3
"""Threat Intelligence Backfill Script for AEGIS.

Enriches all existing vulnerabilities in the database with:
- CISA KEV catalog status
- FIRST EPSS probability scores and percentiles (batched)
- Public exploit reference classification
- Multi-factor Threat Level (ACTIVE-THREAT, ELEVATED, MODERATE, LOW)
"""

import asyncio
import sys
from pathlib import Path
from typing import Dict, List, Set

# Ensure backend directory is in path
script_dir = Path(__file__).resolve().parent
sys.path.insert(0, "/app")
sys.path.insert(0, str(script_dir.parent))
sys.path.insert(0, str(script_dir.parent / "backend"))

from sqlalchemy import select
from app.db.session import AsyncSessionLocal
from app.models.vulnerability import Vulnerability
from app.services.threat_intel.kev import check_kev, kev_stats, download_kev_catalog
from app.services.threat_intel.epss import get_epss_batch
from app.services.threat_intel.exploit_refs import find_public_exploit_refs
from app.services.threat_intel import compute_threat_level


async def backfill():
    print("========================================================")
    print("AEGIS Phase R0: Threat Intelligence Database Backfill")
    print("========================================================")

    # 1. Verify / Sync KEV Catalog
    k_stats = kev_stats()
    if not k_stats.get("total_entries"):
        print("[*] Downloading CISA KEV catalog...")
        try:
            k_stats = await download_kev_catalog()
            print(f"[✓] KEV catalog synced: {k_stats.get('total_entries')} entries.")
        except Exception as e:
            print(f"[!] Warning: KEV sync failed: {e}. Proceeding with available cache.")
    else:
        print(f"[✓] Using cached KEV catalog with {k_stats.get('total_entries')} entries.")

    async with AsyncSessionLocal() as db:
        # 2. Query all existing vulnerabilities
        result = await db.execute(select(Vulnerability))
        vulns: List[Vulnerability] = result.scalars().all()
        total_vulns = len(vulns)
        print(f"[*] Found {total_vulns} total vulnerability record(s) in database.")

        if total_vulns == 0:
            print("[✓] No vulnerabilities found in database to backfill.")
            return

        # 3. Collect distinct CVE IDs
        distinct_cves: Set[str] = set()
        for v in vulns:
            cve = (v.cve_id or "").strip().upper()
            if cve and cve.startswith("CVE-"):
                distinct_cves.add(cve)

        print(f"[*] Distinct valid CVE IDs to enrich: {len(distinct_cves)}")

        # 4. Batch query EPSS API for all distinct CVEs
        print("[*] Fetching EPSS scores in batches from FIRST.org API...")
        epss_map = await get_epss_batch(list(distinct_cves))
        print(f"[✓] Received EPSS telemetry for {len(epss_map)} CVE(s).")

        # 5. Process each distinct CVE's KEV, exploit references, and threat level
        print("[*] Correlating KEV status and exploit reference documentation (concurrently)...", flush=True)
        cve_intel: Dict[str, dict] = {}
        sem = asyncio.Semaphore(10)

        async def process_cve(cve: str):
            async with sem:
                kev_data = check_kev(cve)
                in_kev = bool(kev_data.get("in_kev"))

                epss_data = epss_map.get(cve, {})
                epss_score = epss_data.get("epss_score")

                ref_data = await find_public_exploit_refs(cve)
                has_public_exploit = bool(ref_data.get("public_exploit_available"))

                threat_lvl = compute_threat_level(
                    in_kev=in_kev,
                    has_public_exploit=has_public_exploit,
                    epss_score=epss_score,
                )

                return cve, {
                    "in_kev": in_kev,
                    "epss_score": epss_score,
                    "exploit_refs": ref_data,
                    "threat_level": threat_lvl,
                    "has_public_exploit": has_public_exploit,
                }

        cve_results = await asyncio.gather(*(process_cve(c) for c in distinct_cves))
        for cve, intel in cve_results:
            cve_intel[cve] = intel

        # 6. Apply updates to vulnerability records
        updated_count = 0
        kev_hits = 0
        epss_hits = 0
        threat_breakdown = {"ACTIVE-THREAT": 0, "ELEVATED": 0, "MODERATE": 0, "LOW": 0}

        for v in vulns:
            cve = (v.cve_id or "").strip().upper()
            intel = cve_intel.get(cve)
            if intel:
                v.in_kev = intel["in_kev"]
                v.epss_score = intel["epss_score"]
                v.threat_level = intel["threat_level"]
                v.exploit_refs = intel["exploit_refs"]
                # Also synchronize public_exploit flag if exploit refs indicate available
                if intel["has_public_exploit"]:
                    v.public_exploit = True

                if intel["in_kev"]:
                    kev_hits += 1
                if intel["epss_score"] is not None:
                    epss_hits += 1
                threat_breakdown[intel["threat_level"]] = threat_breakdown.get(intel["threat_level"], 0) + 1
                updated_count += 1
            else:
                # Non-CVE findings (e.g. SSL weak cipher or custom checks)
                v.in_kev = False
                v.threat_level = "LOW"
                threat_breakdown["LOW"] += 1
                updated_count += 1

        await db.commit()

        print("\n========================================================")
        print("Threat Intelligence Backfill Summary")
        print("========================================================")
        print(f"✓ Total Vulnerabilities Updated:  {updated_count} / {total_vulns}")
        print(f"✓ Distinct CVEs Evaluated:        {len(distinct_cves)}")
        print(f"✓ CISA KEV Hits:                  {kev_hits}")
        print(f"✓ EPSS Scores Populated:          {epss_hits}")
        print("✓ Threat Level Breakdown:")
        for lvl, cnt in threat_breakdown.items():
            print(f"    - {lvl:<14}: {cnt}")
        print("========================================================")


if __name__ == "__main__":
    asyncio.run(backfill())
