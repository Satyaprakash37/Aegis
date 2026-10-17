"""Isolated unit tests for NVD enrichment client and precision guards.

Verifies:
1. Proprietary banners (e.g. 'gws', 'cloudflare') return zero findings and make no NVD requests.
2. Identifiable services with unknown versions do not trigger speculative CVE keyword searches.
3. Unversioned identifiable service can produce an informational needs-verification observation without DB migrations.
4. Version-match findings require credible product identity and numeric version evidence.
5. Linux kernel and AMD GPU CVEs are strictly rejected for network services.
6. Upper bound version constraints in CVE descriptions filter out non-applicable CVEs.
7. Mock external network calls to guarantee full isolation from live NVD APIs.
"""

import unittest
from unittest.mock import AsyncMock, patch

from app.services.enricher.nvd_client import (
    NVDClient,
    create_unversioned_observation,
    is_cve_applicable,
    normalize_service_identity,
    nvd_client,
)


class TestNVDEnrichmentIsolated(unittest.IsolatedAsyncioTestCase):
    """Isolated unit test suite for NVD enrichment client."""

    async def test_proprietary_banners_return_no_findings_and_no_nvd_request(self):
        """Proprietary/generic banners (gws, cloudflare, akamai, etc.) must never trigger NVD requests."""
        client = NVDClient()
        with patch.object(client, "_query_nvd", new_callable=AsyncMock) as mock_query:
            # gws banner
            res_gws = await client.enrich_service(product="gws", service="http", version="")
            self.assertEqual(res_gws, [])

            # gws with bogus numeric version
            res_gws_v = await client.enrich_service(product="gws", service="https", version="1.0")
            self.assertEqual(res_gws_v, [])

            # cloudflare reverse proxy
            res_cf = await client.enrich_service(product="cloudflare", service="http", version="1.0")
            self.assertEqual(res_cf, [])

            # akamai
            res_ak = await client.enrich_service(product="akamai", service="https", version="2.0")
            self.assertEqual(res_ak, [])

            # Verify that _query_nvd was NEVER called
            mock_query.assert_not_called()

    async def test_unversioned_identifiable_service_handling(self):
        """Unversioned identifiable services return clean empty findings by default or observation when requested."""
        client = NVDClient()
        with patch.object(client, "_query_nvd", new_callable=AsyncMock) as mock_query:
            # Default behavior: clean empty list, no speculative NVD queries
            res_default = await client.enrich_service(
                product="Apache HTTP Server", service="http", version="", record_observation=False
            )
            self.assertEqual(res_default, [])
            mock_query.assert_not_called()

            # When observation requested: structured informational finding without speculative CVE
            res_obs = await client.enrich_service(
                product="Apache HTTP Server", service="http", version="", record_observation=True
            )
            self.assertEqual(len(res_obs), 1)
            obs = res_obs[0]
            self.assertEqual(obs["cve_id"], "INFO-APACHE-HTTP-UNVERSIONED")
            self.assertEqual(obs["severity"], "none")
            self.assertEqual(obs["cvss_score"], 0.0)
            self.assertTrue(obs["needs_verification"])
            self.assertIn("Apache HTTP", obs["title"])
            mock_query.assert_not_called()

    def test_create_unversioned_observation_helper(self):
        """create_unversioned_observation creates clean needs-verification observations."""
        obs = create_unversioned_observation(product="nginx", service="http")
        self.assertIsNotNone(obs)
        self.assertEqual(obs["cve_id"], "INFO-NGINX-UNVERSIONED")
        self.assertEqual(obs["severity"], "none")
        self.assertTrue(obs["needs_verification"])

        # Proprietary banners must NOT produce observations
        obs_gws = create_unversioned_observation(product="gws", service="http")
        self.assertIsNone(obs_gws)

        # Generic service without product must NOT produce observations
        obs_generic = create_unversioned_observation(product="", service="tcpwrapped")
        self.assertIsNone(obs_generic)

    def test_version_match_requires_credible_product_and_numeric_version(self):
        """is_cve_applicable must reject unversioned or generic inputs."""
        desc = "Buffer overflow in web server allows remote command execution."
        cve_id = "CVE-2023-12345"

        # Missing version
        self.assertFalse(is_cve_applicable(cve_id, desc, "Apache HTTP Server", ""))
        self.assertFalse(is_cve_applicable(cve_id, desc, "nginx", "unknown"))

        # Empty product
        self.assertFalse(is_cve_applicable(cve_id, desc, "", "2.4.49"))

        # Generic blacklisted service
        self.assertFalse(is_cve_applicable(cve_id, desc, "tcpwrapped", "1.0"))
        self.assertFalse(is_cve_applicable(cve_id, desc, "http", "1.1"))

        # Proprietary banner
        self.assertFalse(is_cve_applicable(cve_id, desc, "gws", "1.0"))

    def test_linux_kernel_and_hardware_cves_rejected_for_network_services(self):
        """Network services must not be assigned Linux kernel or GPU driver CVEs."""
        gpu_cve = "CVE-2026-80541"
        gpu_desc = (
            "In the Linux kernel, the following vulnerability has been resolved:\n\n"
            "drm/amdgpu: validate GEM_CREATE domain combinations\n\n"
            "AMDGPU_GEM_CREATE checked domain bits against AMDGPU_GEM_DOMAIN_MASK, "
            "making amdgpu_bo_placement_from_domain() hit BUG_ON()."
        )
        self.assertFalse(is_cve_applicable(gpu_cve, gpu_desc, "Apache HTTP Server", "2.4.50"))
        self.assertFalse(is_cve_applicable(gpu_cve, gpu_desc, "nginx", "1.20.1"))
        self.assertFalse(is_cve_applicable(gpu_cve, gpu_desc, "OpenSSH", "8.9p1"))
        self.assertFalse(is_cve_applicable(gpu_cve, gpu_desc, "gws", "1.0"))

        rdna_cve = "CVE-2026-46276"
        rdna_desc = (
            "In the Linux kernel, the following vulnerability has been resolved:\n\n"
            "drm/amdgpu: fix zero-size GDS range init on RDNA4\n\n"
            "RDNA4 (GFX 12) hardware removes the GDS, GWS, and OA on-chip memory resources."
        )
        self.assertFalse(is_cve_applicable(rdna_cve, rdna_desc, "Apache HTTP Server", "2.4.49"))
        self.assertFalse(is_cve_applicable(rdna_cve, rdna_desc, "nginx", "1.22.0"))

    def test_upper_bound_version_constraints(self):
        """CVEs with upper bounds lower than the detected major version must be rejected."""
        cve_old = "CVE-2016-1234"
        desc_old = "MySQL Server before 5.7.12 allows denial of service via malformed query."
        # Detected version is MySQL 8.0.30 -> upper bound 5.7 < 8 -> rejected
        self.assertFalse(is_cve_applicable(cve_old, desc_old, "MySQL", "8.0.30"))

        # Detected version is MariaDB 10.6.12 -> upper bound 5.7 < 10 -> rejected
        self.assertFalse(is_cve_applicable(cve_old, desc_old, "MariaDB", "10.6.12"))

    def test_temporal_guard_rejects_pre_dating_cves(self):
        """CVEs published before the software branch existed must be rejected."""
        ancient_cve = "CVE-2005-1234"
        ancient_desc = "Vulnerability in database engine."
        # MariaDB 10.6 branch created around 2021; 2005 CVE is impossible
        self.assertFalse(is_cve_applicable(ancient_cve, ancient_desc, "MariaDB", "10.6.5"))
        # MySQL 8.0 branch created around 2018; 2005 CVE is impossible
        self.assertFalse(is_cve_applicable(ancient_cve, ancient_desc, "MySQL", "8.0.28"))


if __name__ == "__main__":
    unittest.main()
