"""Isolated unit tests for testssl.sh output parser in deep_scanner.py.

Verifies:
1. Genuine unmitigated vulnerability is reported and never suppressed.
2. Explicitly mitigated finding ('likely mitigated') is suppressed.
3. Explicit non-vulnerable finding ('not vulnerable') is suppressed.
4. Timeouts and connection resets with WARN severity do not generate false positives.
5. Genuine positive findings with WARN severity are retained.
6. Target hostname, evidence, and audit details are strictly preserved.
7. Malformed, empty, and partial records are handled gracefully without exceptions.
"""

import unittest
from app.services.scanner.deep_scanner import (
    _parse_testssl_records,
    _is_mitigated,
    _is_non_vulnerable,
    _is_inconclusive_error,
    _is_positive_finding,
)


class TestTestsslParserIsolated(unittest.TestCase):
    """Test suite verifying testssl parser state differentiation and precision."""

    def test_unmitigated_vulnerability_retained(self):
        """Unmitigated vulnerabilities must NEVER be treated as mitigated."""
        self.assertFalse(_is_mitigated("vulnerable (unmitigated)"))
        self.assertFalse(_is_mitigated("VULNERABLE - not mitigated"))
        self.assertFalse(_is_mitigated("vulnerable, no mitigation available"))

        records = [
            {
                "id": "BEAST",
                "finding": "VULNERABLE (unmitigated), server offers CBC ciphers",
                "cve": "CVE-2011-3389",
                "severity": "HIGH",
                "port": 443,
            }
        ]
        findings = _parse_testssl_records(records, target="secure.example.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cve_id"], "CVE-2011-3389")
        self.assertEqual(findings[0]["target_host"], "secure.example.com")
        self.assertIn("secure.example.com", findings[0]["title"])
        self.assertIn("VULNERABLE (unmitigated)", findings[0]["evidence"])

    def test_explicitly_mitigated_finding_suppressed(self):
        """Explicitly mitigated findings must be suppressed."""
        self.assertTrue(_is_mitigated("VULNERABLE -- but supports higher protocols (likely mitigated)"))
        self.assertTrue(_is_mitigated("client-side mitigation supported"))
        self.assertTrue(_is_mitigated("mitigated by higher protocols"))

        records = [
            {
                "id": "BEAST",
                "finding": "VULNERABLE -- but also supports higher protocols TLSv1.1 TLSv1.2 (likely mitigated)",
                "cve": "CVE-2011-3389",
                "severity": "LOW",
                "port": 443,
            }
        ]
        findings = _parse_testssl_records(records, target="mitigated.example.com")
        self.assertEqual(len(findings), 0)

    def test_explicit_non_vulnerable_suppressed(self):
        """Explicit non-vulnerable and not affected findings must be suppressed."""
        self.assertTrue(_is_non_vulnerable("not vulnerable"))
        self.assertTrue(_is_non_vulnerable("not affected"))
        self.assertTrue(_is_non_vulnerable("not offered"))
        self.assertTrue(_is_non_vulnerable("no fallback"))

        records = [
            {
                "id": "ROBOT",
                "finding": "not vulnerable",
                "cve": "CVE-2017-13099",
                "severity": "OK",
                "port": 443,
            },
            {
                "id": "heartbleed",
                "finding": "not vulnerable (OK)",
                "cve": "CVE-2014-0160",
                "severity": "LOW",
                "port": 443,
            },
            {
                "id": "TLS1",
                "finding": "not offered",
                "severity": "OK",
                "port": 443,
            },
        ]
        findings = _parse_testssl_records(records, target="clean.example.com")
        self.assertEqual(len(findings), 0)

    def test_timeout_and_reset_with_warn_severity_suppressed(self):
        """Network timeouts and connection resets with WARN severity must not create false positives."""
        self.assertTrue(_is_inconclusive_error("handshake timed out"))
        self.assertTrue(_is_inconclusive_error("connection reset by peer"))
        self.assertTrue(_is_inconclusive_error("unexpected EOF"))
        self.assertTrue(_is_inconclusive_error("could not connect"))

        records = [
            {
                "id": "poodle_ssl",
                "finding": "handshake timed out after 10s",
                "severity": "WARN",
                "port": 443,
            },
            {
                "id": "LOGJAM",
                "finding": "connection reset by peer during probe",
                "severity": "WARN",
                "port": 443,
            },
            {
                "id": "SWEET32",
                "finding": "unexpected EOF in TLS handshake",
                "severity": "WARN",
                "port": 443,
            },
            {
                "id": "TLS1",
                "finding": "timed out waiting for response",
                "severity": "WARN",
                "port": 443,
            },
        ]
        findings = _parse_testssl_records(records, target="flake.example.com")
        self.assertEqual(len(findings), 0)

    def test_genuine_positive_with_warn_severity_retained(self):
        """Genuine positive findings must NOT be suppressed merely because severity is WARN."""
        records = [
            {
                "id": "SWEET32",
                "finding": "uses 64 bit block ciphers",
                "cve": "CVE-2016-2183",
                "severity": "WARN",
                "port": 443,
            },
            {
                "id": "TLS1",
                "finding": "TLS 1.0 offered (deprecated)",
                "severity": "WARN",
                "port": 443,
            },
        ]
        findings = _parse_testssl_records(records, target="warn.example.com")
        self.assertEqual(len(findings), 2)
        cves = {f["cve_id"] for f in findings}
        self.assertIn("CVE-2016-2183", cves)
        self.assertIn("SSL-TLS1-DEPRECATED", cves)

    def test_hostname_and_evidence_preservation(self):
        """Exact tested hostname, evidence prefix, and title tags must be preserved."""
        records = [
            {
                "id": "SWEET32",
                "finding": "uses 64 bit block ciphers (3DES)",
                "cve": "CVE-2016-2183",
                "severity": "MEDIUM",
                "port": 443,
            }
        ]
        subdomain = "subdomain.corp.example.com"
        findings = _parse_testssl_records(records, target=subdomain)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["target_host"], subdomain)
        self.assertIn(f"({subdomain})", f["title"])
        self.assertIn(f"Audited Host: {subdomain}", f["evidence"])
        self.assertIn("testssl.sh Finding: uses 64 bit block ciphers (3DES)", f["evidence"])

    def test_warn_with_scan_interrupted_by_signal(self):
        """WARN severity with scan interrupted by signal must be treated as inconclusive (no finding)."""
        records = [
            {
                "id": "ROBOT",
                "finding": "scan interrupted by signal 15",
                "severity": "WARN",
                "port": 443,
            },
            {
                "id": "BEAST",
                "finding": "scan interrupted",
                "severity": "WARN",
                "port": 443,
            },
        ]
        findings = _parse_testssl_records(records, target="interrupted.example.com")
        self.assertEqual(len(findings), 0)

    def test_warn_with_server_returned_http_500(self):
        """WARN severity with HTTP errors must be treated as inconclusive (no finding)."""
        records = [
            {
                "id": "heartbleed",
                "finding": "server returned HTTP 500 Internal Server Error",
                "severity": "WARN",
                "port": 443,
            },
            {
                "id": "LOGJAM",
                "finding": "server returned HTTP 502 Bad Gateway during handshake",
                "severity": "WARN",
                "port": 443,
            },
        ]
        findings = _parse_testssl_records(records, target="httperror.example.com")
        self.assertEqual(len(findings), 0)

    def test_warn_with_timeout(self):
        """WARN severity with connection or handshake timeout must be treated as inconclusive."""
        records = [
            {
                "id": "BEAST",
                "finding": "connection timed out after 30s",
                "severity": "WARN",
                "port": 443,
            },
            {
                "id": "SWEET32",
                "finding": "handshake timed out waiting for server hello",
                "severity": "WARN",
                "port": 443,
            },
        ]
        findings = _parse_testssl_records(records, target="timeout.example.com")
        self.assertEqual(len(findings), 0)

    def test_warn_alone_without_positive_evidence_never_confirms(self):
        """A WARN severity alone without vulnerability-specific positive evidence must never confirm a vulnerability."""
        records = [
            {
                "id": "ROBOT",
                "finding": "ambiguous warning: server behavior non-standard",
                "severity": "WARN",
                "port": 443,
            },
            {
                "id": "FREAK",
                "finding": "unrecognized response from target server",
                "severity": "WARN",
                "port": 443,
            },
        ]
        findings = _parse_testssl_records(records, target="ambiguous.example.com")
        self.assertEqual(len(findings), 0)

    def test_positive_evidence_with_incidental_error_phrase_retained(self):
        """Do not suppress a genuine vulnerability merely because its output contains an error-related phrase elsewhere."""
        records = [
            {
                "id": "BEAST",
                "finding": "VULNERABLE (server returned HTTP 500 on secondary probe, but CBC block ciphers confirmed vulnerable)",
                "cve": "CVE-2011-3389",
                "severity": "WARN",
                "port": 443,
            },
            {
                "id": "SWEET32",
                "finding": "uses 64 bit block ciphers (handshake timed out on re-test)",
                "cve": "CVE-2016-2183",
                "severity": "WARN",
                "port": 443,
            },
        ]
        findings = _parse_testssl_records(records, target="incidental.example.com")
        self.assertEqual(len(findings), 2)
        cves = {f["cve_id"] for f in findings}
        self.assertIn("CVE-2011-3389", cves)
        self.assertIn("CVE-2016-2183", cves)

    def test_contradictory_positive_and_negative_phrases(self):
        """Contradictory positive and negative phrases ('VULNERABLE - not vulnerable') must not report vulnerabilities."""
        records = [
            {
                "id": "ROBOT",
                "finding": "VULNERABLE - not vulnerable to ROBOT attack",
                "cve": "CVE-2017-13099",
                "severity": "HIGH",
                "port": 443,
            },
            {
                "id": "heartbleed",
                "finding": "vulnerable test checked: not affected",
                "cve": "CVE-2014-0160",
                "severity": "HIGH",
                "port": 443,
            },
        ]
        findings = _parse_testssl_records(records, target="contradictory.example.com")
        self.assertEqual(len(findings), 0)

    def test_contradictory_positive_and_mitigated_phrases(self):
        """Contradictory positive and mitigated phrases must be suppressed under mitigation rules."""
        records = [
            {
                "id": "BEAST",
                "finding": "VULNERABLE -- but server enforces client-side mitigation (likely mitigated)",
                "cve": "CVE-2011-3389",
                "severity": "HIGH",
                "port": 443,
            }
        ]
        findings = _parse_testssl_records(records, target="mitigated.example.com")
    def test_malformed_and_edge_case_records(self):
        """Malformed, empty, and partial records must not crash the parser."""
        records = [
            {},
            {"id": ""},
            {"id": "unknown_test", "finding": ""},
            {"id": None, "finding": None, "severity": None},
            "not a dictionary",  # type: ignore
            None,  # type: ignore
            {"id": "HSTS", "finding": "not offered", "severity": "LOW", "port": "invalid_port"},
        ]
        findings = _parse_testssl_records(records, target="edge.example.com")  # type: ignore
        # Only valid HSTS finding should be extracted
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cve_id"], "SSL-MISSING-HSTS")
        self.assertEqual(findings[0]["port"], 443)


if __name__ == "__main__":
    unittest.main()

