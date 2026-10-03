import unittest

from tests.helpers import load_core


class RiskTests(unittest.TestCase):
    def setUp(self):
        self.core = load_core()

    def test_two_high_findings_produce_high_risk(self):
        finding = self.core["finding"]
        findings = [finding("a", "High", "A", "e", "r"), finding("b", "High", "B", "e", "r")]
        self.assertEqual(self.core["calculate_risk_score"](findings)[:2], (50, "High"))

    def test_one_high_finding_cannot_be_reported_as_low(self):
        finding = self.core["finding"]
        findings = [finding("legacy_tls", "High", "TLS 1.0 is enabled", "probe", "disable it")]
        self.assertEqual(self.core["calculate_risk_score"](findings)[:2], (50, "High"))

    def test_critical_finding_has_critical_score_floor(self):
        finding = self.core["finding"]
        findings = [finding("expired", "Critical", "Expired certificate", "date", "renew it")]
        self.assertEqual(self.core["calculate_risk_score"](findings)[:2], (80, "Critical"))

    def test_failed_scan_has_no_risk_score(self):
        self.assertEqual(self.core["calculate_risk_score"]([], "TIMEOUT")[:2], (None, "N/A"))
