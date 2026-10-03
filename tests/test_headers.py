import unittest

from tests.helpers import load_core


class HeaderTests(unittest.TestCase):
    def setUp(self):
        self.core = load_core()

    def test_missing_hsts_creates_medium_finding(self):
        headers = {name: {"present": False, "value": "Missing"} for name in self.core["HTTP_SECURITY_HEADERS"]}
        cert = {"notAfter": "Jan 01 00:00:00 2035 GMT"}
        cert_info = {"hostname_verified": True, "days_until_expiration": 100, "self_signed": False}
        cipher = {"strength": "Strong", "name": "TLS_AES_256_GCM_SHA384"}
        tls = {"TLS 1.3": True, "TLS 1.2": True, "TLS 1.1": False, "TLS 1.0": False}
        findings = self.core["build_findings"](tls, headers, cert, cert_info, cipher, "SUCCESS")
        hsts = next(item for item in findings if item["id"] == "missing_strict-transport-security")
        self.assertEqual(hsts["severity"], "Medium")

    def test_missing_optional_headers_are_not_overweighted(self):
        headers = {name: {"present": False, "value": "Missing"} for name in self.core["HTTP_SECURITY_HEADERS"]}
        cert = {"notAfter": "Jan 01 00:00:00 2035 GMT"}
        cert_info = {"hostname_verified": True, "days_until_expiration": 100, "self_signed": False}
        cipher = {"strength": "Strong", "name": "TLS_AES_256_GCM_SHA384"}
        tls = {"TLS 1.3": True, "TLS 1.2": True, "TLS 1.1": False, "TLS 1.0": False}

        findings = self.core["build_findings"](tls, headers, cert, cert_info, cipher, "SUCCESS")
        score, level, _ = self.core["calculate_risk_score"](findings)

        self.assertEqual((score, level), (20, "Low"))
