import unittest

from tests.helpers import load_core


class TlsTests(unittest.TestCase):
    def setUp(self):
        self.core = load_core()

    def test_tls_error_is_scan_status_not_security_finding(self):
        self.assertEqual(self.core["scan_status_from_error"]("TLS_HANDSHAKE_FAIL"), "TLS_ERROR")
        self.assertEqual(self.core["build_findings"]({}, {}, None, {}, {}, "TLS_ERROR"), [])

    def test_cipher_analysis_explains_weak_cipher(self):
        cipher = self.core["cipher_details"](("ECDHE-RSA-3DES-EDE-CBC-SHA", "TLSv1.2", 112), "TLSv1.2")
        self.assertEqual(cipher["strength"], "Weak")
        self.assertIn("3DES", cipher["reason"])

    def test_legacy_fallback_is_informational_when_modern_tls_exists(self):
        headers = {name: {"present": True, "value": "present"} for name in self.core["HTTP_SECURITY_HEADERS"]}
        tls = {"TLS 1.3": True, "TLS 1.2": True, "TLS 1.1": True, "TLS 1.0": True}
        cert_info = {"hostname_verified": True, "days_until_expiration": 100, "self_signed": False}
        findings = self.core["build_findings"](tls, headers, {"notAfter": "Jan 01 00:00:00 2035 GMT"}, cert_info,
                                                {"strength": "Strong", "name": "TLS_AES_256_GCM_SHA384"}, "SUCCESS")
        self.assertTrue(all(item["severity"] == "Info" for item in findings))

    def test_legacy_only_endpoint_is_critical(self):
        headers = {name: {"present": True, "value": "present"} for name in self.core["HTTP_SECURITY_HEADERS"]}
        tls = {"TLS 1.3": False, "TLS 1.2": False, "TLS 1.1": False, "TLS 1.0": True}
        cert_info = {"hostname_verified": True, "days_until_expiration": 100, "self_signed": False}
        findings = self.core["build_findings"](tls, headers, {"notAfter": "Jan 01 00:00:00 2035 GMT"}, cert_info,
                                                {"strength": "Strong", "name": "TLS_AES_256_GCM_SHA384"}, "SUCCESS")
        self.assertEqual(self.core["calculate_risk_score"](findings)[:2], (80, "Critical"))
