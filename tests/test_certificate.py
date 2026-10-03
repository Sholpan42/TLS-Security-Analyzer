import unittest

from tests.helpers import load_core


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.core = load_core()

    def test_missing_certificate_is_not_verified(self):
        details = self.core["certificate_details"](None, None, False)
        self.assertFalse(details["received"])
        self.assertFalse(details["chain_verified"])
        self.assertFalse(details["hostname_verified"])

    def test_expired_certificate_is_detected(self):
        certificate = {"notAfter": "Jan 01 00:00:00 2020 GMT"}
        self.assertTrue(self.core["certificate_expired"](certificate))
