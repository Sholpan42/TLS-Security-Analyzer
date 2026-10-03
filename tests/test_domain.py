import unittest

from tests.helpers import load_core


class DomainTests(unittest.TestCase):
    def setUp(self):
        self.core = load_core()

    def test_normalize_domain_removes_scheme_path_and_port(self):
        self.assertEqual(self.core["normalize_domain_value"](" https://example.com:443/path "), "example.com")

    def test_normalize_domain_keeps_plain_name(self):
        self.assertEqual(self.core["normalize_domain_value"]("example.com"), "example.com")

    def test_normalize_domain_converts_unicode_idn_to_punycode(self):
        self.assertEqual(self.core["normalize_domain_value"]("пример.рф"), "xn--e1afmkfd.xn--p1ai")
