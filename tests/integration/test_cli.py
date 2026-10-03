import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


RUN_NETWORK_TESTS = os.environ.get("RUN_NETWORK_TESTS") == "1"
PROJECT_ROOT = Path(__file__).parents[2]
APP = PROJECT_ROOT / "TLS_Analyzer.py"


@unittest.skipUnless(RUN_NETWORK_TESTS, "Set RUN_NETWORK_TESTS=1 to run network integration tests")
class CliIntegrationTests(unittest.TestCase):
    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, str(APP), *arguments],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def test_successful_scan_returns_json_with_risk_score(self):
        completed = self.run_cli("example.com", "--json")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["scan_status"], "SUCCESS")
        self.assertIsNotNone(result["risk_score"])

    def test_invalid_domain_returns_failed_scan_without_risk_score(self):
        completed = self.run_cli("nonexistent-tls-analyzer-test.invalid", "--json")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["scan_status"], "DNS_ERROR")
        self.assertIsNone(result["risk_score"])
        self.assertEqual(result["risk_level"], "N/A")

    def test_fail_on_low_returns_security_gate_exit_code(self):
        completed = self.run_cli("example.com", "--quiet", "--fail-on", "low")
        self.assertEqual(completed.returncode, 1, completed.stderr)
