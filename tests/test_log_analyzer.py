import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ANALYZER_PATH = PROJECT_ROOT / "src" / "log-analyzer.py"

module_specification = importlib.util.spec_from_file_location(
    "log_analyzer",
    ANALYZER_PATH
)
log_analyzer = importlib.util.module_from_spec(module_specification)
module_specification.loader.exec_module(log_analyzer)


class LogAnalyzerTests(unittest.TestCase):

    def test_parse_failed_login_entry(self):

        line = (
            "Jul 16 09:00:10 server sshd[1040]: "
            "Failed password for root from 185.220.101.15 port 42000 ssh2"
        )

        timestamp, hour, user, ip = log_analyzer.parse_log_entry(line)

        self.assertEqual(timestamp, "Jul 16 09:00:10")
        self.assertEqual(hour, "09")
        self.assertEqual(user, "root")
        self.assertEqual(ip, "185.220.101.15")

    def test_parse_invalid_user_entry(self):

        line = (
            "Jul 16 12:00:11 server sshd[1126]: "
            "Failed password for invalid user guest from 203.0.113.50 "
            "port 45000 ssh2"
        )

        timestamp, hour, user, ip = log_analyzer.parse_log_entry(line)

        self.assertEqual(timestamp, "Jul 16 12:00:11")
        self.assertEqual(hour, "12")
        self.assertEqual(user, "invalid user guest")
        self.assertEqual(ip, "203.0.113.50")

    def test_severity_levels(self):

        self.assertIsNone(log_analyzer.get_severity(9))
        self.assertEqual(log_analyzer.get_severity(10), "LOW")
        self.assertEqual(log_analyzer.get_severity(25), "MEDIUM")
        self.assertEqual(log_analyzer.get_severity(50), "HIGH")
        self.assertEqual(log_analyzer.get_severity(100), "CRITICAL")

    def test_default_log_file_path(self):

        with patch.object(sys, "argv", ["log-analyzer.py"]):
            log_file = log_analyzer.get_log_file_path()

        self.assertEqual(log_file, log_analyzer.LOG_FILE)

    def test_custom_log_file_path(self):

        with patch.object(
            sys,
            "argv",
            ["log-analyzer.py", "data/auth_simple.log"]
        ):
            log_file = log_analyzer.get_log_file_path()

        self.assertEqual(log_file, "data/auth_simple.log")

    def test_successful_login_after_failed_attempt(self):

        failed_login_pairs = {
            ("185.220.101.15", "root")
        }

        self.assertTrue(
            log_analyzer.is_successful_login_after_failed_attempt(
                "185.220.101.15",
                "root",
                failed_login_pairs
            )
        )
        self.assertFalse(
            log_analyzer.is_successful_login_after_failed_attempt(
                "185.220.101.15",
                "simon",
                failed_login_pairs
            )
        )
        self.assertFalse(
            log_analyzer.is_successful_login_after_failed_attempt(
                "198.51.100.44",
                "root",
                failed_login_pairs
            )
        )


if __name__ == "__main__":
    unittest.main()
