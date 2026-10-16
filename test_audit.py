import json
from pathlib import Path
import subprocess
import sys
import unittest

from audit import audit


def statuses(headers, scheme="https"):
    return {c["rule"]: c["status"] for c in audit(dict(scheme=scheme, headers=headers))["checks"]}


class AuditTests(unittest.TestCase):
    def test_missing_headers(self):
        self.assertEqual(statuses({}), dict(hsts="missing", nosniff="missing", csp="missing"))

    def test_case_insensitive_names_and_basic_values(self):
        self.assertEqual(statuses({"STRICT-TRANSPORT-SECURITY": "max-age=3600; includeSubDomains",
                                   "X-Content-Type-Options": " NoSnIfF ",
                                   "Content-Security-Policy": "default-src 'self'"}),
                         dict(hsts="basic_check_passed", nosniff="basic_check_passed", csp="manual_review"))

    def test_http_does_not_receive_hsts_pass(self):
        self.assertEqual(statuses({"Strict-Transport-Security": "max-age=3600"}, "http")["hsts"], "not_applicable")

    def test_bad_hsts_and_disabled_policy(self):
        for value in ["max-age=0", "max-age=-1", "max-age=no", "includeSubDomains",
                      "max-age=1; max-age=2"]:
            with self.subTest(value=value):
                self.assertEqual(statuses({"Strict-Transport-Security": value})["hsts"], "review")
        self.assertEqual(statuses({"Strict-Transport-Security": 'max-age="3600"'})["hsts"], "basic_check_passed")

    def test_report_only_is_not_enforced(self):
        self.assertEqual(statuses({"Content-Security-Policy-Report-Only": "default-src 'none'"})["csp"], "review")

    def test_invalid_nosniff(self):
        self.assertEqual(statuses({"X-Content-Type-Options": "off"})["nosniff"], "review")

    def test_ambiguous_or_malformed_input_is_rejected(self):
        for data in [[], {}, {"scheme": "ftp", "headers": {}},
                     {"scheme": "https", "headers": {"X-A": "a", "x-a": "b"}},
                     {"scheme": "https", "headers": {"X A": "b"}},
                     {"scheme": "https", "headers": {"X-A": "one\r\ntwo"}},
                     {"scheme": "https", "headers": {"X-A": 1}}]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                audit(data)

    def test_unrelated_headers_are_not_echoed(self):
        result = audit({"scheme": "https", "headers": {"Set-Cookie": "session=do-not-echo"}})
        self.assertNotIn("do-not-echo", json.dumps(result))

    def test_cli_example_and_missing_file(self):
        root = Path(__file__).parent
        result = subprocess.run([sys.executable, str(root / "audit.py"),
                                 str(root / "examples/review.json")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["checks"]), 3)
        result = subprocess.run([sys.executable, str(root / "audit.py"),
                                 str(root / "examples/missing.json")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
