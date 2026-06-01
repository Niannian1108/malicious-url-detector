import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import reputation_checker  # noqa: E402


class ReputationCheckerTests(unittest.TestCase):
    def test_reputation_check_is_disabled_without_api_key(self):
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": ""}, clear=False):
            result = reputation_checker.check_reputation("https://www.facebook.com/messages/")

        self.assertFalse(result["enabled"])
        self.assertEqual(result["source"], "disabled")
        self.assertEqual(result["verdict"], "unavailable")

    def test_virustotal_url_id_is_urlsafe_base64_without_padding(self):
        url_id = reputation_checker._url_id("https://www.facebook.com/messages/")

        self.assertNotIn("=", url_id)
        self.assertNotIn("+", url_id)
        self.assertNotIn("/", url_id)

    def test_verdict_from_stats(self):
        self.assertEqual(
            reputation_checker._verdict_from_stats({"malicious": 2, "suspicious": 0}),
            "malicious",
        )
        self.assertEqual(
            reputation_checker._verdict_from_stats({"malicious": 0, "suspicious": 2}),
            "suspicious",
        )
        self.assertEqual(
            reputation_checker._verdict_from_stats({"malicious": 0, "suspicious": 0, "harmless": 5}),
            "clean",
        )


if __name__ == "__main__":
    unittest.main()
