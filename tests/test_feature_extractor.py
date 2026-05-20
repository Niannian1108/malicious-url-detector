import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from feature_extractor import extract_features  # noqa: E402


class FeatureExtractorTests(unittest.TestCase):
    def test_trusted_paypal_signin_has_no_brand_mismatch(self):
        features = extract_features("https://www.paypal.com/us/signin")
        self.assertEqual(features["is_known_trusted_domain"], 1)
        self.assertEqual(features["has_brand_keyword"], 1)
        self.assertEqual(features["has_brand_mismatch"], 0)
        self.assertEqual(features["has_suspicious_keyword"], 1)

    def test_phishing_brand_mismatch_sets_risky_flags(self):
        features = extract_features(
            "http://login-secure.paypal.verify-account.xyz/cmd=_login-submit"
        )
        self.assertEqual(features["is_known_trusted_domain"], 0)
        self.assertEqual(features["has_brand_keyword"], 1)
        self.assertEqual(features["has_brand_mismatch"], 1)
        self.assertEqual(features["has_suspicious_tld"], 1)
        self.assertGreaterEqual(features["num_hyphens"], 2)

    def test_ip_and_script_path_detection(self):
        features = extract_features("http://192.168.1.1/admin/login.php")
        self.assertEqual(features["has_ip_address"], 1)
        self.assertEqual(features["has_executable_path"], 1)
        self.assertGreaterEqual(features["path_depth"], 2)

    def test_punycode_and_query_parameter_count(self):
        features = extract_features("https://xn--paypl-3ve.com/login?user=a&token=b")
        self.assertEqual(features["has_punycode"], 1)
        self.assertEqual(features["num_query_params"], 2)


if __name__ == "__main__":
    unittest.main()
