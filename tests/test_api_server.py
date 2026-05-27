import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "backend" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import api_server  # noqa: E402


class ApiServerTests(unittest.TestCase):
    def setUp(self):
        self.log_patch = patch.object(api_server, "log_event", autospec=True)
        self.log_patch.start()

    def tearDown(self):
        self.log_patch.stop()

    def test_health_check_reports_feature_count(self):
        payload = api_server.health_check()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["model_features"], len(api_server.FEATURES))

    def test_empty_url_is_rejected(self):
        with self.assertRaises(HTTPException) as exc_ctx:
            api_server.predict(api_server.PredictRequest(url="   "))
        self.assertEqual(exc_ctx.exception.status_code, 422)

    def test_predict_response_schema_is_stable(self):
        payload = api_server.predict(api_server.PredictRequest(url="https://www.google.com/"))
        self.assertIn(payload.prediction, [0, 1])
        self.assertGreaterEqual(payload.confidence, 0.0)
        self.assertLessEqual(payload.confidence, 1.0)
        self.assertIn(payload.risk_level, ["low", "medium", "high"])
        self.assertIsInstance(payload.reasons, list)

    def test_official_paypal_signin_is_not_block_threshold_risk(self):
        payload = api_server.predict(api_server.PredictRequest(url="https://www.paypal.com/us/signin"))
        self.assertLess(payload.confidence, 0.90)
        self.assertNotEqual(payload.risk_level, "high")

    def test_brand_mismatch_phishing_url_scores_as_malicious(self):
        payload = api_server.predict(
            api_server.PredictRequest(
                url="http://login-secure.paypal.verify-account.xyz/cmd=_login-submit"
            )
        )
        self.assertEqual(payload.prediction, 1)
        self.assertGreaterEqual(payload.confidence, 0.80)
        self.assertIn(payload.risk_level, ["medium", "high"])

    def test_dom_signals_can_raise_severity(self):
        url = "http://login-secure.paypal.verify-account.xyz/cmd=_login-submit"
        base_payload = api_server.predict(api_server.PredictRequest(url=url))
        dom_payload = api_server.predict(
            api_server.PredictRequest(
                url=url,
                dom_signals=api_server.DomSignals(
                    password_field_count=1,
                    hidden_iframe_count=1,
                    suspicious_text_hit_count=4,
                    page_brand_mismatch=1,
                ),
            )
        )
        self.assertGreaterEqual(dom_payload.confidence, base_payload.confidence)
        self.assertEqual(dom_payload.risk_level, "high")


if __name__ == "__main__":
    unittest.main()
