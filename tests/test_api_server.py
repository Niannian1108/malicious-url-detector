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
        self.reputation_patch = patch.object(
            api_server,
            "check_reputation",
            autospec=True,
            return_value={
                "enabled": False,
                "source": "disabled",
                "verdict": "unavailable",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "undetected_count": 0,
                "error": None,
            },
        )
        self.reputation_patch.start()

    def tearDown(self):
        self.reputation_patch.stop()
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

    def test_official_youtube_watch_url_is_not_blocked(self):
        payload = api_server.predict(
            api_server.PredictRequest(
                url="https://www.youtube.com/watch?v=XkvZkBDjOI4&feature=youtu.be"
            )
        )
        self.assertEqual(payload.prediction, 0)
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

    def test_macro_document_payload_url_is_block_level_risk(self):
        payload = api_server.predict(
            api_server.PredictRequest(
                url="https://login.croppng.online/ad_document.docm?r=aFIlIT"
            )
        )
        self.assertEqual(payload.prediction, 1)
        self.assertEqual(payload.risk_level, "high")

    def test_installer_payload_url_is_block_level_risk(self):
        payload = api_server.predict(
            api_server.PredictRequest(
                url="https://login.croppng.online/evidence/phish_download_now.msi?r=TX48UR"
            )
        )
        self.assertEqual(payload.prediction, 1)
        self.assertEqual(payload.risk_level, "high")

    def test_suspicious_online_domain_is_block_level_when_model_confident(self):
        payload = api_server.predict(
            api_server.PredictRequest(url="https://www.creepylink.online/")
        )
        self.assertEqual(payload.prediction, 1)
        self.assertEqual(payload.risk_level, "high")

    def test_trusted_phishtank_research_page_is_not_hard_blocked(self):
        payload = api_server.predict(
            api_server.PredictRequest(url="https://www.phishtank.com/phish_archive.php")
        )
        self.assertNotEqual(payload.risk_level, "high")

    def test_hidden_iframe_alone_does_not_create_high_risk(self):
        risk_level = api_server._determine_risk_level(
            prediction=1,
            model_confidence=0.96,
            effective_confidence=0.96,
            url_features={
                "has_brand_mismatch": 0,
                "has_suspicious_tld": 0,
                "has_ip_address": 0,
                "has_executable_path": 0,
                "has_punycode": 0,
                "has_suspicious_keyword": 0,
            },
            dom_signals={
                "form_count": 0,
                "password_field_count": 0,
                "hidden_iframe_count": 3,
                "external_script_count": 4,
                "suspicious_text_hit_count": 0,
                "page_brand_mismatch": 0,
            },
            reputation={"verdict": "unavailable"},
        )
        self.assertEqual(risk_level, "medium")

    def test_clean_reputation_downgrades_weak_local_signal(self):
        risk_level = api_server._determine_risk_level(
            prediction=1,
            model_confidence=0.97,
            effective_confidence=0.97,
            url_features={
                "has_brand_mismatch": 0,
                "has_suspicious_tld": 0,
                "has_ip_address": 0,
                "has_executable_path": 0,
                "has_punycode": 0,
                "has_suspicious_keyword": 0,
            },
            dom_signals={
                "form_count": 0,
                "password_field_count": 0,
                "hidden_iframe_count": 1,
                "external_script_count": 4,
                "suspicious_text_hit_count": 0,
                "page_brand_mismatch": 0,
            },
            reputation={"verdict": "clean"},
        )
        self.assertEqual(risk_level, "medium")

    def test_oauth_style_brand_mismatch_without_url_evidence_stays_medium(self):
        risk_level = api_server._determine_risk_level(
            prediction=1,
            model_confidence=0.99,
            effective_confidence=1.0,
            url_features={
                "has_brand_mismatch": 0,
                "has_suspicious_tld": 0,
                "has_ip_address": 0,
                "has_executable_path": 0,
                "has_punycode": 0,
                "has_suspicious_keyword": 1,
            },
            dom_signals={
                "form_count": 1,
                "password_field_count": 1,
                "hidden_iframe_count": 0,
                "external_script_count": 4,
                "suspicious_text_hit_count": 3,
                "page_brand_mismatch": 1,
            },
            reputation={"verdict": "unavailable"},
        )
        self.assertEqual(risk_level, "medium")


if __name__ == "__main__":
    unittest.main()
