from unittest.mock import patch

from tests.base import AppTestCase
from app.routes.analyzer_routes import url_history_summary
from app.services.url_analyzer import analyze_url


class UrlAnalyzerTests(AppTestCase):
    def test_url_analysis_is_passive_and_returns_structured_result(self):
        with patch(
            "app.services.url_analyzer.predict_url_with_ml",
            return_value=None,
        ):
            result = analyze_url("https://example.com/docs")

        self.assertEqual(result["features"]["hostname"], "example.com")
        self.assertIn("risk_score", result)
        self.assertIn("recommendations", result)

    def test_history_summary_discards_credentials_paths_and_tokens(self):
        summary = url_history_summary(
            "https://person:password@example.com/private/reset"
            "?token=top-secret#account"
        )

        self.assertEqual(summary, "https://example.com")
        self.assertNotIn("password", summary)
        self.assertNotIn("token", summary)

    def test_invalid_url_is_rejected(self):
        with patch(
            "app.services.url_analyzer.predict_url_with_ml",
            return_value=None,
        ):
            with self.assertRaises(ValueError):
                analyze_url("not a valid url")
