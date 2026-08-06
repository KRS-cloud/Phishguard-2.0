from tests.base import AppTestCase
from app.extensions import db
from app.models import ScanHistory
from app.services.email_analyzer import analyze_email


class EmailAnalyzerTests(AppTestCase):
    def test_suspicious_language_produces_indicators(self):
        result = analyze_email(
            "unknown@example.com",
            "URGENT account warning",
            "Act now! Send your password and OTP immediately!!!!!",
        )

        self.assertGreater(result["risk_score"], 0)
        self.assertTrue(result["reasons"])
        self.assertIn(result["prediction"], {"Suspicious", "Phishing"})

    def test_route_does_not_retain_email_content(self):
        self.create_user()
        self.login()
        secret_marker = "private-message-marker-123"

        response = self.client.post(
            "/analyze/email",
            data={
                "sender_email": "unknown@example.com",
                "subject": "Private subject",
                "email_body": f"Urgent verification {secret_marker}",
            },
        )

        self.assertEqual(response.status_code, 200)
        scan = db.session.scalar(db.select(ScanHistory))
        self.assertEqual(scan.input_value, "Email content (not retained)")
        self.assertNotIn(secret_marker, scan.input_value)
