from tests.base import AppTestCase
from app.extensions import db
from app.models import ScanHistory, User
from app.routes.history_routes import pdf_text, safe_csv_cell


class DatabaseAndAccessTests(AppTestCase):
    def test_database_relationship_and_password_session_fingerprint(self):
        user = self.create_user()
        original_fingerprint = user.get_session_fingerprint()

        scan = ScanHistory(
            user_id=user.id,
            scan_type="URL",
            input_value="https://example.com",
            prediction="Safe",
            risk_level="Low",
            risk_score=2.0,
        )
        db.session.add(scan)
        db.session.commit()

        self.assertEqual(len(user.scans), 1)
        user.set_password("DifferentPass456")
        self.assertFalse(user.matches_session_fingerprint(original_fingerprint))

    def test_security_headers_and_custom_access_denied_page(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

        self.create_user()
        self.login()
        denied = self.client.get("/admin/")
        self.assertEqual(denied.status_code, 403)
        self.assertIn(b"Access denied", denied.data)

    def test_public_transparency_pages_exist(self):
        for path in (
            "/about",
            "/privacy",
            "/security",
            "/robots.txt",
            "/.well-known/security.txt",
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)

    def test_export_helpers_neutralize_active_content(self):
        self.assertEqual(safe_csv_cell("=1+1"), "'=1+1")
        self.assertEqual(pdf_text("<b>unsafe</b>"), "&lt;b&gt;unsafe&lt;/b&gt;")
