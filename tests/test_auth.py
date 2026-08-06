from unittest.mock import patch

from tests.base import AppTestCase
from app.extensions import db
from app.models import User
from app.services.password_reset_service import generate_reset_token


class AuthenticationTests(AppTestCase):
    def test_register_login_and_logout(self):
        response = self.client.post(
            "/auth/register",
            data={
                "full_name": "Pankaj Pawar",
                "email": "pankaj@example.com",
                "password": "UniquePass123",
                "confirm_password": "UniquePass123",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        user = db.session.scalar(
            db.select(User).where(User.email == "pankaj@example.com")
        )
        self.assertIsNotNone(user)
        self.assertNotEqual(user.password_hash, "UniquePass123")

        response = self.login("pankaj@example.com", "UniquePass123")
        self.assertIn(b"Welcome back", response.data)

        response = self.client.post("/auth/logout", follow_redirects=True)
        self.assertIn(b"logged out successfully", response.data)

    def test_password_reset_requires_possession_of_signed_link(self):
        user = self.create_user()
        token = generate_reset_token(user)

        with patch(
            "app.routes.auth_routes.send_password_changed_email"
        ):
            response = self.client.post(
                f"/auth/reset-password/{token}",
                data={
                    "password": "DifferentPass456",
                    "confirm_password": "DifferentPass456",
                },
                follow_redirects=True,
            )

        self.assertEqual(response.status_code, 200)
        db.session.refresh(user)
        self.assertTrue(user.check_password("DifferentPass456"))

        reused = self.client.get(
            f"/auth/reset-password/{token}",
            follow_redirects=True,
        )
        self.assertIn(b"invalid or has expired", reused.data)

    def test_forgot_password_response_does_not_reveal_account(self):
        with patch(
            "app.routes.auth_routes.send_password_reset_email"
        ) as sender:
            missing = self.client.post(
                "/auth/forgot-password",
                data={"email": "missing@example.com"},
                follow_redirects=True,
            )

        self.assertIn(
            b"If an active account exists",
            missing.data,
        )
        sender.assert_not_called()
