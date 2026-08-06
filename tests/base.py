import os
import unittest


os.environ.setdefault(
    "SECRET_KEY",
    "test-secret-key-with-at-least-32-characters",
)
os.environ.setdefault("APP_ENV", "development")

from app import create_app
from app.extensions import db
from app.models import User


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret-key-with-at-least-32-characters"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {}
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False
    RATELIMIT_STORAGE_URI = "memory://"
    APP_BASE_URL = "http://localhost"
    PASSWORD_RESET_MAX_AGE = 1800
    TRUST_PROXY = False
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    GEMINI_API_KEY = None
    GEMINI_MODEL = "gemini-3.6-flash"
    BREVO_API_KEY = None
    BREVO_SENDER_EMAIL = None
    BREVO_SENDER_NAME = "PhishGuard"
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    MAX_FORM_MEMORY_SIZE = 1024 * 1024
    MAX_FORM_PARTS = 20


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def create_user(
        self,
        email="student@example.com",
        password="StrongPass123",
        is_admin=False,
    ):
        user = User(
            full_name="Test Student",
            email=email,
            is_admin=is_admin,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    def login(
        self,
        email="student@example.com",
        password="StrongPass123",
    ):
        return self.client.post(
            "/auth/login",
            data={
                "email": email,
                "password": password,
            },
            follow_redirects=True,
        )
