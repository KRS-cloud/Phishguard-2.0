import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()

BASE_DIR = Path(__file__).resolve().parent


def get_boolean_environment_value(
    variable_name,
    default=False,
):
    value = os.getenv(variable_name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def get_database_url():
    """
    Return a SQLAlchemy-compatible database URL.

    Local development uses SQLite. Render supplies a PostgreSQL
    URL, which is converted to the Psycopg 3 driver format.
    """

    database_url = os.getenv(
        "DATABASE_URL"
    )

    if not database_url:
        return (
            f"sqlite:///"
            f"{BASE_DIR / 'instance' / 'phishguard.db'}"
        )

    if database_url.startswith(
        "postgres://"
    ):
        return database_url.replace(
            "postgres://",
            "postgresql+psycopg://",
            1,
        )

    if database_url.startswith(
        "postgresql://"
    ):
        return database_url.replace(
            "postgresql://",
            "postgresql+psycopg://",
            1,
        )

    return database_url


class Config:
    """
    Base configuration shared by the entire application.
    """

    APP_ENV = os.getenv(
        "APP_ENV",
        "development",
    ).strip().lower()

    IS_PRODUCTION = APP_ENV == "production"

    SECRET_KEY = os.getenv("SECRET_KEY")

    if not SECRET_KEY or len(SECRET_KEY) < 32:
        raise RuntimeError(
            "SECRET_KEY must be configured with at least 32 characters."
        )

    if IS_PRODUCTION and not os.getenv("DATABASE_URL"):
        raise RuntimeError(
            "DATABASE_URL must be configured in production."
        )

    SQLALCHEMY_DATABASE_URI = (
        get_database_url()
    )

    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
    }

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    MAX_FORM_MEMORY_SIZE = 1024 * 1024
    MAX_FORM_PARTS = 20

    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

    GEMINI_MODEL = os.getenv(
        "GEMINI_MODEL",
        "gemini-3.6-flash",
    )

    BREVO_API_KEY = os.getenv(
        "BREVO_API_KEY"
    )

    BREVO_SENDER_EMAIL = os.getenv(
        "BREVO_SENDER_EMAIL"
    )

    BREVO_SENDER_NAME = os.getenv(
        "BREVO_SENDER_NAME",
        "PhishGuard",
    )

    PASSWORD_RESET_MAX_AGE = int(
        os.getenv(
            "PASSWORD_RESET_MAX_AGE",
            "1800",
        )
    )

    APP_BASE_URL = os.getenv(
        "APP_BASE_URL",
        "http://127.0.0.1:5000",
    ).rstrip("/")

    if IS_PRODUCTION and not APP_BASE_URL.startswith("https://"):
        raise RuntimeError(
            "APP_BASE_URL must use HTTPS in production."
        )

    RATELIMIT_STORAGE_URI = os.getenv(
        "RATELIMIT_STORAGE_URI",
        "memory://",
    )

    RATELIMIT_HEADERS_ENABLED = True

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_NAME = "phishguard_session"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)

    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_NAME = "phishguard_remember"
    REMEMBER_COOKIE_DURATION = timedelta(days=14)

    SESSION_COOKIE_SECURE = (
        IS_PRODUCTION
        or get_boolean_environment_value(
            "COOKIE_SECURE",
            False,
        )
    )

    REMEMBER_COOKIE_SECURE = (
        IS_PRODUCTION
        or get_boolean_environment_value(
            "COOKIE_SECURE",
            False,
        )
    )

    PREFERRED_URL_SCHEME = (
        "https"
        if IS_PRODUCTION
        else "http"
    )

    TRUST_PROXY = (
        get_boolean_environment_value(
            "TRUST_PROXY",
            False,
        )
    )
