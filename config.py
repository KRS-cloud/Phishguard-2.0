import os
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

    SECRET_KEY = os.getenv("SECRET_KEY")

    if not SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY must be configured in .env."
        )

    SQLALCHEMY_DATABASE_URI = (
        get_database_url()
    )

    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
    }

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAX_CONTENT_LENGTH = 5 * 1024 * 1024

    MAIL_SERVER = os.getenv(
        "MAIL_SERVER",
        "smtp.gmail.com",
    )

    MAIL_PORT = int(
        os.getenv(
            "MAIL_PORT",
            "587",
        )
    )

    MAIL_USE_TLS = get_boolean_environment_value(
        "MAIL_USE_TLS",
        True,
    )

    MAIL_USE_SSL = get_boolean_environment_value(
        "MAIL_USE_SSL",
        False,
    )

    MAIL_USERNAME = os.getenv("MAIL_USERNAME")

    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

    MAIL_DEFAULT_SENDER = (
        os.getenv("MAIL_DEFAULT_SENDER") or MAIL_USERNAME
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

    RATELIMIT_STORAGE_URI = os.getenv(
        "RATELIMIT_STORAGE_URI",
        "memory://",
    )

    RATELIMIT_HEADERS_ENABLED = True

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"

    SESSION_COOKIE_SECURE = get_boolean_environment_value(
        "COOKIE_SECURE",
        False,
    )

    REMEMBER_COOKIE_SECURE = get_boolean_environment_value(
        "COOKIE_SECURE",
        False,
    )

    TRUST_PROXY = (
        get_boolean_environment_value(
            "TRUST_PROXY",
            False,
        )
    )