import os


os.environ.setdefault(
    "SECRET_KEY",
    "test-secret-key-with-at-least-32-characters",
)
os.environ.setdefault("APP_ENV", "development")
