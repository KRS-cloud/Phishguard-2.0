import hashlib
import hmac

from flask import current_app
from itsdangerous import (
    BadSignature,
    SignatureExpired,
    URLSafeTimedSerializer,
)

from app.extensions import db
from app.models import User


RESET_TOKEN_SALT = "phishguard-password-reset-v2"


def _get_serializer():
    return URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"]
    )


def _get_password_fingerprint(user):
    """
    Create a protected fingerprint of the current password hash.

    When the password changes, this fingerprint changes and all
    previously generated reset tokens become invalid.
    """

    secret_key = current_app.config["SECRET_KEY"]

    if isinstance(secret_key, str):
        secret_key = secret_key.encode("utf-8")

    password_hash = (
        user.password_hash or ""
    ).encode("utf-8")

    return hmac.new(
        secret_key,
        password_hash,
        hashlib.sha256,
    ).hexdigest()


def generate_reset_token(user):
    serializer = _get_serializer()

    return serializer.dumps(
        {
            "user_id": user.id,
            "password_fingerprint": (
                _get_password_fingerprint(user)
            ),
        },
        salt=RESET_TOKEN_SALT,
    )


def verify_reset_token(token, max_age=None):
    if max_age is None:
        max_age = current_app.config.get(
            "PASSWORD_RESET_MAX_AGE",
            1800,
        )

    serializer = _get_serializer()

    try:
        payload = serializer.loads(
            token,
            salt=RESET_TOKEN_SALT,
            max_age=max_age,
        )

    except (SignatureExpired, BadSignature):
        return None

    user_id = payload.get("user_id")
    token_fingerprint = payload.get(
        "password_fingerprint"
    )

    if not isinstance(user_id, int):
        return None

    if not isinstance(token_fingerprint, str):
        return None

    user = db.session.get(
        User,
        user_id,
    )

    if user is None or not user.is_active_account:
        return None

    current_fingerprint = (
        _get_password_fingerprint(user)
    )

    if not hmac.compare_digest(
        token_fingerprint,
        current_fingerprint,
    ):
        return None

    return user