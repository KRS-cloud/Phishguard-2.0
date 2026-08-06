import hashlib
import hmac
from datetime import datetime, timezone

from flask import current_app
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db


class User(UserMixin, db.Model):
    """
    Stores registered PhishGuard users.
    """

    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    full_name = db.Column(
        db.String(120),
        nullable=False,
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False,
        index=True,
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    last_login = db.Column(
        db.DateTime,
        nullable=True,
    )

    last_seen = db.Column(
        db.DateTime,
        nullable=True,
        index=True,
    )

    login_count = db.Column(
        db.Integer,
        default=0,
        nullable=False,
    )

    is_admin = db.Column(
        db.Boolean,
        default=False,
        nullable=False,
    )

    is_active_account = db.Column(
        db.Boolean,
        default=True,
        nullable=False,
    )

    scans = db.relationship(
        "ScanHistory",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy=True,
    )

    def set_password(self, password):
        """
        Convert a plain password into a secure password hash.
        """

        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """
        Check whether a submitted password is correct.
        """

        return check_password_hash(
            self.password_hash,
            password,
        )

    @property
    def is_active(self):
        """
        Tell Flask-Login whether this account is active.
        """

        return self.is_active_account

    def get_session_fingerprint(self):
        """
        Generate a session fingerprint linked to the current
        password hash.

        Changing the password changes this fingerprint and
        invalidates all existing sessions.
        """

        secret_key = current_app.config["SECRET_KEY"]

        if isinstance(secret_key, str):
            secret_key = secret_key.encode("utf-8")

        password_hash = (self.password_hash or "").encode("utf-8")

        return hmac.new(
            secret_key,
            password_hash,
            hashlib.sha256,
        ).hexdigest()

    def get_id(self):
        """
        Return the identifier stored by Flask-Login.
        """

        return f"{self.id}:{self.get_session_fingerprint()}"

    def matches_session_fingerprint(
        self,
        supplied_fingerprint,
    ):
        """
        Verify that a stored session belongs to the user's
        current password.
        """

        if not supplied_fingerprint:
            return False

        return hmac.compare_digest(
            supplied_fingerprint,
            self.get_session_fingerprint(),
        )

    def __repr__(self):
        return f"<User {self.email}>"