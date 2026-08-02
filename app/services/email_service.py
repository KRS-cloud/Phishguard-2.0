from flask import current_app
from flask_mail import Message

from app.extensions import mail


def send_password_reset_email(
    user,
    reset_url,
):
    """
    Send a password-reset link to the registered inbox.
    """

    sender = current_app.config.get(
        "MAIL_DEFAULT_SENDER"
    )

    username = current_app.config.get(
        "MAIL_USERNAME"
    )

    password = current_app.config.get(
        "MAIL_PASSWORD"
    )

    if not sender or not username or not password:
        raise RuntimeError(
            "Password-reset email is not configured."
        )

    message = Message(
        subject="Reset your PhishGuard password",
        sender=sender,
        recipients=[
            user.email,
        ],
    )

    message.body = f"""Hello {user.full_name},

A password reset was requested for your PhishGuard account.

Open this secure link to create a new password:

{reset_url}

This link expires in 30 minutes and can only be used once.

If you did not request this reset, ignore this email. Your current password will remain unchanged.

Never share this reset link with anyone.

PhishGuard AI & ML Security Platform
Developed by Pankaj Pawar
"""

    mail.send(message)


def send_password_changed_email(user):
    """
    Notify the account owner after a successful reset.
    """

    sender = current_app.config.get(
        "MAIL_DEFAULT_SENDER"
    )

    if not sender:
        return

    message = Message(
        subject="Your PhishGuard password was changed",
        sender=sender,
        recipients=[
            user.email,
        ],
    )

    message.body = f"""Hello {user.full_name},

Your PhishGuard account password was changed successfully.

If you performed this action, no further action is required.

If you did not perform this action, contact the administrator immediately.

PhishGuard AI & ML Security Platform
Developed by Pankaj Pawar
"""

    mail.send(message)