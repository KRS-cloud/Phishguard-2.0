import requests
from flask import current_app


BREVO_EMAIL_API_URL = (
    "https://api.brevo.com/v3/smtp/email"
)


def send_transactional_email(
    recipient_email,
    subject,
    body,
):
    """
    Send one transactional email through Brevo's HTTPS API.
    """

    api_key = current_app.config.get(
        "BREVO_API_KEY"
    )

    sender_email = current_app.config.get(
        "BREVO_SENDER_EMAIL"
    )

    sender_name = current_app.config.get(
        "BREVO_SENDER_NAME",
        "PhishGuard",
    )

    if not api_key or not sender_email:
        raise RuntimeError(
            "Brevo email delivery is not configured."
        )

    payload = {
        "sender": {
            "name": sender_name,
            "email": sender_email,
        },
        "to": [
            {
                "email": recipient_email,
            }
        ],
        "subject": subject,
        "textContent": body,
    }

    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json",
    }

    try:
        response = requests.post(
            BREVO_EMAIL_API_URL,
            json=payload,
            headers=headers,
            timeout=20,
        )

        response.raise_for_status()

    except requests.RequestException as error:
        status_code = (
            error.response.status_code
            if error.response is not None
            else None
        )

        current_app.logger.error(
            "Brevo email delivery failed with status %s.",
            status_code,
        )

        raise RuntimeError(
            "Transactional email delivery failed."
        ) from error


def send_password_reset_email(
    user,
    reset_url,
):
    """
    Send a password-reset link to the registered inbox.
    """

    body = f"""Hello {user.full_name},

A password reset was requested for your PhishGuard account.

Open this secure link to create a new password:

{reset_url}

This link expires in 30 minutes and can only be used once.

If you did not request this reset, ignore this email. Your current password will remain unchanged.

Never share this reset link with anyone.

PhishGuard AI & ML Security Platform
Developed by Pankaj Pawar
"""

    send_transactional_email(
        recipient_email=user.email,
        subject="Reset your PhishGuard password",
        body=body,
    )


def send_password_changed_email(user):
    """
    Notify the account owner after a successful reset.
    """

    body = f"""Hello {user.full_name},

Your PhishGuard account password was changed successfully.

If you performed this action, no further action is required.

If you did not perform this action, contact the administrator immediately.

PhishGuard AI & ML Security Platform
Developed by Pankaj Pawar
"""

    send_transactional_email(
        recipient_email=user.email,
        subject="Your PhishGuard password was changed",
        body=body,
    )