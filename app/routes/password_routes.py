from flask import Blueprint, render_template

from flask_login import login_required

password_bp = Blueprint(
    "password",
    __name__,
    url_prefix="/password",
)


@password_bp.route("/")
@login_required
def password_tools():
    """
    Display a browser-only password generator.

    Password material is created by the Web Crypto API and is
    never submitted to PhishGuard.
    """

    return render_template(
        "password/password_tools.html"
    )
