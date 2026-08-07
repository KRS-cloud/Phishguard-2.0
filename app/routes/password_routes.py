from flask import Blueprint, render_template

password_bp = Blueprint(
    "password",
    __name__,
    url_prefix="/password",
)


@password_bp.route("/")
def password_tools():
    """
    Display the public browser-only password generator.

    Password material is created by the Web Crypto API and is
    never submitted to PhishGuard.
    """

    return render_template(
        "password/password_tools.html"
    )