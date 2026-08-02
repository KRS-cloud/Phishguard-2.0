from flask import flash, redirect, render_template, request, url_for
from werkzeug.exceptions import RequestEntityTooLarge


def register_error_handlers(app):
    """
    Register application-wide custom error handlers.
    """

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template("errors/500.html"), 500

    @app.errorhandler(RequestEntityTooLarge)
    def file_too_large(error):
        flash(
            "The uploaded file is too large. Maximum size is 5 MB.",
            "error",
        )
        return redirect(
            request.referrer or url_for("main.dashboard")
        )