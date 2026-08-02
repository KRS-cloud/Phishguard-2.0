from datetime import datetime, timezone
from pathlib import Path

from flask import Flask
from flask_login import current_user
from werkzeug.middleware.proxy_fix import ProxyFix

from app.extensions import (
    csrf,
    db,
    limiter,
    login_manager,
    mail,
)
from config import Config


def create_app(config_class=Config):
    """
    Create and configure the Flask application.
    """

    app = Flask(
        __name__,
        instance_relative_config=True,
    )

    app.config.from_object(config_class)

    if app.config.get("TRUST_PROXY"):
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=1,
            x_proto=1,
            x_host=1,
        )

    Path(app.instance_path).mkdir(
        parents=True,
        exist_ok=True,
    )

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)

    @app.before_request
    def update_user_activity():
        """
        Update last_seen at most once per minute.
        """

        if not current_user.is_authenticated:
            return

        now = datetime.now(timezone.utc).replace(tzinfo=None)

        last_seen = current_user.last_seen

        if last_seen is not None:
            elapsed = (now - last_seen).total_seconds()

            if elapsed < 60:
                return

        current_user.last_seen = now

        try:
            db.session.commit()

        except Exception:
            db.session.rollback()

    from app.models import User

    @login_manager.user_loader
    def load_user(session_identifier):
        """
        Load a user only when the stored session fingerprint
        matches the current password hash.
        """

        try:
            user_id_text, fingerprint = session_identifier.split(
                ":",
                1,
            )

            user_id = int(user_id_text)

        except (
            AttributeError,
            TypeError,
            ValueError,
        ):
            return None

        user = db.session.get(
            User,
            user_id,
        )

        if user is None:
            return None

        if not user.matches_session_fingerprint(fingerprint):
            return None

        return user

    from app.routes.admin_routes import admin_bp
    from app.routes.analyzer_routes import analyzer_bp
    from app.routes.auth_routes import auth_bp
    from app.routes.history_routes import history_bp
    from app.routes.main_routes import main_bp
    from app.routes.password_routes import password_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(analyzer_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(password_bp)
    app.register_blueprint(admin_bp)

    from app.errors import register_error_handlers

    register_error_handlers(app)

    return app