from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Blueprint,
    abort,
    render_template,
)
from flask_login import (
    current_user,
    login_required,
)

from app.extensions import db
from app.models import ScanHistory, User


admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
)


def admin_required(view_function):
    """
    Allow access only to authenticated administrators.
    """

    @wraps(view_function)
    @login_required
    def wrapped_view(*args, **kwargs):

        if not current_user.is_admin:
            abort(403)

        return view_function(
            *args,
            **kwargs,
        )

    return wrapped_view


@admin_bp.route("/")
@admin_required
def dashboard():
    """
    Display administrator statistics and recent activity.
    """

    now = datetime.now(
        timezone.utc
    ).replace(
        tzinfo=None
    )

    active_threshold = (
        now - timedelta(minutes=5)
    )

    today_start = datetime(
        now.year,
        now.month,
        now.day,
    )

    total_users = (
        db.session.scalar(
            db.select(
                db.func.count(User.id)
            )
        )
        or 0
    )

    active_users = (
        db.session.scalar(
            db.select(
                db.func.count(User.id)
            ).where(
                User.last_seen.is_not(None),
                User.last_seen >= active_threshold,
                User.is_active_account.is_(True),
            )
        )
        or 0
    )

    logged_in_today = (
        db.session.scalar(
            db.select(
                db.func.count(User.id)
            ).where(
                User.last_login.is_not(None),
                User.last_login >= today_start,
            )
        )
        or 0
    )

    total_scans = (
        db.session.scalar(
            db.select(
                db.func.count(ScanHistory.id)
            )
        )
        or 0
    )

    recent_users = db.session.scalars(
        db.select(User)
        .order_by(
            User.created_at.desc()
        )
        .limit(8)
    ).all()

    recent_scans = db.session.scalars(
        db.select(ScanHistory)
        .order_by(
            ScanHistory.created_at.desc()
        )
        .limit(8)
    ).all()

    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        active_users=active_users,
        logged_in_today=logged_in_today,
        total_scans=total_scans,
        recent_users=recent_users,
        recent_scans=recent_scans,
        active_threshold=active_threshold,
    )