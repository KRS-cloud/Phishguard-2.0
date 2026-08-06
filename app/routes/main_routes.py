from datetime import datetime, timedelta

from flask import (
    Blueprint,
    current_app,
    jsonify,
    render_template,
    request,
    Response,
    send_from_directory,
)
from flask_login import current_user, login_required

from app.extensions import limiter
from app.models import ScanHistory
from app.services.ai_assistant import (
    explain_scan_result,
    get_ai_security_response,
)

main_bp = Blueprint(
    "main",
    __name__,
)


def assistant_user_key():
    """Use the signed-in user as the assistant rate-limit key."""

    return f"assistant-user:{current_user.id}"


@main_bp.route("/")
def home():
    """
    Display the public home page.
    """
    return render_template("index.html")


@main_bp.route("/about")
def about():
    """Explain the project's purpose and ownership."""

    return render_template("about.html")


@main_bp.route("/privacy")
def privacy():
    """Describe what the application processes and stores."""

    return render_template("privacy.html")


@main_bp.route("/security")
def security():
    """Explain safe use and the project's defensive scope."""

    return render_template("security.html")


@main_bp.route("google590769cadd41dffa.html")
def google_verification():
    """Serve Google Search Console ownership verification file from static directory."""

    return send_from_directory(current_app.static_folder, "google590769cadd41dffa.html")


@main_bp.route("/robots.txt")
def robots_txt():
    """Allow public documentation while excluding account areas."""

    body = """User-agent: *
Allow: /
Disallow: /admin/
Disallow: /analyze/
Disallow: /assistant
Disallow: /auth/
Disallow: /dashboard
Disallow: /history/
Disallow: /password/
"""

    return Response(body, mimetype="text/plain")


@main_bp.route("/.well-known/security.txt")
def security_txt():
    """Publish project ownership and a responsible-reporting path."""

    body = """Contact: https://github.com/KRS-cloud/Phishguard-2.0/issues
Expires: 2027-08-06T00:00:00Z
Preferred-Languages: en
Canonical: https://github.com/KRS-cloud/Phishguard-2.0/blob/main/SECURITY.md
Policy: https://github.com/KRS-cloud/Phishguard-2.0/blob/main/SECURITY.md
"""

    return Response(body, mimetype="text/plain")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    """
    Display the authenticated user's dashboard with analytics.
    """

    scans = (
        ScanHistory.query
        .filter_by(user_id=current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .all()
    )

    total_scans = len(scans)

    safe_scans = sum(
        1
        for scan in scans
        if scan.prediction == "Safe"
    )

    suspicious_scans = sum(
        1
        for scan in scans
        if scan.prediction == "Suspicious"
    )

    phishing_scans = sum(
        1
        for scan in scans
        if scan.prediction == "Phishing"
    )

    today = datetime.now().date()

    today_scans = sum(
        1
        for scan in scans
        if scan.created_at
        and scan.created_at.date() == today
    )

    recent_scans = scans[:8]

    recent_alerts = [
        scan
        for scan in scans
        if scan.prediction in [
            "Suspicious",
            "Phishing",
        ]
    ][:5]

    last_7_days = []

    for days_ago in range(6, -1, -1):

        day = today - timedelta(
            days=days_ago
        )

        count = sum(
            1
            for scan in scans
            if scan.created_at
            and scan.created_at.date() == day
        )

        last_7_days.append({
            "date": day.strftime("%d %b"),
            "day": day.strftime("%a"),
            "count": count,
        })

    max_daily_scans = max(
        [
            item["count"]
            for item in last_7_days
        ],
        default=1,
    )

    if max_daily_scans == 0:
        max_daily_scans = 1

    security_tips = [
        "Never share OTPs or passwords with anyone.",
        "Verify the exact domain before entering login details.",
        "HTTPS does not automatically mean a website is trustworthy.",
        "Avoid opening unexpected attachments from unknown senders.",
        "Scan unknown QR codes before opening their destination.",
        "Use unique passwords and enable two-factor authentication.",
    ]

    security_tip = security_tips[
        today.toordinal()
        % len(security_tips)
    ]

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        safe_scans=safe_scans,
        suspicious_scans=suspicious_scans,
        phishing_scans=phishing_scans,
        today_scans=today_scans,
        recent_scans=recent_scans,
        recent_alerts=recent_alerts,
        last_7_days=last_7_days,
        max_daily_scans=max_daily_scans,
        security_tip=security_tip,
    )


@main_bp.route("/assistant")
@login_required
def assistant():
    """
    Render the AI Assistant interface.
    """
    return render_template("assistant.html")


@main_bp.route(
    "/assistant/message",
    methods=["POST"],
)
@login_required
@limiter.limit(
    "20 per hour",
    methods=["POST"],
    key_func=assistant_user_key,
)
def assistant_message():
    """
    Handle one AI Assistant question without retaining chat history.
    """

    data = request.get_json(
        silent=True
    ) or {}

    if not isinstance(data, dict):
        return jsonify({
            "reply": "A JSON object containing a message is required.",
            "source": "local",
        }), 400

    message_value = data.get(
        "message",
        ""
    )

    if not isinstance(message_value, str):
        return jsonify({
            "reply": "Please enter a valid text question.",
            "source": "local",
        }), 400

    message = message_value.strip()

    if not message:
        return jsonify({
            "reply": "Please enter a message.",
            "source": "local",
        }), 400

    if len(message) > 500:
        return jsonify({
            "reply": "Questions must contain no more than 500 characters.",
            "source": "local",
        }), 400

    result = get_ai_security_response(
        message=message,
    )

    return jsonify(result)


@main_bp.route(
    "/assistant/explain-scan",
    methods=["POST"],
)
@login_required
@limiter.limit(
    "30 per hour",
    methods=["POST"],
    key_func=assistant_user_key,
)
def explain_scan():
    """
    Generate an AI explanation for a given scan result payload.
    """
    data = request.get_json(silent=True) or {}

    if not isinstance(data, dict):
        return jsonify({
            "reply": "A JSON object containing a scan result is required.",
            "category": "scan_explanation",
        }), 400
    supplied_result = data.get("scan_result")

    if not isinstance(supplied_result, dict):
        return jsonify({
            "reply": "A valid scan result is required.",
            "category": "scan_explanation",
        }), 400

    supplied_reasons = supplied_result.get("reasons", [])

    if not isinstance(supplied_reasons, list):
        supplied_reasons = []

    supplied_ml_result = supplied_result.get("ml_result")

    if not isinstance(supplied_ml_result, dict):
        supplied_ml_result = None

    sanitized_reasons = []

    for reason in supplied_reasons[:10]:
        if isinstance(reason, dict):
            sanitized_reasons.append({
                "message": str(reason.get("message", ""))[:300],
            })
        elif isinstance(reason, str):
            sanitized_reasons.append(reason[:300])

    scan_result = {
        "prediction": str(supplied_result.get("prediction", "Unknown"))[:30],
        "risk_level": str(supplied_result.get("risk_level", "Unknown"))[:30],
        "risk_score": supplied_result.get("risk_score", 0),
        "confidence": supplied_result.get("confidence", 0),
        "reasons": sanitized_reasons,
        "ml_result": supplied_ml_result,
    }

    result = explain_scan_result(scan_result)

    return jsonify(result)