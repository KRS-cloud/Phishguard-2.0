from datetime import datetime, timedelta

from flask import (
    Blueprint,
    jsonify,
    render_template,
    request,
    session,
)
from flask_login import current_user, login_required

from app.models import ScanHistory
from app.services.ai_assistant import (
    explain_scan_result,
    get_ai_security_response,
)

main_bp = Blueprint(
    "main",
    __name__,
)


@main_bp.route("/")
def home():
    """
    Display the public home page.
    """
    return render_template("index.html")


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
def assistant_message():
    """
    Handle general AI Assistant conversations with session history.
    """

    data = request.get_json(
        silent=True
    ) or {}

    message = data.get(
        "message",
        ""
    ).strip()

    if not message:
        return jsonify({
            "reply": "Please enter a message.",
            "source": "local",
        })

    conversation = session.get(
        "assistant_conversation",
        [],
    )

    conversation.append({
        "role": "user",
        "message": message,
    })

    # Keep only recent conversation to avoid sending unlimited history.
    conversation = conversation[-12:]

    scan_context = data.get(
        "scan_context"
    )

    result = get_ai_security_response(
        message=message,
        scan_context=scan_context,
        conversation=conversation,
    )

    conversation.append({
        "role": "assistant",
        "message": result["reply"],
    })

    session[
        "assistant_conversation"
    ] = conversation[-12:]

    session.modified = True

    return jsonify(result)


@main_bp.route(
    "/assistant/reset",
    methods=["POST"],
)
@login_required
def reset_assistant():
    """
    Clear the current AI conversation.
    """

    session.pop(
        "assistant_conversation",
        None,
    )

    return jsonify({
        "success": True,
    })


@main_bp.route(
    "/assistant/explain-scan",
    methods=["POST"],
)
@login_required
def explain_scan():
    """
    Generate an AI explanation for a given scan result payload.
    """
    data = request.get_json(silent=True) or {}
    scan_result = data.get("scan_result")

    result = explain_scan_result(scan_result)

    return jsonify(result)