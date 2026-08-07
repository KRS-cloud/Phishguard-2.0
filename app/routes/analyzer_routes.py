import json
from urllib.parse import urlsplit, urlunsplit

from flask import Blueprint, flash, render_template, request
from flask_limiter.util import get_remote_address
from flask_login import current_user

from app.extensions import db, limiter
from app.ml.email_features import extract_email_features
from app.models import ScanHistory
from app.services.qr_analyzer import analyze_qr_code, is_allowed_image
from app.services.url_analyzer import analyze_url

analyzer_bp = Blueprint(
    "analyzer",
    __name__,
    url_prefix="/analyze",
)


def analyzer_rate_limit_key():
    """
    Use the account ID for signed-in users and the client IP
    address for anonymous visitors.
    """

    if current_user.is_authenticated:
        return f"user:{current_user.id}"

    return f"guest:{get_remote_address()}"


def save_authenticated_scan(
    scan_type,
    input_value,
    result,
):
    """
    Save a scan only when the visitor is signed in.

    Anonymous visitors receive the complete result, but no
    database history record is created.
    """

    if not current_user.is_authenticated:
        return False

    scan_record = ScanHistory(
        user_id=current_user.id,
        scan_type=scan_type,
        input_value=input_value,
        prediction=result["prediction"],
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        confidence=result["confidence"],
        explanation=result["explanation"],
        recommendations=json.dumps(
            result["recommendations"]
        ),
    )

    try:
        db.session.add(scan_record)
        db.session.commit()

        flash(
            "Analysis completed and saved to your history.",
            "success",
        )

        return True

    except Exception:
        db.session.rollback()

        flash(
            "The analysis completed, but it could not be saved "
            "to your history.",
            "warning",
        )

        return False


def url_history_summary(value):
    """
    Retain only a URL's origin in scan history.

    User information, paths, query strings and fragments can contain
    reset tokens or other secrets and are deliberately discarded.
    """

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname

        if not hostname:
            return "URL analyzed (details not retained)"

        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"

        netloc = hostname

        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"

        scheme = parsed.scheme.lower()

        if scheme not in {"http", "https"}:
            scheme = "https"

        return urlunsplit((scheme, netloc, "", "", ""))

    except (TypeError, ValueError):
        return "URL analyzed (details not retained)"


def add_risk(reasons, feature, message, score):
    """
    Add one detected email risk.
    """
    reasons.append(
        {
            "feature": feature,
            "message": message,
            "score": score,
        }
    )
    return score


def analyze_email(sender_email, subject, body):
    """
    Analyze email content for phishing indicators.
    """
    features = extract_email_features(
        sender_email,
        subject,
        body,
    )

    risk_score = 0
    reasons = []

    if not body.strip():
        raise ValueError("Please enter the suspicious email content.")

    if features["urgent_words"]:
        words = ", ".join(features["urgent_words"][:5])
        risk_score += add_risk(
            reasons,
            "Urgency",
            f"The email uses urgent language: {words}.",
            12,
        )

    if features["threat_words"]:
        words = ", ".join(features["threat_words"][:5])
        risk_score += add_risk(
            reasons,
            "Threatening language",
            f"The message contains threats or account warnings: {words}.",
            15,
        )

    if features["credential_words"]:
        words = ", ".join(features["credential_words"][:5])
        risk_score += add_risk(
            reasons,
            "Credential request",
            f"The email asks about login or identity information: {words}.",
            18,
        )

    if features["financial_words"]:
        words = ", ".join(features["financial_words"][:5])
        risk_score += add_risk(
            reasons,
            "Financial request",
            f"The email contains financial or payment-related wording: {words}.",
            12,
        )

    if features["otp_words"]:
        words = ", ".join(features["otp_words"][:5])
        risk_score += add_risk(
            reasons,
            "OTP request",
            f"The message refers to sensitive verification codes: {words}.",
            20,
        )

    if features["reward_words"]:
        words = ", ".join(features["reward_words"][:5])
        risk_score += add_risk(
            reasons,
            "Prize or reward",
            f"The message uses prize or reward language: {words}.",
            14,
        )

    if features["generic_greetings"]:
        risk_score += add_risk(
            reasons,
            "Generic greeting",
            "The message uses a generic greeting instead of the recipient's name.",
            5,
        )

    if features["uppercase_ratio"] > 0.45:
        risk_score += add_risk(
            reasons,
            "Uppercase text",
            "A large portion of the message is written in uppercase letters.",
            8,
        )

    if features["exclamation_count"] >= 5:
        risk_score += add_risk(
            reasons,
            "Excessive punctuation",
            "The message uses an unusually high number of exclamation marks.",
            7,
        )

    if features["suspicious_attachments"]:
        extensions = ", ".join(features["suspicious_attachments"])
        risk_score += add_risk(
            reasons,
            "Suspicious attachment",
            f"The message mentions potentially dangerous attachment types: {extensions}.",
            20,
        )

    if features["contains_html_form"]:
        risk_score += add_risk(
            reasons,
            "Embedded form",
            "The email appears to contain an embedded form requesting information.",
            18,
        )

    if features["uses_free_email_domain"] and (
        features["financial_words"] or features["credential_words"]
    ):
        risk_score += add_risk(
            reasons,
            "Sender domain",
            "The sender uses a free email service while requesting sensitive information.",
            10,
        )

    suspicious_links = []

    for url in features["urls"][:5]:
        try:
            url_result = analyze_url(url)
        except ValueError:
            continue

        if url_result["prediction"] in {"Suspicious", "Phishing"}:
            suspicious_links.append(
                {
                    "url": url,
                    "prediction": url_result["prediction"],
                    "risk_score": url_result["risk_score"],
                }
            )

    if suspicious_links:
        highest_link_score = max(
            link["risk_score"] for link in suspicious_links
        )
        link_risk = min(25, 10 + int(highest_link_score * 0.2))
        risk_score += add_risk(
            reasons,
            "Suspicious link",
            "One or more links inside the email contain phishing indicators.",
            link_risk,
        )
    elif features["url_count"] >= 4:
        risk_score += add_risk(
            reasons,
            "Multiple links",
            "The email contains an unusually high number of links.",
            6,
        )

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        prediction = "Phishing"
        risk_level = "High"
        confidence = min(72 + risk_score * 0.24, 98)
    elif risk_score >= 30:
        prediction = "Suspicious"
        risk_level = "Medium"
        confidence = min(62 + risk_score * 0.28, 93)
    else:
        prediction = "Safe"
        risk_level = "Low"
        confidence = max(65, 94 - risk_score)

    if reasons:
        explanation = " ".join(reason["message"] for reason in reasons)
    else:
        explanation = (
            "No major phishing indicators were detected in the submitted email."
        )

    recommendations = build_email_recommendations(
        prediction,
        suspicious_links,
        features,
    )

    return {
        "prediction": prediction,
        "risk_level": risk_level,
        "risk_score": float(risk_score),
        "confidence": round(float(confidence), 2),
        "explanation": explanation,
        "recommendations": recommendations,
        "reasons": reasons,
        "features": features,
        "suspicious_links": suspicious_links,
    }


def build_email_recommendations(prediction, suspicious_links, features):
    """
    Create safety recommendations for the email report.
    """
    recommendations = []

    if prediction == "Phishing":
        recommendations.extend(
            [
                "Do not reply to the email.",
                "Do not click any links or download attachments.",
                "Do not share passwords, banking information or OTP codes.",
                "Report the message as phishing and delete it.",
                "Contact the organization using its official website or phone number.",
            ]
        )
    elif prediction == "Suspicious":
        recommendations.extend(
            [
                "Verify the sender through another trusted communication method.",
                "Avoid clicking links until the message is confirmed.",
                "Check the sender's complete email address carefully.",
                "Visit the official website manually instead of using email links.",
            ]
        )
    else:
        recommendations.extend(
            [
                "No major indicators were found, but continue carefully.",
                "Verify unexpected requests before sharing sensitive information.",
                "Check the sender address and linked domains before taking action.",
            ]
        )

    if suspicious_links:
        recommendations.append(
            "At least one link was flagged. Do not open it directly."
        )

    if features["suspicious_attachments"]:
        recommendations.append(
            "Do not open the mentioned attachment unless the sender is verified."
        )

    return recommendations


@analyzer_bp.route("/url", methods=["GET", "POST"])
@limiter.limit(
    "30 per hour",
    methods=["POST"],
    key_func=analyzer_rate_limit_key,
)
def url_analyzer():
    """
    Display and process the URL phishing analyzer.
    """
    result = None
    submitted_url = ""

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()

        if not submitted_url:
            flash("Please enter a website URL.", "error")
            return render_template(
                "analyzers/url_analyzer.html",
                submitted_url=submitted_url,
                result=None,
            )

        if len(submitted_url) > 2048:
            flash("The submitted URL is too long.", "error")
            return render_template(
                "analyzers/url_analyzer.html",
                submitted_url="",
                result=None,
            )

        try:
            result = analyze_url(submitted_url)
        except ValueError as error:
            flash(str(error), "error")
            return render_template(
                "analyzers/url_analyzer.html",
                submitted_url=submitted_url,
                result=None,
            )

        save_authenticated_scan(
            scan_type="URL",
            input_value=url_history_summary(
                result["normalized_url"]
            ),
            result=result,
        )

    return render_template(
        "analyzers/url_analyzer.html",
        submitted_url=submitted_url,
        result=result,
    )


@analyzer_bp.route("/email", methods=["GET", "POST"])
@limiter.limit(
    "20 per hour",
    methods=["POST"],
    key_func=analyzer_rate_limit_key,
)
def email_analyzer():
    """
    Display and process the email phishing analyzer.
    """
    result = None
    sender_email = ""
    subject = ""
    email_body = ""

    if request.method == "POST":
        sender_email = request.form.get("sender_email", "").strip().lower()
        subject = request.form.get("subject", "").strip()
        email_body = request.form.get("email_body", "").strip()

        if len(sender_email) > 200 or len(subject) > 300:
            flash(
                "The sender address or subject is too long.",
                "error",
            )
            return render_template(
                "analyzers/email_analyzer.html",
                sender_email="",
                subject="",
                email_body=email_body,
                result=None,
            )

        if not email_body:
            flash("Please enter the suspicious email content.", "error")
            return render_template(
                "analyzers/email_analyzer.html",
                sender_email=sender_email,
                subject=subject,
                email_body=email_body,
                result=None,
            )

        if len(email_body) > 20000:
            flash("The submitted email content is too long.", "error")
            return render_template(
                "analyzers/email_analyzer.html",
                sender_email=sender_email,
                subject=subject,
                email_body="",
                result=None,
            )

        try:
            result = analyze_email(sender_email, subject, email_body)
        except ValueError as error:
            flash(str(error), "error")
            return render_template(
                "analyzers/email_analyzer.html",
                sender_email=sender_email,
                subject=subject,
                email_body=email_body,
                result=None,
            )

        save_authenticated_scan(
            scan_type="Email",
            input_value="Email content (not retained)",
            result=result,
        )

    return render_template(
        "analyzers/email_analyzer.html",
        sender_email=sender_email,
        subject=subject,
        email_body=email_body,
        result=result,
    )


@analyzer_bp.route("/qr", methods=["GET", "POST"])
@limiter.limit(
    "15 per hour",
    methods=["POST"],
    key_func=analyzer_rate_limit_key,
)
def qr_analyzer():
    """
    Upload, decode, and analyze a QR-code image.
    """
    result = None
    uploaded_filename = ""

    if request.method == "POST":
        uploaded_file = request.files.get("qr_image")

        if uploaded_file is None:
            flash("Please select a QR-code image.", "error")
            return render_template(
                "analyzers/qr_analyzer.html",
                result=None,
                uploaded_filename="",
            )

        uploaded_filename = (uploaded_file.filename or "").strip()

        if not uploaded_filename:
            flash("Please select a QR-code image.", "error")
            return render_template(
                "analyzers/qr_analyzer.html",
                result=None,
                uploaded_filename="",
            )

        if not is_allowed_image(uploaded_filename):
            flash(
                "Only PNG, JPG, JPEG, and WEBP images are supported.",
                "error",
            )
            return render_template(
                "analyzers/qr_analyzer.html",
                result=None,
                uploaded_filename="",
            )

        file_bytes = uploaded_file.read()

        if len(file_bytes) > 5 * 1024 * 1024:
            flash(
                "The uploaded image must be smaller than 5 MB.",
                "error",
            )
            return render_template(
                "analyzers/qr_analyzer.html",
                result=None,
                uploaded_filename="",
            )

        try:
            result = analyze_qr_code(file_bytes)
        except ValueError as error:
            flash(str(error), "error")
            return render_template(
                "analyzers/qr_analyzer.html",
                result=None,
                uploaded_filename=uploaded_filename,
            )

        if result["content_type"] == "URL":
            history_input = url_history_summary(result["decoded_text"])
        else:
            history_input = "QR text content (not retained)"

        save_authenticated_scan(
            scan_type="QR",
            input_value=history_input,
            result=result,
        )

    return render_template(
        "analyzers/qr_analyzer.html",
        result=result,
        uploaded_filename=uploaded_filename,
    )