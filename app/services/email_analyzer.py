from app.ml.email_features import extract_email_features
from app.services.url_analyzer import analyze_url


def add_risk(
    reasons,
    feature,
    message,
    score,
):
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


def analyze_email(
    sender_email,
    subject,
    body,
):
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
        raise ValueError(
            "Please enter the suspicious email content."
        )

    if features["urgent_words"]:
        words = ", ".join(
            features["urgent_words"][:5]
        )

        risk_score += add_risk(
            reasons,
            "Urgency",
            f"The email uses urgent language: {words}.",
            12,
        )

    if features["threat_words"]:
        words = ", ".join(
            features["threat_words"][:5]
        )

        risk_score += add_risk(
            reasons,
            "Threatening language",
            f"The message contains threats or account warnings: {words}.",
            15,
        )

    if features["credential_words"]:
        words = ", ".join(
            features["credential_words"][:5]
        )

        risk_score += add_risk(
            reasons,
            "Credential request",
            f"The email asks about login or identity information: {words}.",
            18,
        )

    if features["financial_words"]:
        words = ", ".join(
            features["financial_words"][:5]
        )

        risk_score += add_risk(
            reasons,
            "Financial request",
            f"The email contains financial or payment-related wording: {words}.",
            12,
        )

    if features["otp_words"]:
        words = ", ".join(
            features["otp_words"][:5]
        )

        risk_score += add_risk(
            reasons,
            "OTP request",
            f"The message refers to sensitive verification codes: {words}.",
            20,
        )

    if features["reward_words"]:
        words = ", ".join(
            features["reward_words"][:5]
        )

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
        extensions = ", ".join(
            features["suspicious_attachments"]
        )

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

    if (
        features["uses_free_email_domain"]
        and (
            features["financial_words"]
            or features["credential_words"]
        )
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

        if url_result["prediction"] in {
            "Suspicious",
            "Phishing",
        }:
            suspicious_links.append(
                {
                    "url": url,
                    "prediction": url_result["prediction"],
                    "risk_score": url_result["risk_score"],
                }
            )

    if suspicious_links:
        highest_link_score = max(
            link["risk_score"]
            for link in suspicious_links
        )

        link_risk = min(
            25,
            10 + int(highest_link_score * 0.2),
        )

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

    risk_score = min(
        risk_score,
        100,
    )

    if risk_score >= 60:
        prediction = "Phishing"
        risk_level = "High"
        confidence = min(
            72 + risk_score * 0.24,
            98,
        )

    elif risk_score >= 30:
        prediction = "Suspicious"
        risk_level = "Medium"
        confidence = min(
            62 + risk_score * 0.28,
            93,
        )

    else:
        prediction = "Safe"
        risk_level = "Low"
        confidence = max(
            65,
            94 - risk_score,
        )

    if reasons:
        explanation = " ".join(
            reason["message"]
            for reason in reasons
        )

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
        "confidence": round(
            float(confidence),
            2,
        ),
        "explanation": explanation,
        "recommendations": recommendations,
        "reasons": reasons,
        "features": features,
        "suspicious_links": suspicious_links,
    }


def build_email_recommendations(
    prediction,
    suspicious_links,
    features,
):
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
