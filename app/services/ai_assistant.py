import re

from flask import current_app

from app.services.gemini_assistant import (
    generate_ai_response,
)


def normalize_message(message):
    if not message:
        return ""

    message = message.strip().lower()
    message = re.sub(r"\s+", " ", message)

    return message


def contains_word(message, word):
    """
    Match a complete word instead of a substring.

    Example:
    'hi' matches 'hi'
    but does NOT match 'phishing'.
    """
    pattern = r"\b" + re.escape(word) + r"\b"

    return bool(
        re.search(pattern, message)
    )


def contains_any_word(message, words):
    return any(
        contains_word(message, word)
        for word in words
    )


def get_security_response(message):
    message = normalize_message(message)

    if not message:
        return {
            "reply": (
                "Please enter a cybersecurity question "
                "so I can help you."
            ),
            "category": "general",
        }

    # ---------------------------------
    # GREETINGS
    # ---------------------------------

    greeting_words = [
        "hi",
        "hello",
        "hey",
        "hii",
    ]

    greeting_phrases = [
        "good morning",
        "good afternoon",
        "good evening",
    ]

    if (
        contains_any_word(
            message,
            greeting_words,
        )
        or message in greeting_phrases
    ):
        return {
            "reply": (
                "Hello! I'm the PhishGuard Security Assistant. "
                "You can ask me about phishing, suspicious URLs, "
                "emails, QR codes, passwords, scams, OTPs, "
                "malware, and account security."
            ),
            "category": "greeting",
        }

    # ---------------------------------
    # PHISHING EMAIL
    # Check specific topics BEFORE
    # general phishing.
    # ---------------------------------

    if (
        "phishing email" in message
        or "suspicious email" in message
        or "fake email" in message
        or "email scam" in message
        or (
            "email" in message
            and "phishing" in message
        )
    ):
        return {
            "reply": (
                "A phishing email often tries to create urgency "
                "or fear so that you act without checking it. "
                "Look for an unusual sender address, unexpected "
                "attachments, suspicious links, requests for "
                "passwords or OTPs, spelling changes in company "
                "domains, and messages claiming your account will "
                "be suspended immediately. Avoid clicking the link "
                "directly. Verify the request through the company's "
                "official website or app instead."
            ),
            "category": "email_security",
        }

    # ---------------------------------
    # PHISHING
    # ---------------------------------

    if (
        "what is phishing" in message
        or "define phishing" in message
        or "phishing meaning" in message
        or "explain phishing" in message
    ):
        return {
            "reply": (
                "Phishing is a social-engineering attack where "
                "someone impersonates a trusted person or "
                "organization to trick you into revealing "
                "information such as passwords, OTPs, banking "
                "details, or card information. It commonly uses "
                "fake websites, emails, messages, and QR codes."
            ),
            "category": "phishing",
        }

    # ---------------------------------
    # SUSPICIOUS URL
    # ---------------------------------

    if (
        contains_word(message, "url")
        or contains_word(message, "link")
        or "website safe" in message
        or "safe website" in message
        or "phishing website" in message
    ):
        return {
            "reply": (
                "When checking a URL, inspect the actual domain "
                "carefully. Warning signs include misspelled brand "
                "names, IP addresses instead of domains, excessive "
                "subdomains, URL shorteners, unusual characters, "
                "suspicious words such as login or verify, and "
                "unexpected requests for sensitive information. "
                "HTTPS is useful, but HTTPS alone does not prove "
                "that a website is legitimate. You can analyze the "
                "URL using PhishGuard's URL Analyzer."
            ),
            "category": "url_security",
        }

    # ---------------------------------
    # QR
    # ---------------------------------

    if (
        contains_word(message, "qr")
        or "qr code" in message
    ):
        return {
            "reply": (
                "A QR code itself is not automatically safe or "
                "dangerous. The risk comes from what it contains. "
                "A malicious QR code can redirect you to a phishing "
                "website. Check the decoded URL before opening it, "
                "especially if the QR code asks for passwords, "
                "payments, banking details, or OTPs. PhishGuard's "
                "QR Analyzer can inspect the destination URL."
            ),
            "category": "qr_security",
        }

    # ---------------------------------
    # PASSWORD
    # ---------------------------------

    if contains_word(
        message,
        "password",
    ):
        return {
            "reply": (
                "Use a long and unique password for every important "
                "account. Avoid names, birthdays, phone numbers, "
                "common words, and reused passwords. A password "
                "manager can generate and store strong passwords. "
                "Enable two-factor authentication for additional "
                "protection. PhishGuard's browser-only generator can "
                "create a random password without sending it to the server."
            ),
            "category": "password_security",
        }

    # ---------------------------------
    # OTP
    # ---------------------------------

    if (
        contains_word(message, "otp")
        or "one time password" in message
        or "one-time password" in message
    ):
        return {
            "reply": (
                "Treat an OTP like a temporary password. Do not "
                "share it with someone who calls, messages, or "
                "emails you asking for it. If you receive an OTP "
                "you did not request, someone may be attempting to "
                "access your account."
            ),
            "category": "otp_security",
        }

    # ---------------------------------
    # HTTPS
    # ---------------------------------

    if (
        contains_word(message, "https")
        or contains_word(message, "ssl")
        or contains_word(message, "padlock")
    ):
        return {
            "reply": (
                "HTTPS encrypts communication between your browser "
                "and a website, but it does not guarantee that the "
                "website belongs to the organization it claims to "
                "represent. Phishing websites can also obtain HTTPS "
                "certificates. Always verify the domain itself."
            ),
            "category": "https_security",
        }

    # ---------------------------------
    # MALWARE
    # ---------------------------------

    if (
        contains_word(message, "malware")
        or contains_word(message, "virus")
    ):
        return {
            "reply": (
                "Malware is software designed to perform harmful "
                "actions such as stealing information, spying on "
                "users, damaging files, or gaining unauthorized "
                "access. Avoid unknown downloads and attachments, "
                "keep software updated, and use trusted security "
                "tools."
            ),
            "category": "malware",
        }

    # ---------------------------------
    # TWO-FACTOR AUTHENTICATION
    # ---------------------------------

    if (
        contains_word(message, "2fa")
        or "two factor" in message
        or "two-factor" in message
    ):
        return {
            "reply": (
                "Two-factor authentication requires another proof "
                "of identity in addition to your password. This "
                "significantly reduces the risk of account takeover "
                "when a password is stolen."
            ),
            "category": "account_security",
        }

    # ---------------------------------
    # CLICKED PHISHING LINK
    # ---------------------------------

    if (
        contains_word(message, "clicked")
        and (
            contains_word(message, "phishing")
            or contains_word(message, "fake")
            or contains_word(message, "scam")
            or contains_word(message, "suspicious")
        )
    ):
        return {
            "reply": (
                "If you clicked a suspicious link but entered "
                "nothing, close the page and avoid downloading "
                "anything. If you entered a password, change it "
                "through the legitimate website and enable 2FA. "
                "If you entered financial information, contact "
                "your bank or payment provider promptly. Also "
                "review the affected account for unauthorized "
                "activity."
            ),
            "category": "incident_response",
        }

    # ---------------------------------
    # PHISHGUARD
    # ---------------------------------

    if (
        contains_word(message, "phishguard")
        or "what can you do" in message
        or "your features" in message
    ):
        return {
            "reply": (
                "PhishGuard combines cybersecurity rules and "
                "machine learning to analyze URLs. It also provides "
                "email analysis, QR analysis, password guidance, a "
                "browser-only password generator, authentication, scan "
                "history, and this "
                "security assistant."
            ),
            "category": "phishguard",
        }

    # ---------------------------------
    # FALLBACK
    # ---------------------------------

    return {
        "reply": (
            "I don't have a reliable answer for that question in "
            "my current local knowledge base. I specialize in "
            "phishing, suspicious URLs and emails, QR-code safety, "
            "passwords, OTPs, malware, HTTPS, scams, and account "
            "security."
        ),
        "category": "unknown",
    }


def explain_scan_result(scan_result):
    """
    Explain a PhishGuard URL analysis result.
    """

    if not scan_result:
        return {
            "reply": (
                "I couldn't find a scan result to explain."
            ),
            "category": "scan_explanation",
        }

    prediction = scan_result.get(
        "prediction",
        "Unknown",
    )

    risk_level = scan_result.get(
        "risk_level",
        "Unknown",
    )

    risk_score = scan_result.get(
        "risk_score",
        0,
    )

    confidence = scan_result.get(
        "confidence",
        0,
    )

    reasons = scan_result.get(
        "reasons",
        [],
    )

    ml_result = scan_result.get(
        "ml_result"
    )

    sections = []

    displayed_prediction = (
        "Low Risk Indicators"
        if str(prediction).lower() == "safe"
        else prediction
    )

    sections.append(
        (
            f"PhishGuard classified this URL as {displayed_prediction} "
            f"with a {risk_level} risk level."
        )
    )

    sections.append(
        (
            f"The final hybrid risk score is {risk_score}% "
            f"and the reported confidence is {confidence}%."
        )
    )

    if ml_result:

        phishing_probability = ml_result.get(
            "phishing_probability",
            0,
        )

        safe_probability = ml_result.get(
            "safe_probability",
            0,
        )

        sections.append(
            (
                "The machine-learning model estimated "
                f"{phishing_probability}% phishing probability "
                f"and {safe_probability}% safe probability."
            )
        )

    valid_reasons = []

    for reason in reasons:

        if isinstance(reason, dict):

            reason_message = reason.get(
                "message"
            )

            if reason_message:
                valid_reasons.append(
                    reason_message
                )

        elif isinstance(reason, str):

            valid_reasons.append(
                reason
            )

    if valid_reasons:

        sections.append(
            "Important indicators detected:"
        )

        for reason in valid_reasons[:5]:
            sections.append(
                f"• {reason}"
            )

    if prediction.lower() == "phishing":

        sections.append(
            (
                "Recommended action: Do not enter passwords, "
                "OTPs, payment information, or personal data. "
                "Avoid downloading files from the site and verify "
                "the service using its official website."
            )
        )

    elif prediction.lower() == "suspicious":

        sections.append(
            (
                "Recommended action: Treat the URL cautiously. "
                "Verify the domain and source independently before "
                "entering sensitive information."
            )
        )

    else:

        sections.append(
            (
                "No strong phishing indicators were detected by "
                "this analysis. However, a low-risk result is not a "
                "guarantee that a website is trustworthy."
            )
        )

    return {
        "reply": "\n\n".join(
            sections
        ),
        "category": "scan_explanation",
    }


def get_ai_security_response(
    message,
):
    """
    Use Gemini when available and fall back to
    the local assistant if the API is unavailable.
    """

    try:

        reply = generate_ai_response(
            message=message,
        )

        return {
            "reply": reply,
            "category": "ai",
            "source": "gemini",
        }

    except Exception as error:
        current_app.logger.warning(
            "Gemini assistant unavailable; using local fallback (%s).",
            error.__class__.__name__,
        )

        fallback = get_security_response(
            message
        )

        fallback["source"] = "local"

        return fallback
