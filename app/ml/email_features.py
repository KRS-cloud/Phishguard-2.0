import re
from urllib.parse import urlparse


URGENT_WORDS = {
    "urgent",
    "immediately",
    "act now",
    "limited time",
    "final warning",
    "last chance",
    "within 24 hours",
    "right now",
    "as soon as possible",
}


THREAT_WORDS = {
    "suspended",
    "blocked",
    "closed",
    "disabled",
    "terminated",
    "legal action",
    "penalty",
    "unauthorized access",
    "security breach",
    "account locked",
}


CREDENTIAL_WORDS = {
    "password",
    "username",
    "login",
    "sign in",
    "verify your account",
    "confirm your identity",
    "security question",
    "credentials",
}


FINANCIAL_WORDS = {
    "bank account",
    "credit card",
    "debit card",
    "payment",
    "invoice",
    "refund",
    "wallet",
    "transaction",
    "billing",
    "money transfer",
}


OTP_WORDS = {
    "otp",
    "one time password",
    "verification code",
    "security code",
    "authentication code",
}


REWARD_WORDS = {
    "winner",
    "won",
    "prize",
    "reward",
    "gift card",
    "lottery",
    "free money",
    "claim now",
    "congratulations",
}


GENERIC_GREETINGS = {
    "dear customer",
    "dear user",
    "dear account holder",
    "valued customer",
    "hello user",
}


SUSPICIOUS_FILE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".zip",
    ".rar",
    ".iso",
}


FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "proton.me",
    "protonmail.com",
}


def find_matching_phrases(text, phrases):
    """
    Return phrases found inside the supplied text.
    """

    lowered_text = text.lower()

    return sorted(
        phrase
        for phrase in phrases
        if phrase in lowered_text
    )


def extract_urls(text):
    """
    Extract HTTP and HTTPS links from email content.
    """

    pattern = r"https?://[^\s<>'\"]+"

    return re.findall(
        pattern,
        text,
        flags=re.IGNORECASE,
    )


def extract_email_features(
    sender_email,
    subject,
    body,
):
    """
    Extract understandable phishing-related email features.
    """

    combined_text = f"{subject}\n{body}".strip()
    lowered_text = combined_text.lower()

    urls = extract_urls(combined_text)

    urgent_words = find_matching_phrases(
        combined_text,
        URGENT_WORDS,
    )

    threat_words = find_matching_phrases(
        combined_text,
        THREAT_WORDS,
    )

    credential_words = find_matching_phrases(
        combined_text,
        CREDENTIAL_WORDS,
    )

    financial_words = find_matching_phrases(
        combined_text,
        FINANCIAL_WORDS,
    )

    otp_words = find_matching_phrases(
        combined_text,
        OTP_WORDS,
    )

    reward_words = find_matching_phrases(
        combined_text,
        REWARD_WORDS,
    )

    generic_greetings = find_matching_phrases(
        combined_text,
        GENERIC_GREETINGS,
    )

    uppercase_letters = sum(
        character.isupper()
        for character in combined_text
    )

    alphabetic_letters = sum(
        character.isalpha()
        for character in combined_text
    )

    uppercase_ratio = (
        uppercase_letters / alphabetic_letters
        if alphabetic_letters
        else 0
    )

    exclamation_count = combined_text.count("!")
    question_count = combined_text.count("?")

    sender_domain = ""

    if "@" in sender_email:
        sender_domain = sender_email.rsplit(
            "@",
            1,
        )[-1].lower()

    suspicious_attachments = sorted(
        extension
        for extension in SUSPICIOUS_FILE_EXTENSIONS
        if extension in lowered_text
    )

    link_domains = []

    for url in urls:
        hostname = urlparse(url).hostname

        if hostname:
            link_domains.append(
                hostname.lower()
            )

    return {
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "subject": subject,
        "body": body,
        "content_length": len(combined_text),
        "urls": urls,
        "url_count": len(urls),
        "link_domains": link_domains,
        "urgent_words": urgent_words,
        "threat_words": threat_words,
        "credential_words": credential_words,
        "financial_words": financial_words,
        "otp_words": otp_words,
        "reward_words": reward_words,
        "generic_greetings": generic_greetings,
        "uppercase_ratio": uppercase_ratio,
        "exclamation_count": exclamation_count,
        "question_count": question_count,
        "suspicious_attachments": suspicious_attachments,
        "uses_free_email_domain": sender_domain in FREE_EMAIL_DOMAINS,
        "contains_html_form": (
            "<form" in lowered_text
            or "<input" in lowered_text
        ),
    }