import ipaddress
import re
from urllib.parse import urlparse


SUSPICIOUS_WORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "banking",
    "wallet",
    "payment",
    "invoice",
    "recover",
    "unlock",
    "suspended",
    "security",
    "support",
    "authenticate",
    "credential",
}


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
}


SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "work",
    "support",
    "live",
    "buzz",
    "rest",
    "fit",
    "cam",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
}


def normalize_url(url):
    """
    Add a scheme when the user enters only a domain name.
    """

    cleaned_url = url.strip()

    if not cleaned_url:
        return ""

    if not cleaned_url.startswith(("http://", "https://")):
        cleaned_url = f"https://{cleaned_url}"

    return cleaned_url


def is_ip_address(hostname):
    """
    Check whether the hostname is an IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def extract_url_features(url):
    """
    Extract understandable phishing-related URL features.
    """

    normalized_url = normalize_url(url)
    parsed_url = urlparse(normalized_url)

    hostname = parsed_url.hostname or ""
    hostname = hostname.lower()

    path = parsed_url.path.lower()
    query = parsed_url.query.lower()
    complete_text = f"{hostname}{path}{query}"

    hostname_parts = [
        part
        for part in hostname.split(".")
        if part
    ]

    subdomain_count = max(
        len(hostname_parts) - 2,
        0,
    )

    domain_extension = ""

    if hostname_parts:
        domain_extension = hostname_parts[-1]

    suspicious_words_found = sorted(
        word
        for word in SUSPICIOUS_WORDS
        if word in complete_text
    )

    special_character_count = sum(
        normalized_url.count(character)
        for character in ["@", "-", "_", "=", "%", "&"]
    )

    digit_count = sum(
        character.isdigit()
        for character in normalized_url
    )

    digit_ratio = (
        digit_count / len(normalized_url)
        if normalized_url
        else 0
    )

    return {
        "normalized_url": normalized_url,
        "scheme": parsed_url.scheme.lower(),
        "hostname": hostname,
        "path": parsed_url.path,
        "query": parsed_url.query,
        "url_length": len(normalized_url),
        "hostname_length": len(hostname),
        "uses_https": parsed_url.scheme.lower() == "https",
        "uses_ip_address": is_ip_address(hostname),
        "contains_at_symbol": "@" in normalized_url,
        "contains_double_slash_redirect": "//" in parsed_url.path,
        "subdomain_count": subdomain_count,
        "hyphen_count": hostname.count("-"),
        "dot_count": hostname.count("."),
        "special_character_count": special_character_count,
        "digit_ratio": digit_ratio,
        "suspicious_words": suspicious_words_found,
        "suspicious_word_count": len(suspicious_words_found),
        "is_shortened_url": hostname in SHORTENER_DOMAINS,
        "suspicious_tld": domain_extension in SUSPICIOUS_TLDS,
        "has_punycode": "xn--" in hostname,
        "has_port": parsed_url.port is not None,
        "has_encoded_characters": bool(
            re.search(r"%[0-9a-fA-F]{2}", normalized_url)
        ),
    }