from app.ml.url_features import extract_url_features


FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "uses_https",
    "uses_ip_address",
    "contains_at_symbol",
    "contains_double_slash_redirect",
    "subdomain_count",
    "hyphen_count",
    "dot_count",
    "special_character_count",
    "digit_ratio",
    "suspicious_word_count",
    "is_shortened_url",
    "suspicious_tld",
    "has_punycode",
    "has_port",
    "has_encoded_characters",
]


def url_to_feature_row(url):
    """
    Convert one URL into a numeric ML feature row.
    """

    features = extract_url_features(url)

    return {
        "url_length": features["url_length"],
        "hostname_length": features["hostname_length"],
        "uses_https": int(features["uses_https"]),
        "uses_ip_address": int(features["uses_ip_address"]),
        "contains_at_symbol": int(
            features["contains_at_symbol"]
        ),
        "contains_double_slash_redirect": int(
            features["contains_double_slash_redirect"]
        ),
        "subdomain_count": features["subdomain_count"],
        "hyphen_count": features["hyphen_count"],
        "dot_count": features["dot_count"],
        "special_character_count": features[
            "special_character_count"
        ],
        "digit_ratio": features["digit_ratio"],
        "suspicious_word_count": features[
            "suspicious_word_count"
        ],
        "is_shortened_url": int(
            features["is_shortened_url"]
        ),
        "suspicious_tld": int(
            features["suspicious_tld"]
        ),
        "has_punycode": int(
            features["has_punycode"]
        ),
        "has_port": int(
            features["has_port"]
        ),
        "has_encoded_characters": int(
            features["has_encoded_characters"]
        ),
    }