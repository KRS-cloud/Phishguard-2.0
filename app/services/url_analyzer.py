from app.ml.url_features import extract_url_features
from app.services.ml_url_predictor import predict_url_with_ml


def add_risk(
    reasons,
    feature_name,
    message,
    score,
):
    """
    Add one risk reason and its score.
    """

    reasons.append(
        {
            "feature": feature_name,
            "message": message,
            "score": score,
        }
    )

    return score


def analyze_url(url):
    """
    Analyze a URL and return its phishing-risk report.
    """

    features = extract_url_features(url)

    risk_score = 0
    reasons = []

    if not features["hostname"]:
        raise ValueError(
            "The submitted URL does not contain a valid domain."
        )

    if not features["uses_https"]:
        risk_score += add_risk(
            reasons,
            "HTTPS",
            "The website does not use an HTTPS connection.",
            12,
        )

    if features["uses_ip_address"]:
        risk_score += add_risk(
            reasons,
            "IP address",
            "The URL uses an IP address instead of a normal domain name.",
            25,
        )

    if features["contains_at_symbol"]:
        risk_score += add_risk(
            reasons,
            "@ symbol",
            "The URL contains an @ symbol, which can hide the real destination.",
            20,
        )

    if features["contains_double_slash_redirect"]:
        risk_score += add_risk(
            reasons,
            "Redirect pattern",
            "The URL path contains a double-slash redirect pattern.",
            10,
        )

    if features["url_length"] > 100:
        risk_score += add_risk(
            reasons,
            "URL length",
            "The URL is unusually long.",
            12,
        )

    elif features["url_length"] > 75:
        risk_score += add_risk(
            reasons,
            "URL length",
            "The URL is longer than normal.",
            7,
        )

    if features["subdomain_count"] >= 4:
        risk_score += add_risk(
            reasons,
            "Subdomains",
            "The domain contains many nested subdomains.",
            18,
        )

    elif features["subdomain_count"] >= 2:
        risk_score += add_risk(
            reasons,
            "Subdomains",
            "The URL contains multiple subdomains.",
            8,
        )

    if features["hyphen_count"] >= 3:
        risk_score += add_risk(
            reasons,
            "Hyphens",
            "The domain contains an unusual number of hyphens.",
            12,
        )

    elif features["hyphen_count"] >= 1:
        risk_score += add_risk(
            reasons,
            "Hyphens",
            "The domain contains hyphens that should be reviewed.",
            4,
        )

    if features["suspicious_word_count"] >= 3:
        words = ", ".join(
            features["suspicious_words"][:5]
        )

        risk_score += add_risk(
            reasons,
            "Suspicious words",
            f"The URL contains several phishing-related words: {words}.",
            20,
        )

    elif features["suspicious_word_count"] >= 1:
        words = ", ".join(
            features["suspicious_words"][:5]
        )

        risk_score += add_risk(
            reasons,
            "Suspicious words",
            f"The URL contains potentially suspicious wording: {words}.",
            7,
        )

    if features["is_shortened_url"]:
        risk_score += add_risk(
            reasons,
            "URL shortener",
            "The URL uses a shortening service that hides its final destination.",
            15,
        )

    if features["suspicious_tld"]:
        risk_score += add_risk(
            reasons,
            "Domain extension",
            "The domain uses an extension frequently associated with disposable or risky websites.",
            14,
        )

    if features["has_punycode"]:
        risk_score += add_risk(
            reasons,
            "Punycode",
            "The domain contains punycode and may imitate another website.",
            22,
        )

    if features["has_encoded_characters"]:
        risk_score += add_risk(
            reasons,
            "Encoded characters",
            "The URL contains encoded characters that may hide its true structure.",
            8,
        )

    if features["digit_ratio"] > 0.30:
        risk_score += add_risk(
            reasons,
            "Numbers",
            "A large portion of the URL is made of numbers.",
            10,
        )

    if features["special_character_count"] >= 8:
        risk_score += add_risk(
            reasons,
            "Special characters",
            "The URL contains many special characters.",
            8,
        )

    if features["has_port"]:
        risk_score += add_risk(
            reasons,
            "Custom port",
            "The URL uses a custom network port.",
            7,
        )

    risk_score = min(
        risk_score,
        100,
    )

    # Attempt machine learning prediction
    ml_result = None
    try:
        ml_result = predict_url_with_ml(
            features["normalized_url"]
        )
    except (
        FileNotFoundError,
        KeyError,
        ValueError,
    ):
        ml_result = None

    rule_risk_score = risk_score

    # Blend ML probability with rule-based score if available
    if ml_result:
        ml_risk_score = ml_result[
            "phishing_probability"
        ]

        risk_score = round(
            (rule_risk_score * 0.60)
            + (ml_risk_score * 0.40),
            2,
        )

    # Classification threshold mapping
    if risk_score >= 60:
        prediction = "Phishing"
        risk_level = "High"
        confidence = min(
            70 + (risk_score * 0.25),
            98,
        )

    elif risk_score >= 30:
        prediction = "Suspicious"
        risk_level = "Medium"
        confidence = min(
            60 + (risk_score * 0.30),
            92,
        )

    else:
        prediction = "Safe"
        risk_level = "Low"
        confidence = max(
            65,
            95 - risk_score,
        )

    if reasons:
        explanation = " ".join(
            reason["message"]
            for reason in reasons
        )

    else:
        explanation = (
            "No major phishing indicators were detected in the URL structure."
        )

    recommendations = build_recommendations(
        prediction,
        features,
    )

    return {
        "input_url": url,
        "normalized_url": features["normalized_url"],
        "prediction": prediction,
        "risk_level": risk_level,
        "risk_score": float(risk_score),
        "rule_risk_score": float(
            rule_risk_score
        ),
        "ml_result": ml_result,
        "analysis_method": (
            "Hybrid ML and rule-based analysis"
            if ml_result
            else "Rule-based analysis"
        ),
        "confidence": round(
            float(confidence),
            2,
        ),
        "explanation": explanation,
        "recommendations": recommendations,
        "reasons": reasons,
        "features": features,
    }


def build_recommendations(
    prediction,
    features,
):
    """
    Create safety recommendations based on the result.
    """

    recommendations = []

    if prediction == "Phishing":
        recommendations.extend(
            [
                "Do not open the website or enter personal information.",
                "Do not download files from this website.",
                "Block or report the link if it was received through email or messaging.",
                "Visit the official website by typing its address manually.",
            ]
        )

    elif prediction == "Suspicious":
        recommendations.extend(
            [
                "Verify the website address before continuing.",
                "Avoid entering passwords, banking details or OTP codes.",
                "Search for the official website independently.",
                "Use another trusted security service for additional verification.",
            ]
        )

    else:
        recommendations.extend(
            [
                "No major structural indicators were found, but remain cautious.",
                "Verify the website content before entering sensitive information.",
                "Confirm that the domain belongs to the expected organization.",
            ]
        )

    if not features["uses_https"]:
        recommendations.append(
            "Avoid submitting sensitive information because the connection does not use HTTPS."
        )

    if features["is_shortened_url"]:
        recommendations.append(
            "Preview the shortened link destination before opening it."
        )

    return recommendations
