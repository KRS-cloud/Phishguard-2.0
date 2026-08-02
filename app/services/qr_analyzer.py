import re

import cv2
import numpy as np

from app.services.url_analyzer import analyze_url


ALLOWED_IMAGE_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "webp",
}


def get_file_extension(filename):
    """
    Return a lowercase filename extension.
    """

    if "." not in filename:
        return ""

    return filename.rsplit(
        ".",
        1,
    )[-1].lower()


def is_allowed_image(filename):
    """
    Check whether the uploaded filename has an allowed extension.
    """

    extension = get_file_extension(filename)

    return extension in ALLOWED_IMAGE_EXTENSIONS


def looks_like_url(value):
    """
    Determine whether decoded QR content appears to be a URL.
    """

    cleaned_value = value.strip()

    url_pattern = re.compile(
        r"^(https?://|www\.)",
        re.IGNORECASE,
    )

    domain_pattern = re.compile(
        r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        r"([/:?#][^\s]*)?$"
    )

    return bool(
        url_pattern.match(cleaned_value)
        or domain_pattern.match(cleaned_value)
    )


def decode_qr_image(file_bytes):
    """
    Decode QR content from uploaded image bytes.
    """

    if not file_bytes:
        raise ValueError(
            "The uploaded image is empty."
        )

    image_array = np.frombuffer(
        file_bytes,
        dtype=np.uint8,
    )

    image = cv2.imdecode(
        image_array,
        cv2.IMREAD_COLOR,
    )

    if image is None:
        raise ValueError(
            "The uploaded file could not be read as an image."
        )

    height, width = image.shape[:2]

    if width < 80 or height < 80:
        raise ValueError(
            "The image is too small. Upload a clearer QR-code image."
        )

    detector = cv2.QRCodeDetector()

    decoded_text, points, _ = detector.detectAndDecode(
        image
    )

    decoded_text = decoded_text.strip()

    if not decoded_text:
        decoded_text = try_improved_decoding(
            detector,
            image,
        )

    if not decoded_text:
        raise ValueError(
            "No readable QR code was found. Try a clearer, larger, or less-blurry image."
        )

    return {
        "decoded_text": decoded_text,
        "image_width": width,
        "image_height": height,
        "qr_detected": points is not None,
    }


def try_improved_decoding(
    detector,
    image,
):
    """
    Retry decoding after basic image improvements.
    """

    grayscale = cv2.cvtColor(
        image,
        cv2.COLOR_BGR2GRAY,
    )

    decoding_attempts = [
        grayscale,
        cv2.resize(
            grayscale,
            None,
            fx=2,
            fy=2,
            interpolation=cv2.INTER_CUBIC,
        ),
        cv2.threshold(
            grayscale,
            0,
            255,
            cv2.THRESH_BINARY + cv2.THRESH_OTSU,
        )[1],
    ]

    for processed_image in decoding_attempts:
        decoded_text, _, _ = detector.detectAndDecode(
            processed_image
        )

        decoded_text = decoded_text.strip()

        if decoded_text:
            return decoded_text

    return ""


def analyze_qr_code(file_bytes):
    """
    Decode a QR image and analyze its content.
    """

    decoded_result = decode_qr_image(
        file_bytes
    )

    decoded_text = decoded_result["decoded_text"]

    if looks_like_url(decoded_text):
        url_result = analyze_url(
            decoded_text
        )

        return {
            "content_type": "URL",
            "decoded_text": decoded_text,
            "prediction": url_result["prediction"],
            "risk_level": url_result["risk_level"],
            "risk_score": url_result["risk_score"],
            "confidence": url_result["confidence"],
            "explanation": url_result["explanation"],
            "recommendations": url_result["recommendations"],
            "reasons": url_result["reasons"],
            "url_result": url_result,
            "image_width": decoded_result["image_width"],
            "image_height": decoded_result["image_height"],
        }

    recommendations = [
        "Review the decoded text before following any instructions.",
        "Do not share passwords, OTP codes, or banking details.",
        "Do not copy unknown commands into a terminal or browser.",
        "Verify unexpected contact information independently.",
    ]

    return {
        "content_type": "Text",
        "decoded_text": decoded_text,
        "prediction": "Safe",
        "risk_level": "Low",
        "risk_score": 0.0,
        "confidence": 70.0,
        "explanation": (
            "The QR code contains plain text rather than a website URL. "
            "No URL phishing analysis was required."
        ),
        "recommendations": recommendations,
        "reasons": [],
        "url_result": None,
        "image_width": decoded_result["image_width"],
        "image_height": decoded_result["image_height"],
    }