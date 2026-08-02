from pathlib import Path

import joblib
import pandas as pd

from training.feature_builder import url_to_feature_row


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

MODEL_PATH = (
    PROJECT_ROOT
    / "trained_models"
    / "url_phishing_model.joblib"
)

_model_package = None


def load_model():
    """
    Load the trained phishing model.

    The model is cached after the first load so it is not
    loaded from disk for every URL scan.
    """

    global _model_package

    if _model_package is not None:
        return _model_package

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "The trained URL phishing model was not found. "
            "Run: python training/train_url_model.py"
        )

    _model_package = joblib.load(MODEL_PATH)

    required_keys = {
        "model",
        "feature_columns",
    }

    if not required_keys.issubset(_model_package):
        raise ValueError(
            "The saved model package is invalid or incomplete."
        )

    return _model_package


def predict_url_with_ml(url):
    """
    Predict whether a URL contains phishing characteristics.
    """

    if not isinstance(url, str) or not url.strip():
        raise ValueError(
            "A valid URL is required for ML prediction."
        )

    model_package = load_model()

    model = model_package["model"]
    feature_columns = model_package["feature_columns"]

    feature_row = url_to_feature_row(url.strip())

    feature_frame = pd.DataFrame(
        [feature_row],
        columns=feature_columns,
    )

    predicted_label = int(
        model.predict(feature_frame)[0]
    )

    probabilities = model.predict_proba(
        feature_frame
    )[0]

    class_probabilities = {
        int(class_label): float(probability)
        for class_label, probability in zip(
            model.classes_,
            probabilities,
        )
    }

    safe_probability = (
        class_probabilities.get(0, 0.0) * 100
    )

    phishing_probability = (
        class_probabilities.get(1, 0.0) * 100
    )

    return {
        "label": predicted_label,
        "prediction": (
            "Phishing"
            if predicted_label == 1
            else "Safe"
        ),
        "safe_probability": round(
            safe_probability,
            2,
        ),
        "phishing_probability": round(
            phishing_probability,
            2,
        ),
        "model_name": model_package.get(
            "model_name",
            "Random Forest URL Classifier",
        ),
        "model_version": model_package.get(
            "version",
            "1.0",
        ),
    }