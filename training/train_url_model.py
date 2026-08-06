from pathlib import Path
import hashlib
import sys

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split


PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from training.feature_builder import (  # noqa: E402
    FEATURE_COLUMNS,
    url_to_feature_row,
)


DATASET_PATH = (
    PROJECT_ROOT
    / "training"
    / "phishing_urls.csv"
)

MODEL_DIRECTORY = (
    PROJECT_ROOT
    / "trained_models"
)

MODEL_PATH = (
    MODEL_DIRECTORY
    / "url_phishing_model.joblib"
)

MODEL_HASH_PATH = MODEL_PATH.with_suffix(".sha256")


def load_dataset():
    """
    Read and validate the URL dataset.
    """

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    dataset = pd.read_csv(
        DATASET_PATH
    )

    required_columns = {
        "url",
        "label",
    }

    if not required_columns.issubset(
        dataset.columns
    ):
        raise ValueError(
            "Dataset must contain url and label columns."
        )

    dataset = dataset.dropna(
        subset=[
            "url",
            "label",
        ]
    )

    dataset["url"] = dataset["url"].astype(
        str
    )

    dataset["label"] = dataset["label"].astype(
        int
    )

    return dataset


def build_feature_dataframe(urls):
    """
    Convert every URL into numeric ML features.
    """

    feature_rows = [
        url_to_feature_row(url)
        for url in urls
    ]

    return pd.DataFrame(
        feature_rows,
        columns=FEATURE_COLUMNS,
    )


def train_model():
    """
    Train, evaluate, and save the phishing model.
    """

    dataset = load_dataset()

    print(
        f"Loaded {len(dataset)} URLs."
    )

    print(
        "\nClass distribution:"
    )

    print(
        dataset["label"].value_counts()
    )

    features = build_feature_dataframe(
        dataset["url"]
    )

    labels = dataset["label"]

    (
        x_train,
        x_test,
        y_train,
        y_test,
    ) = train_test_split(
        features,
        labels,
        test_size=0.25,
        random_state=42,
        stratify=labels,
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=42,
    )

    model.fit(
        x_train,
        y_train,
    )

    predictions = model.predict(
        x_test
    )

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    print(
        f"\nAccuracy: {accuracy:.2%}"
    )

    print(
        "\nConfusion Matrix:"
    )

    print(
        confusion_matrix(
            y_test,
            predictions,
        )
    )

    print(
        "\nClassification Report:"
    )

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Safe",
                "Phishing",
            ],
            zero_division=0,
        )
    )

    feature_importance = pd.DataFrame(
        {
            "feature": FEATURE_COLUMNS,
            "importance": model.feature_importances_,
        }
    ).sort_values(
        "importance",
        ascending=False,
    )

    print(
        "\nFeature Importance:"
    )

    print(
        feature_importance.to_string(
            index=False
        )
    )

    MODEL_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    model_package = {
        "model": model,
        "feature_columns": FEATURE_COLUMNS,
        "model_name": "Random Forest URL Classifier",
        "version": "1.0",
    }

    joblib.dump(
        model_package,
        MODEL_PATH,
    )

    digest = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    MODEL_HASH_PATH.write_text(
        f"{digest}\n",
        encoding="utf-8",
    )

    print(
        f"\nModel saved successfully:\n{MODEL_PATH}"
    )


if __name__ == "__main__":
    train_model()
