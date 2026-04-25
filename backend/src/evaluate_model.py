"""
evaluate_model.py
------------------------------------------------------------
Evaluate the saved malicious URL model on labeled CSV files with a focus on
false positives, especially on legitimate but "phishy-looking" benign URLs.

Usage:
    python backend/src/evaluate_model.py
    python backend/src/evaluate_model.py --csv backend/data/raw/official_hard_negatives.csv
    python backend/src/evaluate_model.py --threshold 0.95
"""

import argparse
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SRC_DIR)
RAW_DATA_DIR = os.path.join(BACKEND_DIR, "data", "raw")
MODEL_PATH = os.path.join(BACKEND_DIR, "models", "model_v1.joblib")
DEFAULT_FALSE_POSITIVE_PATH = os.path.join(RAW_DATA_DIR, "official_hard_negatives.csv")

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from feature_extractor import extract_features  # noqa: E402


def load_model(model_path: str) -> tuple:
    """Load the trained model and its feature ordering."""
    artefact = joblib.load(model_path)
    clf = artefact["model"]
    if hasattr(clf, "n_jobs"):
        clf.n_jobs = 1
    return clf, artefact["features"]


def build_feature_frame(raw_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series, pd.DataFrame]:
    """Extract features while preserving the successfully processed rows."""
    feature_rows = []
    valid_rows = []

    for _, row in raw_df.iterrows():
        url = str(row["url"]).strip()
        label = int(row["label"])
        try:
            feature_rows.append(extract_features(url))
            valid_rows.append({"url": url, "label": label})
        except Exception as exc:
            print(f"WARNING: Skipping '{url[:80]}' due to extraction error: {exc}")

    valid_df = pd.DataFrame(valid_rows)
    X = pd.DataFrame(feature_rows)
    y = valid_df["label"].astype(int)
    return X, y, valid_df


def evaluate_csv(csv_path: str, clf, feature_columns: list[str], threshold: float, top_n: int) -> None:
    """Evaluate one labeled CSV file and print false-positive focused metrics."""
    raw_df = pd.read_csv(csv_path)
    if not {"url", "label"}.issubset(raw_df.columns):
        raise ValueError(f"CSV must contain 'url' and 'label': {csv_path}")

    X, y, valid_df = build_feature_frame(raw_df)
    X = X.reindex(columns=feature_columns, fill_value=0)

    prob_malicious = clf.predict_proba(X)[:, 1]
    pred_default = clf.predict(X).astype(int)
    pred_threshold = (prob_malicious >= threshold).astype(int)

    results = valid_df.copy()
    results["pred_default"] = pred_default
    results["pred_threshold"] = pred_threshold
    results["confidence"] = np.round(prob_malicious, 4)

    print("\n" + "=" * 72)
    print(f"Evaluation file: {csv_path}")
    print("=" * 72)
    print(f"Rows evaluated: {len(results)}")
    print(f"Benign rows: {(results['label'] == 0).sum()}")
    print(f"Malicious rows: {(results['label'] == 1).sum()}")

    print("\nDefault classifier output:")
    print(
        classification_report(
            y,
            pred_default,
            labels=[0, 1],
            target_names=["Benign (0)", "Malicious (1)"],
            zero_division=0,
        )
    )
    print("Confusion matrix [rows=true, cols=pred]:")
    print(confusion_matrix(y, pred_default, labels=[0, 1]))

    if y.nunique() > 1:
        auc = roc_auc_score(y, prob_malicious)
        print(f"ROC-AUC: {auc:.4f}")

    benign_mask = results["label"] == 0
    false_positives_default = results[benign_mask & (results["pred_default"] == 1)]
    false_positives_threshold = results[benign_mask & (results["pred_threshold"] == 1)]

    benign_total = int(benign_mask.sum()) or 1
    print("\nFalse-positive focus:")
    print(
        f"Default threshold false positives: {len(false_positives_default)}/{benign_total} "
        f"({len(false_positives_default) / benign_total:.2%})"
    )
    print(
        f"Custom threshold ({threshold:.2f}) false positives: {len(false_positives_threshold)}/{benign_total} "
        f"({len(false_positives_threshold) / benign_total:.2%})"
    )

    print("\nThreshold sweep:")
    for sweep_threshold in [0.50, 0.70, 0.80, 0.90, 0.95, 0.99]:
        sweep_pred = (prob_malicious >= sweep_threshold).astype(int)
        fp = ((y == 0) & (sweep_pred == 1)).sum()
        tp = ((y == 1) & (sweep_pred == 1)).sum()
        positives = int((y == 1).sum()) or 1
        print(
            f"  threshold={sweep_threshold:.2f}  "
            f"benign_fp_rate={fp / benign_total:.2%}  malicious_recall={tp / positives:.2%}"
        )

    if len(false_positives_default):
        print(f"\nTop {min(top_n, len(false_positives_default))} default-threshold false positives:")
        top_false_positives = false_positives_default.sort_values("confidence", ascending=False).head(top_n)
        for _, row in top_false_positives.iterrows():
            print(f"  conf={row['confidence']:.4f}  {row['url']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate the saved URL classifier.")
    parser.add_argument(
        "--csv",
        action="append",
        help="Path to a labeled CSV file. Repeat for multiple files. Defaults to the hard-negative benign set.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.95,
        help="Custom malicious-confidence threshold to evaluate in addition to the model default.",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="How many top false positives to print.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    csv_paths = args.csv or [DEFAULT_FALSE_POSITIVE_PATH]

    clf, feature_columns = load_model(MODEL_PATH)
    for csv_path in csv_paths:
        evaluate_csv(csv_path, clf, feature_columns, args.threshold, args.top_n)


if __name__ == "__main__":
    main()
