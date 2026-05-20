"""
model_comparison.py
--------------------------------------------------------------------------------
Train and compare multiple ML models on the current URL-feature dataset, then
write report-ready tables for the FYP 2 final report.

Outputs:
  backend/reports/model_comparison_main.csv
  backend/reports/model_comparison_hard_negative.csv
  backend/reports/deployed_model_threshold_analysis.csv
  backend/reports/model_confusion_matrices.json
  backend/reports/model_comparison_summary.md

Usage:
    python backend/src/model_comparison.py
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SRC_DIR)
REPORT_DIR = os.path.join(BACKEND_DIR, "reports")
HARD_NEGATIVE_PATH = os.path.join(BACKEND_DIR, "data", "raw", "official_hard_negatives.csv")
SELECTED_THRESHOLD = 0.90

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from evaluate_model import build_feature_frame  # noqa: E402
from train_model import (  # noqa: E402
    build_feature_matrix,
    create_random_forest_model,
    encode_categoricals,
    load_raw_data,
    split_data,
)


def ensure_report_dir() -> None:
    os.makedirs(REPORT_DIR, exist_ok=True)


def make_models() -> dict[str, Any]:
    """Return the baseline models used in the FYP 2 comparison."""
    return {
        "Random Forest": create_random_forest_model(),
        "Logistic Regression": Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                ("model", LogisticRegression(max_iter=4000, class_weight="balanced", random_state=42)),
            ]
        ),
        "SVM (RBF)": Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                ("model", SVC(probability=True, class_weight="balanced", kernel="rbf", random_state=42)),
            ]
        ),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42),
    }


def probability_scores(model, X: pd.DataFrame) -> np.ndarray:
    """Return malicious-class probabilities."""
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    raise RuntimeError(f"Model does not expose predict_proba(): {type(model).__name__}")


def benign_false_positive_rate(y_true: pd.Series, y_pred: np.ndarray) -> float:
    benign_mask = y_true == 0
    benign_total = int(benign_mask.sum()) or 1
    false_positives = int(((benign_mask) & (y_pred == 1)).sum())
    return false_positives / benign_total


def evaluate_main_split(model_name: str, model, X_train, X_test, y_train, y_test) -> tuple[dict[str, Any], dict[str, int], Any]:
    """Fit one model and evaluate it on the main hold-out split."""
    fitted = clone(model)
    fitted.fit(X_train, y_train)

    y_pred = fitted.predict(X_test)
    y_prob = probability_scores(fitted, X_test)
    y_pred_threshold = (y_prob >= SELECTED_THRESHOLD).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()

    metrics = {
        "model": model_name,
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision_malicious": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall_malicious": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1_malicious": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_test, y_prob), 4),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "benign_fp_rate_default": round(benign_false_positive_rate(y_test, y_pred), 4),
        "benign_fp_rate_threshold_0_90": round(benign_false_positive_rate(y_test, y_pred_threshold), 4),
        "malicious_recall_threshold_0_90": round(recall_score(y_test, y_pred_threshold, zero_division=0), 4),
    }
    confusion = {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    return metrics, confusion, fitted


def evaluate_hard_negatives(model_name: str, fitted_model, feature_columns: list[str], csv_path: str) -> dict[str, Any]:
    """Evaluate false positives on official hard-negative benign URLs."""
    raw_df = pd.read_csv(csv_path)
    X, y, valid_df = build_feature_frame(raw_df)
    X = X.reindex(columns=feature_columns, fill_value=0)

    y_pred = fitted_model.predict(X)
    y_prob = probability_scores(fitted_model, X)
    y_pred_threshold = (y_prob >= SELECTED_THRESHOLD).astype(int)

    false_positives_default = int(((y == 0) & (y_pred == 1)).sum())
    false_positives_threshold = int(((y == 0) & (y_pred_threshold == 1)).sum())
    benign_total = len(valid_df) or 1

    return {
        "model": model_name,
        "benign_rows": benign_total,
        "false_positive_count_default": false_positives_default,
        "false_positive_rate_default": round(false_positives_default / benign_total, 4),
        "false_positive_count_threshold_0_90": false_positives_threshold,
        "false_positive_rate_threshold_0_90": round(false_positives_threshold / benign_total, 4),
        "max_benign_confidence": round(float(np.max(y_prob)) if len(y_prob) else 0.0, 4),
    }


def build_threshold_table(fitted_model, X_test, y_test, feature_columns: list[str], hard_negative_csv: str) -> pd.DataFrame:
    """Create a threshold sweep table for the deployed Random Forest."""
    hard_raw = pd.read_csv(hard_negative_csv)
    X_hard, y_hard, _ = build_feature_frame(hard_raw)
    X_hard = X_hard.reindex(columns=feature_columns, fill_value=0)

    test_prob = probability_scores(fitted_model, X_test)
    hard_prob = probability_scores(fitted_model, X_hard)

    rows = []
    for threshold in [0.50, 0.60, 0.70, 0.80, 0.85, 0.90, 0.95, 0.99]:
        test_pred = (test_prob >= threshold).astype(int)
        hard_pred = (hard_prob >= threshold).astype(int)

        benign_fp_rate_main = benign_false_positive_rate(y_test, test_pred)
        malicious_recall_main = recall_score(y_test, test_pred, zero_division=0)
        malicious_precision_main = precision_score(y_test, test_pred, zero_division=0)
        hard_negative_fp_rate = benign_false_positive_rate(y_hard, hard_pred)

        rows.append({
            "threshold": threshold,
            "main_benign_fp_rate": round(benign_fp_rate_main, 4),
            "main_malicious_recall": round(malicious_recall_main, 4),
            "main_malicious_precision": round(malicious_precision_main, 4),
            "hard_negative_fp_rate": round(hard_negative_fp_rate, 4),
        })

    return pd.DataFrame(rows)


def markdown_table(df: pd.DataFrame) -> str:
    """Render a small DataFrame as a markdown table without extra dependencies."""
    headers = list(df.columns)
    rows = [[str(value) for value in row] for row in df.itertuples(index=False, name=None)]
    table = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        table.append("| " + " | ".join(row) + " |")
    return "\n".join(table)


def reorder_with_preferred_first(df: pd.DataFrame, preferred_model: str) -> pd.DataFrame:
    """Move the preferred model row to the top for easier reporting."""
    df = df.copy()
    df["_preferred"] = (df["model"] == preferred_model).astype(int)
    df = df.sort_values(by="_preferred", ascending=False).drop(columns="_preferred")
    return df.reset_index(drop=True)


def select_deployed_model(main_df: pd.DataFrame, hard_df: pd.DataFrame) -> str:
    """
    Choose the report recommendation.

    Random Forest remains the deployed default unless another model is clearly
    stronger on both malicious recall and hard-negative false positives.
    """
    rf_main = main_df.loc[main_df["model"] == "Random Forest"].iloc[0]
    rf_hard = hard_df.loc[hard_df["model"] == "Random Forest"].iloc[0]

    for _, row in main_df.iterrows():
        if row["model"] == "Random Forest":
            continue
        hard_row = hard_df.loc[hard_df["model"] == row["model"]].iloc[0]
        clearly_better = (
            hard_row["false_positive_rate_threshold_0_90"] <= rf_hard["false_positive_rate_threshold_0_90"]
            and row["malicious_recall_threshold_0_90"] >= rf_main["malicious_recall_threshold_0_90"] + 0.02
            and row["roc_auc"] >= rf_main["roc_auc"]
        )
        if clearly_better:
            return row["model"]
    return "Random Forest"


def write_summary(main_df: pd.DataFrame, hard_df: pd.DataFrame, threshold_df: pd.DataFrame, deployed_model: str) -> None:
    summary_path = os.path.join(REPORT_DIR, "model_comparison_summary.md")
    threshold_row = threshold_df.loc[threshold_df["threshold"] == SELECTED_THRESHOLD].iloc[0]

    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("# Model Comparison Summary\n\n")
        f.write("## Main Dataset Comparison\n\n")
        f.write(markdown_table(main_df))
        f.write("\n\n## Hard-Negative Benign Comparison\n\n")
        f.write(markdown_table(hard_df))
        f.write(f"\n\n## {deployed_model} Threshold Analysis\n\n")
        f.write(markdown_table(threshold_df))
        f.write("\n\n## Recommendation\n\n")
        f.write(
            f"- Recommended deployed model: **{deployed_model}**.\n"
            f"- Selected extension block threshold: **{SELECTED_THRESHOLD:.2f}**.\n"
            f"- At threshold {SELECTED_THRESHOLD:.2f}, the deployed {deployed_model} model achieved "
            f"{threshold_row['main_malicious_recall']:.2%} malicious recall on the main hold-out split "
            f"while keeping the curated hard-negative benign false-positive rate at "
            f"{threshold_row['hard_negative_fp_rate']:.2%}.\n"
            "- This threshold therefore balances user-facing false-positive reduction with strong detection recall "
            "for the FYP 2 demonstration.\n"
        )


def main() -> None:
    ensure_report_dir()

    raw_df = load_raw_data(os.path.join(BACKEND_DIR, "data", "raw"))
    X, y = build_feature_matrix(raw_df)
    X = encode_categoricals(X)
    X_train, X_test, y_train, y_test = split_data(X, y)
    feature_columns = list(X.columns)

    models = make_models()
    main_rows = []
    hard_rows = []
    confusion_rows = {}
    fitted_models = {}

    for model_name, model in models.items():
        print(f"\n[COMPARE] Training {model_name} ...")
        main_metrics, confusion, fitted = evaluate_main_split(
            model_name, model, X_train, X_test, y_train, y_test
        )
        hard_metrics = evaluate_hard_negatives(model_name, fitted, feature_columns, HARD_NEGATIVE_PATH)
        main_rows.append(main_metrics)
        hard_rows.append(hard_metrics)
        confusion_rows[model_name] = confusion
        fitted_models[model_name] = fitted

    main_df = pd.DataFrame(main_rows).sort_values(
        by=["malicious_recall_threshold_0_90", "roc_auc", "accuracy"],
        ascending=False,
    )
    hard_df = pd.DataFrame(hard_rows).sort_values(
        by=["false_positive_rate_threshold_0_90", "false_positive_rate_default", "max_benign_confidence"],
        ascending=[True, True, True],
    )
    deployed_model = select_deployed_model(main_df, hard_df)
    main_df = reorder_with_preferred_first(main_df, deployed_model)
    hard_df = reorder_with_preferred_first(hard_df, deployed_model)
    threshold_df = build_threshold_table(fitted_models[deployed_model], X_test, y_test, feature_columns, HARD_NEGATIVE_PATH)

    main_df.to_csv(os.path.join(REPORT_DIR, "model_comparison_main.csv"), index=False)
    hard_df.to_csv(os.path.join(REPORT_DIR, "model_comparison_hard_negative.csv"), index=False)
    threshold_df.to_csv(os.path.join(REPORT_DIR, "deployed_model_threshold_analysis.csv"), index=False)

    with open(os.path.join(REPORT_DIR, "model_confusion_matrices.json"), "w", encoding="utf-8") as f:
        json.dump(confusion_rows, f, indent=2)

    write_summary(main_df, hard_df, threshold_df, deployed_model)

    print("\n[OK] Wrote report artifacts to backend/reports/")
    print(f"[OK] Recommended deployed model: {deployed_model}")


if __name__ == "__main__":
    main()
