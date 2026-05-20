"""
train_model.py
--------------------------------------------------------------------------------
Train the currently selected deployment model for the malicious URL detector.

Workflow:
  1. Load every labeled CSV from backend/data/raw/
  2. Extract URL features
  3. Build a numeric feature matrix
  4. Split into train/test sets for honest evaluation
  5. Train and evaluate the selected deployed model
  6. Refit that model on the full dataset for deployment
  7. Save the deployed model artifact to backend/models/model_v1.joblib
"""

import glob
import os
import sys

import joblib
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split


SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SRC_DIR)
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from feature_extractor import extract_features  # noqa: E402


RAW_DATA_DIR = os.path.join(BACKEND_DIR, "data", "raw")
MODEL_DIR = os.path.join(BACKEND_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "model_v1.joblib")

DEPLOYED_MODEL_NAME = "Gradient Boosting"


def load_raw_data(raw_dir: str) -> pd.DataFrame:
    """Load and concatenate all CSV files from the raw data directory."""
    pattern = os.path.join(raw_dir, "*.csv")
    csv_files = glob.glob(pattern)

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in '{raw_dir}'. "
            "Please add at least one file with columns: url, label"
        )

    print(f"[1/6] Found {len(csv_files)} CSV file(s) in '{raw_dir}':")
    frames = []
    for path in csv_files:
        df = pd.read_csv(path)
        print(f"      - {os.path.basename(path)}  ({len(df)} rows)")
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)

    before = len(combined)
    combined.dropna(subset=["url", "label"], inplace=True)
    dropped = before - len(combined)
    if dropped:
        print(f"      WARNING: Dropped {dropped} row(s) with missing url/label.")

    print(f"      Total rows after merge: {len(combined)}\n")
    return combined


def build_feature_matrix(raw_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Extract feature rows for each URL and return X, y."""
    print("[2/6] Extracting features from URLs...")

    feature_rows = []
    failed_count = 0

    for idx, row in raw_df.iterrows():
        url = str(row["url"]).strip()
        try:
            feature_rows.append(extract_features(url))
        except Exception as exc:
            print(f"      WARNING: Skipping row {idx} ('{url[:60]}'): {exc}")
            feature_rows.append(None)
            failed_count += 1

    X = pd.DataFrame(feature_rows)
    y = raw_df["label"].reset_index(drop=True)

    valid_mask = X.notna().all(axis=1)
    X = X[valid_mask].reset_index(drop=True)
    y = y[valid_mask].reset_index(drop=True).astype(int)

    if failed_count:
        print(f"      WARNING: {failed_count} URL(s) skipped due to extraction errors.")

    print(f"      Feature matrix shape: {X.shape}")
    print(f"      Label distribution:\n{y.value_counts().to_string()}\n")
    return X, y


def encode_categoricals(X: pd.DataFrame) -> pd.DataFrame:
    """One-hot encode any object columns if they ever appear."""
    categorical_cols = X.select_dtypes(include=["object"]).columns.tolist()
    if not categorical_cols:
        print("[3/6] No categorical columns found - skipping one-hot encoding.\n")
        return X

    print(f"[3/6] One-hot encoding {len(categorical_cols)} categorical column(s): {categorical_cols}")
    X_encoded = pd.get_dummies(X, columns=categorical_cols, drop_first=True)
    print(f"      Feature count after encoding: {X_encoded.shape[1]}\n")
    return X_encoded


def split_data(
    X: pd.DataFrame,
    y: pd.Series,
    test_size: float = 0.20,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """Split into train and test sets with stratification."""
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    print(f"[4/6] Train/test split (test_size={test_size:.0%}, random_state={random_state})")
    print(f"      Train rows : {len(X_train)}")
    print(f"      Test  rows : {len(X_test)}\n")
    return X_train, X_test, y_train, y_test


def create_random_forest_model(
    n_estimators: int = 200,
    random_state: int = 42,
    n_jobs: int = 1,
) -> RandomForestClassifier:
    """Create the Random Forest baseline used in comparisons."""
    return RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=n_jobs,
        class_weight="balanced",
    )


def create_gradient_boosting_model(random_state: int = 42) -> GradientBoostingClassifier:
    """Create the selected deployed Gradient Boosting model."""
    return GradientBoostingClassifier(random_state=random_state)


def create_deployed_model() -> GradientBoostingClassifier:
    """Return the currently selected deployment model."""
    return create_gradient_boosting_model()


def train_and_evaluate(
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_train: pd.Series,
    y_test: pd.Series,
) -> GradientBoostingClassifier:
    """Train and evaluate the deployed model on the hold-out split."""
    print(f"[5/6] Training {DEPLOYED_MODEL_NAME} ...")

    clf = create_deployed_model()
    clf.fit(X_train, y_train)
    print("      Training complete.\n")

    y_pred = clf.predict(X_test)
    y_pred_prob = clf.predict_proba(X_test)[:, 1]

    print("=" * 60)
    print("  Classification Report")
    print("=" * 60)
    print(classification_report(y_test, y_pred, target_names=["Benign (0)", "Malicious (1)"], zero_division=0))

    auc = roc_auc_score(y_test, y_pred_prob)
    print(f"  ROC-AUC Score : {auc:.4f}")
    print("=" * 60)

    if hasattr(clf, "feature_importances_"):
        importances = pd.Series(clf.feature_importances_, index=X_train.columns).sort_values(ascending=False)
        print("\n  Top-10 Feature Importances:")
        print(importances.head(10).to_string())
        print()

    return clf


def fit_final_model(X: pd.DataFrame, y: pd.Series, base_model):
    """Refit the deployed model on the full dataset after hold-out evaluation."""
    print(f"[6/6] Re-fitting final {DEPLOYED_MODEL_NAME} model on the full dataset ...")
    final_clf = clone(base_model)
    final_clf.fit(X, y)
    print("      Final fit complete.\n")
    return final_clf


def save_model(clf, feature_columns: list[str], model_path: str) -> None:
    """Persist the deployed model and feature ordering together."""
    os.makedirs(os.path.dirname(model_path), exist_ok=True)

    artefact = {
        "model": clf,
        "features": feature_columns,
        "model_name": DEPLOYED_MODEL_NAME,
    }

    joblib.dump(artefact, model_path)
    print(f"  [OK] Model saved -> {model_path}")
    print(f"  [OK] Model name saved -> {DEPLOYED_MODEL_NAME}")
    print(f"  [OK] Feature columns saved ({len(feature_columns)} features)")


def main() -> None:
    print("\n" + "=" * 60)
    print("  Malicious URL Detector - Training Pipeline")
    print("=" * 60 + "\n")

    raw_df = load_raw_data(RAW_DATA_DIR)
    X, y = build_feature_matrix(raw_df)
    X = encode_categoricals(X)
    X_train, X_test, y_train, y_test = split_data(X, y)

    clf = train_and_evaluate(X_train, X_test, y_train, y_test)
    final_clf = fit_final_model(X, y, clf)
    save_model(final_clf, list(X.columns), MODEL_PATH)

    print("\n  Pipeline finished successfully.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
