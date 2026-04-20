"""
train_model.py
────────────────────────────────────────────────────────────────────────────────
End-to-end training pipeline for the malicious URL detector.

Pipeline steps:
  1. Load every CSV file from  backend/data/raw/
  2. Extract URL features with  feature_extractor.extract_features()
  3. Build a pandas DataFrame from the extracted features
  4. One-hot encode any categorical (string) columns that exist
  5. Split into 80 % train / 20 % test
  6. Train a RandomForestClassifier
  7. Print a classification report and ROC-AUC score
  8. Save the model and feature column names to  backend/models/model_v1.joblib

Usage:
    cd malicious-url-detector
    python backend/src/train_model.py
"""

import os
import sys
import glob

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

# ── Resolve the project root and src directory from this file's location.
# This makes all paths work correctly no matter which directory the user
# runs the script from (project root, backend/src/, etc.).
#
# Directory layout:
#   <PROJECT_ROOT>/
#       backend/
#           src/          <-- this file lives here
#           data/raw/     <-- CSV files
#           models/       <-- saved model

# backend/src/
SRC_DIR = os.path.dirname(os.path.abspath(__file__))

# backend/
BACKEND_DIR = os.path.dirname(SRC_DIR)

# <PROJECT_ROOT>/
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)

# Ensure feature_extractor (in the same src/ folder) is importable.
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from feature_extractor import extract_features  # noqa: E402


# ──────────────────────────────────────────────────────────────────────────────
# Path configuration  (anchored to the script location, not the cwd)
# ──────────────────────────────────────────────────────────────────────────────

# Folder that contains one or more  *.csv  training files.
RAW_DATA_DIR = os.path.join(BACKEND_DIR, "data", "raw")

# Where the trained model artefacts will be saved.
MODEL_DIR  = os.path.join(BACKEND_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "model_v1.joblib")


# ──────────────────────────────────────────────────────────────────────────────
# Step 1 – Load all CSV files from  backend/data/raw/
# ──────────────────────────────────────────────────────────────────────────────

def load_raw_data(raw_dir: str) -> pd.DataFrame:
    """
    Find every  *.csv  file inside *raw_dir*, read them all, and
    concatenate them into a single DataFrame.

    Each CSV must have at least two columns:
      url   – the raw URL string
      label – 1 for malicious, 0 for benign

    Parameters
    ----------
    raw_dir : str
        Path (relative or absolute) to the folder containing the CSV files.

    Returns
    -------
    pd.DataFrame
        Combined DataFrame with columns  [url, label]  (plus any extras).

    Raises
    ------
    FileNotFoundError
        If no CSV files are found in *raw_dir*.
    """
    # Use glob to collect all CSV file paths in the directory.
    pattern   = os.path.join(raw_dir, "*.csv")
    csv_files = glob.glob(pattern)

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in '{raw_dir}'. "
            "Please add at least one file with columns: url, label"
        )

    print(f"[1/5] Found {len(csv_files)} CSV file(s) in '{raw_dir}':")
    frames = []
    for path in csv_files:
        df = pd.read_csv(path)
        print(f"      - {os.path.basename(path)}  ({len(df)} rows)")
        frames.append(df)

    # Stack all files into one DataFrame and reset the index.
    combined = pd.concat(frames, ignore_index=True)

    # Drop rows where either the URL or the label is missing.
    before = len(combined)
    combined.dropna(subset=["url", "label"], inplace=True)
    dropped = before - len(combined)
    if dropped:
        print(f"      WARNING: Dropped {dropped} row(s) with missing url/label.")

    print(f"      Total rows after merge: {len(combined)}\n")
    return combined


# ──────────────────────────────────────────────────────────────────────────────
# Step 2 & 3 – Extract features and build the feature DataFrame
# ──────────────────────────────────────────────────────────────────────────────

def build_feature_matrix(raw_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """
    Apply  extract_features()  to every URL in *raw_df* and return:
      - X : DataFrame of numeric / boolean features  (one row per URL)
      - y : Series of integer labels  (0 = benign, 1 = malicious)

    Parameters
    ----------
    raw_df : pd.DataFrame
        Must contain columns  'url'  and  'label'.

    Returns
    -------
    tuple[pd.DataFrame, pd.Series]
        (feature_matrix, label_series)
    """
    print("[2/5] Extracting features from URLs...")

    feature_rows = []
    failed_count = 0

    for idx, row in raw_df.iterrows():
        url = str(row["url"]).strip()
        try:
            features = extract_features(url)
            feature_rows.append(features)
        except Exception as exc:
            # Skip problematic URLs but warn the user.
            print(f"      WARNING: Skipping row {idx} ('{url[:60]}'): {exc}")
            failed_count += 1
            # Add a None placeholder so indices stay aligned with raw_df.
            feature_rows.append(None)

    # Build the feature DataFrame.
    X = pd.DataFrame(feature_rows)

    # Align the label series to the same rows (drop any that failed).
    y = raw_df["label"].reset_index(drop=True)

    # Remove rows where feature extraction failed (None rows).
    valid_mask = X.notna().all(axis=1)
    X = X[valid_mask].reset_index(drop=True)
    y = y[valid_mask].reset_index(drop=True)

    # Cast label values to integer for sklearn compatibility.
    y = y.astype(int)

    if failed_count:
        print(f"      WARNING: {failed_count} URL(s) skipped due to extraction errors.")

    print(f"      Feature matrix shape: {X.shape}")
    print(f"      Label distribution:\n{y.value_counts().to_string()}\n")
    return X, y


# ──────────────────────────────────────────────────────────────────────────────
# Step 4 – One-hot encode any remaining categorical (string) columns
# ──────────────────────────────────────────────────────────────────────────────

def encode_categoricals(X: pd.DataFrame) -> pd.DataFrame:
    """
    Convert string / object columns to numeric using one-hot encoding.

    Currently  extract_features()  returns only numbers, so this step is
    a safety net – it guarantees the pipeline stays compatible if extra
    string features are added in the future (e.g. the raw TLD string).

    Parameters
    ----------
    X : pd.DataFrame
        Feature matrix, possibly containing object-dtype columns.

    Returns
    -------
    pd.DataFrame
        Fully numeric feature matrix.
    """
    # Identify columns that store Python objects / strings.
    categorical_cols = X.select_dtypes(include=["object"]).columns.tolist()

    if not categorical_cols:
        print("[3/5] No categorical columns found - skipping one-hot encoding.\n")
        return X

    print(f"[3/5] One-hot encoding {len(categorical_cols)} categorical column(s): "
          f"{categorical_cols}")

    # pd.get_dummies converts each unique value in a column into its own
    # binary (0/1) column.  drop_first=True removes the first category to
    # avoid the "dummy variable trap" (perfect multicollinearity).
    X_encoded = pd.get_dummies(X, columns=categorical_cols, drop_first=True)

    print(f"      Feature count after encoding: {X_encoded.shape[1]}\n")
    return X_encoded


# ──────────────────────────────────────────────────────────────────────────────
# Step 5 – Train / test split
# ──────────────────────────────────────────────────────────────────────────────

def split_data(
    X: pd.DataFrame, y: pd.Series, test_size: float = 0.20, random_state: int = 42
) -> tuple:
    """
    Split (X, y) into training and test sets.

    Parameters
    ----------
    X            : feature matrix
    y            : label series
    test_size    : fraction to reserve for testing (default 20 %)
    random_state : seed for reproducibility

    Returns
    -------
    tuple
        (X_train, X_test, y_train, y_test)
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,          # preserve class ratio in both splits
    )

    print(f"[4/5] Train/test split  (test_size={test_size:.0%}, "
          f"random_state={random_state})")
    print(f"      Train rows : {len(X_train)}")
    print(f"      Test  rows : {len(X_test)}\n")

    return X_train, X_test, y_train, y_test


# ──────────────────────────────────────────────────────────────────────────────
# Step 6 & 7 – Train the model and evaluate
# ──────────────────────────────────────────────────────────────────────────────

def train_and_evaluate(
    X_train: pd.DataFrame,
    X_test:  pd.DataFrame,
    y_train: pd.Series,
    y_test:  pd.Series,
    n_estimators: int = 200,
    random_state: int = 42,
    n_jobs: int = 1,
) -> RandomForestClassifier:
    """
    Train a RandomForestClassifier and print evaluation metrics.

    Why RandomForest?
      • Handles mixed numeric / binary features well
      • Robust to outliers and does not require feature scaling
      • Provides feature importances for interpretability
      • Low risk of overfitting compared to a single decision tree

    Parameters
    ----------
    X_train, X_test : feature splits
    y_train, y_test : label splits
    n_estimators    : number of trees in the forest
    random_state    : seed for reproducibility

    Returns
    -------
    RandomForestClassifier
        The fitted model object.
    """
    print(f"[5/5] Training RandomForestClassifier "
          f"(n_estimators={n_estimators}, n_jobs={n_jobs}) …")

    # Initialise the classifier.
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=n_jobs,       # single-process is more reliable on some Windows setups
        class_weight="balanced",  # handle any mild class imbalance
    )

    # Fit on the training data.
    clf.fit(X_train, y_train)
    print("      Training complete.\n")

    # ── Predictions ──────────────────────────────────────────────────────────
    y_pred      = clf.predict(X_test)          # hard 0/1 predictions
    y_pred_prob = clf.predict_proba(X_test)[:, 1]  # probability of class 1

    # ── Classification report (precision, recall, F1 per class) ──────────────
    print("=" * 60)
    print("  Classification Report")
    print("=" * 60)
    print(classification_report(
        y_test, y_pred,
        target_names=["Benign (0)", "Malicious (1)"]
    ))

    # ── ROC-AUC score ─────────────────────────────────────────────────────────
    # AUC = 1.0 is perfect; 0.5 = random guessing.
    auc = roc_auc_score(y_test, y_pred_prob)
    print(f"  ROC-AUC Score : {auc:.4f}")
    print("=" * 60)

    # ── Feature importances (top-10) ─────────────────────────────────────────
    importances = pd.Series(
        clf.feature_importances_, index=X_train.columns
    ).sort_values(ascending=False)

    print("\n  Top-10 Feature Importances:")
    print(importances.head(10).to_string())
    print()

    return clf


# ──────────────────────────────────────────────────────────────────────────────
# Step 8 – Save model and feature column names
# ──────────────────────────────────────────────────────────────────────────────

def save_model(clf: RandomForestClassifier, feature_columns: list, model_path: str):
    """
    Persist the trained model and the ordered list of feature column names
    together in a single  .joblib  file.

    Saving feature_columns alongside the model is critical: when the API
    server receives a new URL, it must build a feature vector in EXACTLY
    the same column order that the model was trained on.

    The saved artefact is a dict:
      {
        "model":    <RandomForestClassifier>,
        "features": ["url_length", "domain_length", ...]
      }

    Parameters
    ----------
    clf             : fitted RandomForestClassifier
    feature_columns : list of column names used during training
    model_path      : destination file path
    """
    # Ensure the models/ directory exists.
    os.makedirs(os.path.dirname(model_path), exist_ok=True)

    artefact = {
        "model":    clf,
        "features": feature_columns,
    }

    joblib.dump(artefact, model_path)
    print(f"\n  [OK] Model saved -> {model_path}")
    print(f"  [OK] Feature columns saved ({len(feature_columns)} features)")


# ──────────────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "=" * 60)
    print("  Malicious URL Detector - Model Training Pipeline")
    print("=" * 60 + "\n")

    # 1. Load raw CSVs.
    raw_df = load_raw_data(RAW_DATA_DIR)

    # 2 & 3. Extract features -> DataFrame.
    X, y = build_feature_matrix(raw_df)

    # 4. One-hot encode any categorical columns.
    X = encode_categoricals(X)

    # 5. Train / test split.
    X_train, X_test, y_train, y_test = split_data(X, y)

    # 6 & 7. Train + evaluate.
    clf = train_and_evaluate(X_train, X_test, y_train, y_test)

    # 8. Save model artefact.
    save_model(clf, list(X.columns), MODEL_PATH)

    print("\n  Pipeline finished successfully.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
