# Machine Learning Based Malicious Website Detection and Response System

A local phishing and suspicious-URL detection prototype consisting of:

- A **Python backend** that extracts lexical, trust-aware, and brand-mismatch URL features and classifies URLs with a trained Gradient Boosting model served via FastAPI.
- A **Chrome extension** (Manifest V3) that checks every top-level navigation against the local backend, applies lightweight DOM-signal heuristics after the page loads, and warns or blocks suspicious destinations.

---

## Project Structure

```text
malicious-url-detector/
├─ backend/
│  ├─ data/
│  │  ├─ evaluation/   # held-out evaluation sets (excluded from training)
│  │  ├─ external/     # downloaded source feeds and dataset manifest
│  │  ├─ raw/          # model-ready CSV files used for training
│  │  └─ updates/      # drop new CSVs here for auto-retraining via updater.py
│  ├─ logs/            # SQLite prediction log (events.db)
│  ├─ models/          # trained model artifact (model_v1.joblib)
│  ├─ reports/         # model comparison and threshold analysis artifacts
│  └─ src/
│     ├─ api_server.py          # FastAPI application
│     ├─ feature_extractor.py   # URL feature extraction
│     ├─ logger_db.py           # SQLite prediction logger
│     ├─ reputation_checker.py  # optional VirusTotal integration
│     ├─ train_model.py         # model training script
│     ├─ evaluate_model.py      # false-positive evaluation script
│     ├─ model_comparison.py    # baseline model comparison script
│     └─ updater.py             # file-watcher auto-retraining script
├─ extension/
│  ├─ background.js      # service worker: navigation interception and risk logic
│  ├─ dom_inspector.js   # content script: DOM signal collection after page load
│  ├─ blocked.html / .js # built-in high-risk warning/block page
│  ├─ popup.html / .js   # extension toolbar popup
│  └─ manifest.json      # Manifest V3 extension descriptor
├─ tests/
│  ├─ test_api_server.py        # API response and risk-level behavior tests
│  ├─ test_feature_extractor.py # feature extraction unit tests
│  └─ test_reputation_checker.py
├─ tools/                # helper and report-generation scripts
├─ requirements.txt
└─ README.md
```

---

## How It Works

1. The Chrome extension intercepts every top-level page navigation.
2. It sends the target URL to the local FastAPI backend at `http://127.0.0.1:8000/predict`.
3. The backend extracts 22 numerical URL features and runs the trained Gradient Boosting classifier.
4. After the page loads, the extension's content script (`dom_inspector.js`) collects lightweight DOM signals — password fields, hidden iframes, external script count, suspicious page text, and brand/domain mismatch cues — and sends them to the backend for a second-pass confidence adjustment.
5. The backend returns a `prediction`, `confidence` score, `risk_level`, and short `reasons` list.
6. The extension acts on the risk level:
   - **`low`** — allow normally.
   - **`medium`** — show a caution notification.
   - **`high`** — redirect the tab to the built-in warning page and block by default.
7. Every prediction event is logged to a local SQLite database (`backend/logs/events.db`).

---

## Requirements

| Dependency | Version |
|---|---|
| Python | 3.12 |
| fastapi | 0.115.6 |
| uvicorn[standard] | 0.32.1 |
| scikit-learn | 1.5.2 |
| pandas | 2.2.3 |
| numpy | 2.1.3 |
| joblib | 1.4.2 |
| tldextract | 5.1.3 |
| watchdog | 6.0.0 |
| sqlalchemy | 2.0.36 |

Browser: Google Chrome or any Chromium browser that supports Manifest V3 extensions.

---

## Setup

From the project root:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## Train the Model

The training script reads every CSV under `backend/data/raw/`. Each CSV must contain:

| Column | Description |
|---|---|
| `url` | The raw URL string |
| `label` | `0` = benign, `1` = malicious |

> **Note**: Only training-time benign examples should be placed in `backend/data/raw/`. Held-out evaluation data lives separately under `backend/data/evaluation/` and is never used for training.

Run training with:

```powershell
python backend\src\train_model.py
```

This will:

1. Load all CSVs from `backend/data/raw/`
2. Extract 22 URL features (lexical, structural, trust-aware, and brand/domain consistency signals)
3. Split data into train/test sets and print hold-out evaluation metrics
4. Refit the deployed model on the full dataset
5. Save the trained artifact to `backend/models/model_v1.joblib`

---

## Run the Backend API

```powershell
uvicorn backend.src.api_server:app --reload
```

The API is available at:

- `http://127.0.0.1:8000/` — health check (returns model name, feature count, and reputation status)
- `http://127.0.0.1:8000/docs` — interactive Swagger UI
- `http://127.0.0.1:8000/predict` — `POST` endpoint for URL classification

### API Schema

**Request** (`POST /predict`):

```json
{
  "url": "http://example.com",
  "dom_signals": {
    "form_count": 0,
    "password_field_count": 0,
    "hidden_iframe_count": 0,
    "external_script_count": 0,
    "suspicious_text_hit_count": 0,
    "page_brand_mismatch": 0
  }
}
```

`dom_signals` is optional. When omitted, all DOM signal values default to `0`.

**Response**:

```json
{
  "prediction": 1,
  "confidence": 0.9312,
  "risk_level": "high",
  "reasons": [
    "The URL mentions a trusted brand on a non-brand domain.",
    "The domain uses a higher-risk top-level domain.",
    "The combined risk score is high enough to justify blocking."
  ],
  "reputation": { "..." : "..." }
}
```

| Field | Type | Description |
|---|---|---|
| `prediction` | `int` | `0` = benign, `1` = malicious |
| `confidence` | `float` | Combined risk score in `[0, 1]`, after DOM signal adjustment |
| `risk_level` | `str` | `"low"`, `"medium"`, or `"high"` |
| `reasons` | `list[str]` | Up to 4 short explanation bullets |
| `reputation` | `dict` | VirusTotal result if enabled, otherwise `null` |

---

## Optional: VirusTotal Reputation Check

The backend can query VirusTotal as a second opinion for medium- and high-risk local predictions. This feature is **disabled by default**.

To enable it, set the API key before starting the backend:

```powershell
$env:VIRUSTOTAL_API_KEY="your_api_key_here"
uvicorn backend.src.api_server:app --reload
```

- Reputation lookup is only triggered when the local classifier already considers a URL suspicious (medium or high risk), to protect privacy and respect rate limits.
- Results are cached in `backend/logs/reputation_cache.db` to avoid duplicate queries.
- The implementation checks existing VirusTotal URL reports; it does **not** submit every visited URL for new scans.

---

## Load the Chrome Extension

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `extension` folder in this project
5. Ensure the backend is running before browsing

---

## Typical Local Workflow

```powershell
# 1. Activate the virtual environment
.venv\Scripts\Activate.ps1

# 2. Train the model (first time, or after adding new data)
python backend\src\train_model.py

# 3. Start the API server
uvicorn backend.src.api_server:app --reload
```

Then load the unpacked extension in Chrome and browse normally.

---

## Warning and Caution Behavior

The current extension uses three severity bands:

| Risk Level | Action |
|---|---|
| `low` | Allow — no notification |
| `medium` | Show a Chrome caution notification |
| `high` | Redirect tab to the built-in warning/block page |

**Current thresholds:**
- High-risk block: `confidence >= 0.90` **and** strong URL evidence (brand mismatch, suspicious TLD, IP address, executable path, or punycode)
- Medium-risk caution: `confidence >= 0.70`

These thresholds were selected during threshold analysis to maintain **0% false-positive rate** on held-out hard-negative benign examples while preserving **93.33% malicious recall**.

**DOM signal treatment:** DOM signals such as hidden iframes are treated as supporting evidence only. They can raise a result to `medium`, but they do not trigger a `high`-risk block unless stronger URL evidence or external reputation evidence also supports it.

**The warning page shows:**

- The blocked URL
- The model confidence score
- The current risk level
- Short explanation reasons
- **Go Back** — returns to the previous tab
- **Proceed Anyway** — one-time override for that tab

---

## URL Feature Set

The `feature_extractor.py` module extracts 22 numerical features from every URL:

| Category | Feature | Description |
|---|---|---|
| **Lexical** | `url_length` | Total URL character length |
| | `host_length` | Hostname character length |
| | `domain_length` | Registered domain + TLD length |
| | `path_length` | Path component length |
| | `query_length` | Query string length |
| | `num_dots` | Number of `.` characters in the full URL |
| | `num_digits` | Number of digit characters in the full URL |
| | `num_hyphens` | Number of `-` characters |
| | `num_special_chars` | Count of `-_?=&@%#!` characters |
| | `num_query_params` | Number of `&`-separated query parameters |
| | `has_https` | `1` if scheme is HTTPS, else `0` |
| | `entropy` | Shannon entropy of the full URL string |
| | `path_depth` | Number of non-empty path segments |
| **Structural** | `subdomain_count` | Number of subdomain labels |
| | `has_ip_address` | `1` if host is a bare IPv4 address |
| | `has_punycode` | `1` if hostname contains `xn--` labels |
| | `has_executable_path` | `1` if path ends with a risky extension (`.php`, `.exe`, `.zip`, etc.) |
| | `has_suspicious_tld` | `1` if TLD is in the hand-curated high-risk list |
| **Trust-aware** | `is_known_trusted_domain` | `1` if host belongs to a monitored trusted vendor |
| **Brand/Domain** | `has_brand_keyword` | `1` if a monitored brand token appears anywhere in the URL |
| | `has_brand_mismatch` | `1` if a brand token appears but the host is not brand-owned |
| **Keyword** | `has_suspicious_keyword` | `1` if a phishing-oriented keyword appears in the URL |

---

## Dataset

### Training Data

| File | Contents |
|---|---|
| `backend/data/raw/internet_urls.csv` | Mixed benign and malicious URLs |
| `backend/data/raw/official_hard_negatives_train.csv` | Phishy-looking but legitimate URLs (hard negatives for training) |

### Evaluation Data

| File | Contents |
|---|---|
| `backend/data/evaluation/official_hard_negatives_eval.csv` | 21 held-out benign URLs excluded from training |

### Dataset Shape (as of June 18, 2026)

| Split | Benign | Malicious |
|---|---|---|
| Training + evaluation combined | 878 | 300 |
| Held-out hard-negative evaluation | 21 | 0 |

Hard-negative benign examples come from official sign-in, security, verification, account-recovery, and support pages on trusted domains: Google, GitHub, Microsoft, Apple, PayPal, Dropbox, Adobe, AWS, Atlassian, and Amazon Pay. They are intentionally "phishy-looking" to stress-test the false-positive rate.

### Data Sources

| Source | Use |
|---|---|
| [OpenPhish community feed](https://openphish.com/feed.txt) | Malicious URLs |
| [Tranco top-1M list](https://tranco-list.eu/) | Benign: trusted domain breadth |
| `docs.python.org/sitemap.xml` | Benign: real documentation URLs |
| `developer.mozilla.org/sitemap.xml` | Benign: real documentation URLs |
| Microsoft and Apple `robots.txt` sitemaps | Benign: real product and support URLs |
| Official hard-negative vendor pages | Benign: phishy-looking but legitimate pages |

---

## Model Performance

Gradient Boosting was selected after comparing four baseline classifiers. Results on a hold-out test split:

| Model | Accuracy | Precision (Malicious) | Recall (Malicious) | F1 (Malicious) | ROC-AUC |
|---|---|---|---|---|---|
| **Gradient Boosting** | 0.9831 | 0.9828 | 0.9500 | 0.9661 | 0.9924 |
| Random Forest | 0.9831 | 0.9828 | 0.9500 | 0.9661 | 0.9871 |
| SVM (RBF) | 0.9703 | 0.9344 | 0.9500 | 0.9421 | 0.9718 |
| Logistic Regression | 0.9619 | 0.9180 | 0.9333 | 0.9256 | 0.9871 |

**Held-out hard-negative benign false-positive rate at threshold 0.90:**

| Model | FP Count | FP Rate | Max Benign Confidence |
|---|---|---|---|
| **Gradient Boosting** | 0 | 0.00% | 0.0051 |
| Random Forest | 0 | 0.00% | 0.2250 |
| Logistic Regression | 0 | 0.00% | 0.2736 |
| SVM (RBF) | 0 | 0.00% | 0.6757 |

Gradient Boosting was chosen because it achieves the lowest maximum benign confidence score on hard-negative examples (`0.0051`), giving the most headroom below the blocking threshold.

Detailed comparison reports are in `backend/reports/`:

| File | Contents |
|---|---|
| `model_comparison_main.csv` | Per-model metrics on the main hold-out split |
| `model_comparison_hard_negative.csv` | Per-model false-positive rates on held-out hard negatives |
| `deployed_model_threshold_analysis.csv` | Threshold sweep for the deployed Gradient Boosting model |
| `model_confusion_matrices.json` | Confusion matrices for all models |
| `model_comparison_summary.md` | Narrative summary with recommendation |
| `architecture_refinement.md` | Architecture notes and refinement history |

---

## Compare Models

To regenerate the comparison reports:

```powershell
python backend\src\model_comparison.py
```

---

## Evaluate False Positives

Measure the current model on labeled CSVs with a focus on the false-positive rate:

```powershell
# Default: evaluate on the held-out hard-negative evaluation set
python backend\src\evaluate_model.py

# Evaluate on a custom labeled CSV
python backend\src\evaluate_model.py --csv backend\data\raw\internet_urls.csv
```

The script reports:

- Classification metrics (accuracy, precision, recall, F1, ROC-AUC)
- Confusion matrix
- False-positive rate on benign URLs
- Threshold sweep showing benign FP rate and malicious recall at each threshold
- Highest-confidence false positives

---

## Auto-Updating Data

`backend/src/updater.py` watches `backend/data/updates/` and automatically retrains the model when a new CSV is dropped in:

```powershell
python backend\src\updater.py
```

Any CSV placed in `backend/data/updates/` must follow the expected schema:

| Column | Description |
|---|---|
| `url` | Raw URL string |
| `label` | `0` = benign, `1` = malicious |

---

## Run Tests

```powershell
python -m unittest discover -s tests -v
```

| Test file | Coverage |
|---|---|
| `test_feature_extractor.py` | Feature extraction correctness for various URL types |
| `test_api_server.py` | API response stability, risk-level behavior, hard-negative benign URLs, malicious brand-mismatch and risky-structure URLs |
| `test_reputation_checker.py` | Reputation checker behavior (enabled/disabled/cached) |

---

## Logs and Artifacts

| Path | Description |
|---|---|
| `backend/models/model_v1.joblib` | Trained model artifact (sklearn estimator + ordered feature list) |
| `backend/logs/events.db` | SQLite prediction log (`id`, `timestamp`, `url`, `prediction`, `confidence`) |
| `backend/logs/reputation_cache.db` | VirusTotal result cache (only created when key is configured) |

---