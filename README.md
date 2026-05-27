# Malicious URL Detector

Malicious URL Detector is a local phishing and suspicious-URL detection prototype made of:

- A Python backend that extracts lexical, trust-aware, and brand-mismatch URL features and classifies URLs with a trained Gradient Boosting model.
- A Chrome extension that checks visited URLs against the local backend, applies lightweight page-signal heuristics, and warns or blocks suspicious destinations.

## Project Structure

```text
malicious-url-detector/
├─ backend/
│  ├─ data/
│  │  ├─ external/   # downloaded source feeds and legacy sample data
│  │  └─ raw/        # model-ready CSV files used for training
│  ├─ logs/          # SQLite prediction logs
│  ├─ models/        # trained model artifacts
│  └─ src/           # backend, training, feature extraction, updater
├─ extension/        # Chrome extension
├─ requirements.txt
└─ README.md
```

## What It Does

1. The browser extension listens for top-level page navigations.
2. It sends the target URL to the local FastAPI backend at `http://127.0.0.1:8000/predict`.
3. The backend extracts numerical URL features and runs a saved machine-learning model.
4. After the page loads, the extension can send lightweight DOM signals such as password fields, hidden iframes, external scripts, suspicious page text, and simple brand/domain mismatch cues.
5. The backend returns a prediction, confidence score, risk level, and short explanation reasons.
6. If the destination is high risk, the extension sends the tab to a built-in warning page. Medium-risk results trigger a caution notification. Low-risk results are allowed.
7. The backend logs prediction events to SQLite.

## Requirements

- Python 3.12
- Google Chrome or another Chromium browser that supports Manifest V3 extensions

## Setup

From the project root:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Train the Model

The training script reads every CSV in `backend/data/raw/`. Each CSV must contain:

- `url`
- `label` where `0 = benign` and `1 = malicious`

Train the model with:

```powershell
python backend\src\train_model.py
```

Because the training script reads every CSV in `backend/data/raw/`, any curated hard-negative benign CSV placed there is included automatically.

This will:

- load the training data
- extract URL features including lexical, trust, and brand/domain consistency signals
- split the data into train/test sets
- train the selected deployed model
- print evaluation metrics on a hold-out split
- refit the deployed model on the full dataset
- save the model to `backend/models/model_v1.joblib`

## Run the Backend API

From the project root:

```powershell
uvicorn backend.src.api_server:app --reload
```

The API will be available at:

- `http://127.0.0.1:8000/`
- `http://127.0.0.1:8000/docs`

## Load the Chrome Extension

1. Open Chrome and go to `chrome://extensions/`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select the `extension` folder:

   `C:\Users\Chong You Xin\Desktop\malicious-url-detector\extension`

5. Make sure the backend is running before browsing

## Typical Local Workflow

```powershell
.venv\Scripts\Activate.ps1
python backend\src\train_model.py
uvicorn backend.src.api_server:app --reload
```

Then load the unpacked extension and browse normally.

## Warning And Caution Behavior

High-confidence blocks no longer send users straight to `about:blank`.

Instead, the extension opens a built-in warning page that shows:

- the blocked URL
- the model confidence score
- the current risk level
- short explanation reasons
- a `Go Back` action
- a `Proceed Anyway` action that allows a one-time override for that tab

The current extension flow uses three severity bands:

- `low` risk: allow
- `medium` risk: show a caution notification
- `high` risk: open the warning page and block by default

## Data Currently Included

The project no longer trains on the toy `sample_urls.csv` file by default.

The current model-ready dataset is:

- `backend/data/raw/internet_urls.csv`
- `backend/data/raw/official_hard_negatives.csv`

The source manifest is stored in:

- `backend/data/external/dataset_manifest.json`

The downloaded source files are stored in:

- `backend/data/external/openphish_feed.txt`
- `backend/data/external/tranco_top_1m.csv`
- `backend/data/external/sample_urls_legacy.csv`

### Current Dataset Shape

As of April 25, 2026, the combined training set contains:

- 899 benign URLs
- 300 malicious URLs

There is also a dedicated hard-negative benign file:

- `backend/data/raw/official_hard_negatives.csv`

This file contains official, legitimate URLs from sign-in, security, verification, account recovery, and support pages on trusted domains such as Google, GitHub, Microsoft, Apple, PayPal, Dropbox, Adobe, AWS, Atlassian, and Amazon Pay. These are intentionally "phishy-looking" but safe, which makes them useful for reducing false positives.

Benign URLs come from legitimate, traceable sources:

- Tranco top sites list for trusted domain breadth: [tranco-list.eu](https://tranco-list.eu/)
- Official Python documentation sitemap: [docs.python.org/sitemap.xml](https://docs.python.org/sitemap.xml)
- Official MDN sitemap endpoint: [developer.mozilla.org/sitemap.xml](https://developer.mozilla.org/sitemap.xml)
- Official Microsoft sitemap indexes exposed in `robots.txt`
- Official Apple sitemap feeds exposed in `robots.txt`

Malicious URLs come from:

- OpenPhish community feed: [openphish.com/feed.txt](https://openphish.com/feed.txt)

This is more realistic than the earlier dataset because the benign side now contains real documentation, product, retail, AI, security, and newsroom URLs instead of only homepage-style domains.

## Notes on Data Sources

- OpenPhish provides a public phishing feed that is useful for near-real-time malicious URLs.
- Tranco provides a research-oriented ranking of popular domains and is a practical benign-domain source.
- Official sitemap feeds from trusted sites provide real benign page URLs with more realistic paths and structures.
- Official help, sign-in, support, and account-management pages from trusted vendors are used as hard-negative benign examples.
- PhishTank is also a strong source, but anonymous bulk downloads may be rate-limited unless you use an application key.

## Auto-Updating Data

The project includes `backend/src/updater.py`, which watches `backend/data/updates/` for new CSV files and retrains the model automatically.

Run it with:

```powershell
python backend\src\updater.py
```

Any CSV dropped into `backend/data/updates/` should match the expected schema:

- `url`
- `label`

## Evaluate False Positives

Use the evaluation script to measure the current model on labeled CSVs with a focus on false positives:

```powershell
python backend\src\evaluate_model.py
```

By default, this evaluates:

- `backend/data/raw/official_hard_negatives.csv`

You can also evaluate any labeled CSV:

```powershell
python backend\src\evaluate_model.py --csv backend\data\raw\internet_urls.csv
```

The script reports:

- classification metrics
- confusion matrix
- false-positive rate on benign URLs
- threshold sweep for benign false positives and malicious recall
- highest-confidence false positives

## Compare Models

Use the comparison script to train and compare the main baseline models for the FYP 2 report:

```powershell
python backend\src\model_comparison.py
```

This writes report-ready artifacts to:

- `backend/reports/model_comparison_main.csv`
- `backend/reports/model_comparison_hard_negative.csv`
- `backend/reports/deployed_model_threshold_analysis.csv`
- `backend/reports/model_confusion_matrices.json`
- `backend/reports/model_comparison_summary.md`
- `backend/reports/architecture_refinement.md`

## Current Detection Strategy

The current detector now combines:

- lexical structure signals such as URL length, dots, digits, hyphens, entropy, query size, and path depth
- suspicious structure signals such as punycode, risky TLDs, executable/script paths, and IP-host usage
- trust-aware signals such as known trusted domains
- brand/domain consistency signals that distinguish legitimate brand-owned URLs from lookalike phishing domains
- lightweight page heuristics such as password fields, hidden iframes, suspicious page text, external script count, and simple brand/domain mismatch cues collected by the extension after load

The current deployed model is **Gradient Boosting**, selected after model comparison because it outperformed the other tested baselines while keeping hard-negative benign false positives at `0%`.

The Chrome extension currently uses:

- a `high` risk threshold of `0.90` for blocking
- a `medium` risk threshold of `0.70` for caution warnings

These thresholds were chosen to preserve `0%` hard-negative benign false positives while maintaining strong malicious recall during threshold analysis.

## Run Tests

Run the lightweight regression tests with:

```powershell
python -m unittest discover -s tests -v
```

The test suite covers:

- feature extraction behavior
- API response stability
- risk-level response behavior
- official benign URLs that look suspicious
- malicious brand-mismatch and risky-structure URLs

## Logs and Artifacts

- Model file: `backend/models/model_v1.joblib`
- Prediction log database: `backend/logs/events.db`

## Known Limitations

- The system is still mostly URL-centric. It now adds lightweight DOM heuristics, but it does not perform deep page-content classification, live redirect tracing, certificate analysis, reputation lookups, or screenshot-based inspection.
- Even with trust-aware and brand/domain features, the model can still produce false positives or miss attacks that look benign lexically.
- The extension depends on the local backend being up.
- The warning page is safer than `about:blank`, but the model can still be wrong and users may need to override false positives.
- Full URLs are stored in the local SQLite log, which has privacy implications.

## Next Recommended Improvements

- Add tests for feature extraction, training, and API behavior
- Track dataset versions and refresh dates more formally
- Add a scripted data refresh flow for OpenPhish, Tranco, and optionally PhishTank
- Expand the lightweight page-signal layer and validate it against more real-world phishing and hard-negative benign pages
- Add richer non-lexical signals such as reputation, redirects, and certificate cues
