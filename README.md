# Malicious URL Detector

Malicious URL Detector is a local phishing and suspicious-URL detection prototype made of:

- A Python backend that extracts lexical URL features and classifies URLs with a trained Random Forest model.
- A Chrome extension that checks visited URLs against the local backend and blocks ones predicted to be malicious.

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
3. The backend extracts numerical URL features and runs a saved `RandomForestClassifier`.
4. If the URL is predicted as malicious with high confidence, the extension sends the tab to a built-in warning page and shows a notification.
5. The backend logs prediction events to SQLite.

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
- extract URL features
- split the data into train/test sets
- train a Random Forest classifier
- print evaluation metrics
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

## Warning Page Behavior

High-confidence blocks no longer send users straight to `about:blank`.

Instead, the extension opens a built-in warning page that shows:

- the blocked URL
- the model confidence score
- a `Go Back` action
- a `Proceed Anyway` action that allows a one-time override for that tab

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

## Logs and Artifacts

- Model file: `backend/models/model_v1.joblib`
- Prediction log database: `backend/logs/events.db`

## Known Limitations

- The model is lexical only; it does not inspect page content, redirects, certificates, reputation feeds, or screenshots.
- Even with improved data, lexical features alone can still produce false positives on legitimate sites.
- The extension depends on the local backend being up.
- The warning page is safer than `about:blank`, but the model can still be wrong and users may need to override false positives.
- Full URLs are stored in the local SQLite log, which has privacy implications.

## Next Recommended Improvements

- Add tests for feature extraction, training, and API behavior
- Track dataset versions and refresh dates more formally
- Add a scripted data refresh flow for OpenPhish, Tranco, and optionally PhishTank
- Add richer, non-lexical signals such as reputation, redirects, and brand-similarity checks
