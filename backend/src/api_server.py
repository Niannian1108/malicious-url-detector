"""
api_server.py
--------------------------------------------------------------------------------
FastAPI server for the Malicious URL Detector.

Endpoints:
    GET  /          -- health check
    POST /predict   -- classify a URL as benign (0) or malicious (1)

Usage (from any directory):
    uvicorn backend.src.api_server:app --reload
  or:
    python backend/src/api_server.py

The server automatically loads the trained model on startup and keeps it in
memory for fast predictions.
"""

import os
import sys
from typing import List

import joblib
import pandas as pd
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Path setup -- works no matter which directory you run the script from
# ---------------------------------------------------------------------------

# backend/src/  (this file's folder)
SRC_DIR = os.path.dirname(os.path.abspath(__file__))

# backend/
BACKEND_DIR = os.path.dirname(SRC_DIR)

# Ensure feature_extractor (same src/ folder) is importable.
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# Local modules -- imported after sys.path update so Python can find them in src.
from feature_extractor import extract_features  # noqa: E402
from logger_db import init_db, log_event        # noqa: E402
from reputation_checker import check_reputation  # noqa: E402

# Path to the saved model artefact produced by train_model.py
MODEL_PATH = os.path.join(BACKEND_DIR, "models", "model_v1.joblib")


# ---------------------------------------------------------------------------
# Load model at startup
# ---------------------------------------------------------------------------

def load_model(model_path: str) -> dict:
    """
    Load the model artefact from disk.

    The artefact is a dict saved by train_model.py:
        {
            "model":    <trained sklearn estimator>,
            "features": ["url_length", "domain_length", ...]
        }

    Storing the feature column list alongside the model guarantees that
    the API always builds its feature vector in the exact same order that
    the model was trained on.

    Raises
    ------
    RuntimeError
        If the model file does not exist (train_model.py has not been run yet).
    """
    if not os.path.exists(model_path):
        raise RuntimeError(
            f"Model file not found: '{model_path}'. "
            "Please run train_model.py first to generate the model."
        )

    artefact = joblib.load(model_path)

    # Basic sanity check to make sure the expected keys are present.
    if "model" not in artefact or "features" not in artefact:
        raise RuntimeError(
            "Unexpected model artefact format. "
            "Expected keys 'model' and 'features'."
        )

    return artefact


# Load once when the module is imported (ie. at server startup).
# Any error here is intentional you want the server to crash loudly
# rather than serve silently wrong predictions.
artefact = load_model(MODEL_PATH)
clf        = artefact["model"]                   # trained sklearn estimator
FEATURES   = artefact["features"]                # ordered list of feature column names
MODEL_NAME = artefact.get("model_name", type(clf).__name__)

# Some Windows environments fail when sklearn tries to spawn worker pools for
# prediction. Force single-process inference for reliability.
if hasattr(clf, "n_jobs"):
    clf.n_jobs = 1


# ---------------------------------------------------------------------------
# Lifespan: runs setup code when the server starts (and teardown on stop)
# ---------------------------------------------------------------------------

from contextlib import asynccontextmanager  # noqa: E402 (std-lib, safe here)

@asynccontextmanager
async def lifespan(app):
    """
    FastAPI lifespan handler.
    Everything before 'yield' runs at startup; after 'yield' runs at shutdown.
    """
    # Initialise the SQLite database (creates the file and table if needed).
    init_db()
    yield   # server is now running and handling requests
    # (add any cleanup code here if needed in the future)


# ---------------------------------------------------------------------------
# FastAPI app + CORS
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Malicious URL Detector API",
    description=(
        "Classifies a URL as benign (0) or malicious (1) using the "
        "currently deployed model trained on URL-structure features."
    ),
    version="1.1.0",
    lifespan=lifespan,   # register the startup/shutdown handler
)

# Allow all origins so the browser extension (or any front-end) can call
# this API without cross-origin errors.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # permit every origin
    allow_methods=["*"],      # GET, POST, OPTIONS, etc.
    allow_headers=["*"],      # all request headers
    allow_credentials=False,  # must be False when allow_origins=["*"]
)


# ---------------------------------------------------------------------------
# Request / Response schemas (Pydantic validates them automatically)
# ---------------------------------------------------------------------------

class DomSignals(BaseModel):
    """Optional lightweight page signals collected by the extension after load."""
    form_count: int = 0
    password_field_count: int = 0
    hidden_iframe_count: int = 0
    external_script_count: int = 0
    suspicious_text_hit_count: int = 0
    page_brand_mismatch: int = 0


class PredictRequest(BaseModel):
    """Body expected by POST /predict."""
    url: str
    dom_signals: DomSignals | None = None


class PredictResponse(BaseModel):
    """JSON body returned by POST /predict."""
    prediction: int    # 0 = benign, 1 = malicious
    confidence: float  # combined local risk score after lightweight adjustments
    risk_level: str    # low, medium, or high
    reasons: List[str]
    reputation: dict | None = None


def _normalise_dom_signals(dom_signals: DomSignals | None) -> dict[str, int]:
    """Convert optional DOM signals to a plain dict for risk heuristics."""
    if dom_signals is None:
        return {
            "form_count": 0,
            "password_field_count": 0,
            "hidden_iframe_count": 0,
            "external_script_count": 0,
            "suspicious_text_hit_count": 0,
            "page_brand_mismatch": 0,
        }
    return dom_signals.model_dump()


def _adjust_confidence(base_confidence: float, url_features: dict, dom_signals: dict[str, int]) -> float:
    """Raise confidence slightly when lightweight page signals reinforce suspicion."""
    adjustment = 0.0
    strong_url_evidence = _has_strong_url_evidence(url_features)

    if dom_signals["password_field_count"] and url_features.get("has_suspicious_keyword"):
        adjustment += 0.04 if strong_url_evidence else 0.02
    if dom_signals["hidden_iframe_count"] and strong_url_evidence:
        adjustment += 0.03
    if dom_signals["page_brand_mismatch"]:
        adjustment += 0.08 if url_features.get("has_brand_mismatch") else 0.03
    if dom_signals["external_script_count"] >= 12 and strong_url_evidence:
        adjustment += 0.02
    if dom_signals["suspicious_text_hit_count"] >= 4:
        adjustment += 0.03 if strong_url_evidence else 0.01

    return round(min(1.0, base_confidence + adjustment), 4)


def _has_strong_url_evidence(url_features: dict) -> bool:
    """Return True when URL-only signals are strong enough to support blocking."""
    return any(
        [
            url_features.get("has_brand_mismatch"),
            url_features.get("has_suspicious_tld"),
            url_features.get("has_ip_address"),
            url_features.get("has_executable_path"),
            url_features.get("has_punycode"),
        ]
    )


def _has_strong_dom_evidence(dom_signals: dict[str, int]) -> bool:
    """Return True for DOM evidence stronger than common embedded page structure."""
    return (
        dom_signals["password_field_count"] > 0
        and bool(dom_signals["page_brand_mismatch"])
        and dom_signals["suspicious_text_hit_count"] >= 4
    )


def _determine_risk_level(
    prediction: int,
    model_confidence: float,
    effective_confidence: float,
    url_features: dict,
    dom_signals: dict[str, int],
    reputation: dict,
) -> str:
    """Translate model output and heuristics into a user-facing severity band."""
    reputation_verdict = reputation.get("verdict")
    if reputation_verdict == "malicious":
        return "high"
    if url_features.get("is_known_trusted_domain") and not url_features.get("has_brand_mismatch"):
        return "low" if prediction == 0 or model_confidence < 0.70 else "medium"
    if reputation_verdict == "clean" and not _has_strong_url_evidence(url_features):
        return "low" if model_confidence < 0.70 else "medium"

    strong_local_evidence = _has_strong_url_evidence(url_features) or _has_strong_dom_evidence(dom_signals)

    if prediction == 1 and effective_confidence >= 0.90 and strong_local_evidence:
        return "high"
    if prediction == 1 and effective_confidence >= 0.70:
        return "medium"

    if (
        url_features.get("has_brand_mismatch")
        and dom_signals["password_field_count"]
        and dom_signals["page_brand_mismatch"]
    ):
        return "high"

    if (
        url_features.get("has_suspicious_keyword")
        and (
            dom_signals["password_field_count"]
            or dom_signals["hidden_iframe_count"]
            or dom_signals["suspicious_text_hit_count"] >= 4
        )
    ):
        return "medium"

    return "low"


def _build_reasons(url_features: dict, dom_signals: dict[str, int], effective_confidence: float, reputation: dict) -> List[str]:
    """Generate short explanation bullets for warning and demo purposes."""
    reasons: list[str] = []

    if reputation.get("verdict") == "malicious":
        reasons.append("External reputation data reports this URL as malicious.")
    elif reputation.get("verdict") == "suspicious":
        reasons.append("External reputation data reports suspicious activity for this URL.")
    elif reputation.get("verdict") == "clean":
        reasons.append("External reputation data did not find malicious detections for this URL.")
    if url_features.get("has_brand_mismatch"):
        reasons.append("The URL mentions a trusted brand on a non-brand domain.")
    if url_features.get("has_suspicious_tld"):
        reasons.append("The domain uses a higher-risk top-level domain.")
    if url_features.get("has_ip_address"):
        reasons.append("The URL uses a direct IP address instead of a normal domain.")
    if url_features.get("has_executable_path"):
        reasons.append("The path ends with a script or executable-style extension.")
    if dom_signals["password_field_count"]:
        reasons.append("The page contains password fields often seen on credential-harvesting pages.")
    if dom_signals["hidden_iframe_count"]:
        reasons.append("The page includes hidden iframes, which can indicate deceptive behavior.")
    if dom_signals["page_brand_mismatch"]:
        reasons.append("The page content suggests a brand/domain mismatch.")
    if dom_signals["suspicious_text_hit_count"] >= 3:
        reasons.append("The page text contains multiple security- or account-themed bait terms.")
    if effective_confidence >= 0.90 and (_has_strong_url_evidence(url_features) or _has_strong_dom_evidence(dom_signals)):
        reasons.append("The combined risk score is high enough to justify blocking.")
    elif effective_confidence >= 0.70:
        reasons.append("The combined risk score is elevated and worth caution.")

    if not reasons:
        reasons.append("The URL did not trigger any strong risk indicators.")

    return reasons[:4]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", tags=["Health"])
def health_check():
    """
    Simple health-check endpoint.
    Returns a confirmation message and the number of features the model uses.
    """
    return {
        "status": "ok",
        "message": "Malicious URL Detector API is running.",
        "deployed_model": MODEL_NAME,
        "model_features": len(FEATURES),
        "reputation_lookup": "enabled" if os.getenv("VIRUSTOTAL_API_KEY", "").strip() else "disabled",
    }


@app.post("/predict", response_model=PredictResponse, tags=["Prediction"])
def predict(request: PredictRequest):
    """
    Classify a URL as benign or malicious.

    Steps:
        1. Validate that the URL field is not empty.
        2. Extract the current numerical features from the URL.
        3. Build a one-row DataFrame whose columns match the training columns
           exactly (order matters for sklearn).
        4. Run the deployed classifier.
        5. Optionally check external reputation for medium/high local risk.
        6. Return the hard prediction, risk score, severity, and reasons.

    Parameters
    ----------
    request : PredictRequest
        JSON body with a single field "url".

    Returns
    -------
    PredictResponse
        "prediction" : 0 (benign) or 1 (malicious)
        "confidence" : float in [0, 1] -- combined probability/risk score
    """

    # -- Step 1: Validate input ----------------------------------------------
    url = request.url.strip()
    if not url:
        raise HTTPException(
            status_code=422,
            detail="The 'url' field must not be empty."
        )

    # -- Step 2: Extract features --------------------------------------------
    try:
        raw_features = extract_features(url)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Feature extraction failed: {exc}"
        )

    # -- Step 3: Align feature vector to training columns --------------------
    # Build a one-row DataFrame from the extracted features dict.
    # Reindexing ensures:
    #   (a) Columns are in the exact order the model expects.
    #   (b) Any column that is missing in raw_features gets filled with 0
    #       (safe default for binary/count features).
    feature_df = pd.DataFrame([raw_features]).reindex(columns=FEATURES, fill_value=0)

    # -- Step 4: Predict -----------------------------------------------------
    prediction  = int(clf.predict(feature_df)[0])              # 0 or 1
    # predict_proba returns [[prob_class0, prob_class1]]
    model_confidence = float(clf.predict_proba(feature_df)[0][1])   # P(malicious)
    model_confidence = round(model_confidence, 4)
    dom_signals = _normalise_dom_signals(request.dom_signals)
    effective_confidence = _adjust_confidence(model_confidence, raw_features, dom_signals)
    preliminary_high = prediction == 1 and effective_confidence >= 0.90
    preliminary_medium = prediction == 1 and effective_confidence >= 0.70
    reputation = (
        check_reputation(url)
        if preliminary_high or preliminary_medium
        else {"enabled": False, "source": "skipped", "verdict": "not_checked"}
    )
    risk_level = _determine_risk_level(
        prediction,
        model_confidence,
        effective_confidence,
        raw_features,
        dom_signals,
        reputation,
    )
    reasons = _build_reasons(raw_features, dom_signals, effective_confidence, reputation)

    # -- Step 5: Log the event to the database --------------------------------
    # This is a best-effort write; we do not fail the request if logging fails.
    try:
        log_event(url=url, prediction=prediction, confidence=effective_confidence)
    except Exception as log_exc:
        # Print a warning but still return the prediction to the caller.
        print(f"[DB] WARNING: Could not log event: {log_exc}")

    # -- Step 6: Return result -----------------------------------------------
    return PredictResponse(
        prediction=prediction,
        confidence=effective_confidence,
        risk_level=risk_level,
        reasons=reasons,
        reputation=reputation,
    )


# ---------------------------------------------------------------------------
# Run the server
# ---------------------------------------------------------------------------
# Choose ONE of these commands depending on where your terminal is:
#
#   From  backend/src/  directory (most common):
#       uvicorn api_server:app --reload
#
#   From the project root  malicious-url-detector/ :
#       uvicorn api_server:app --reload --app-dir backend/src
#
#   Or just run this file directly:
#       python api_server.py          (from backend/src/)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # "api_server:app" works because __file__ is always inside backend/src/,
    # so Python can find the api_server module directly.
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,   # auto-restart on file changes during development
    )
