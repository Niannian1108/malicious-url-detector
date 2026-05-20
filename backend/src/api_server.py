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

import joblib
import numpy as np
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

from feature_extractor import extract_features  # noqa: E402
from logger_db import init_db, log_event        # noqa: E402

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

    # Basic sanity check -- make sure the expected keys are present.
    if "model" not in artefact or "features" not in artefact:
        raise RuntimeError(
            "Unexpected model artefact format. "
            "Expected keys 'model' and 'features'."
        )

    return artefact


# Load once when the module is imported (i.e. at server startup).
# Any error here is intentional -- you want the server to crash loudly
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
        "Classifies a URL as benign (0) or malicious (1) using a "
        "Random Forest model trained on URL-structure features."
    ),
    version="1.0.0",
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

class PredictRequest(BaseModel):
    """Body expected by POST /predict."""
    url: str  # the raw URL string to classify


class PredictResponse(BaseModel):
    """JSON body returned by POST /predict."""
    prediction: int    # 0 = benign, 1 = malicious
    confidence: float  # probability that the URL belongs to class 1 (malicious)


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
        5. Return the hard prediction (0/1) and the malicious probability.

    Parameters
    ----------
    request : PredictRequest
        JSON body with a single field "url".

    Returns
    -------
    PredictResponse
        "prediction" : 0 (benign) or 1 (malicious)
        "confidence" : float in [0, 1] -- probability of being malicious
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
    confidence  = float(clf.predict_proba(feature_df)[0][1])   # P(malicious)
    confidence  = round(confidence, 4)

    # -- Step 5: Log the event to the database --------------------------------
    # This is a best-effort write; we do not fail the request if logging fails.
    try:
        log_event(url=url, prediction=prediction, confidence=confidence)
    except Exception as log_exc:
        # Print a warning but still return the prediction to the caller.
        print(f"[DB] WARNING: Could not log event: {log_exc}")

    # -- Step 6: Return result -----------------------------------------------
    return PredictResponse(
        prediction=prediction,
        confidence=confidence,
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
