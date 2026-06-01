"""
reputation_checker.py
--------------------------------------------------------------------------------
Optional URL reputation lookup for the Malicious URL Detector.

The module is intentionally conservative:
  - it is disabled unless VIRUSTOTAL_API_KEY is set
  - it caches responses in SQLite to avoid repeated external lookups
  - it checks existing VirusTotal URL reports instead of submitting every URL
"""

import base64
import json
import os
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone


SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SRC_DIR)
DB_PATH = os.path.join(BACKEND_DIR, "logs", "reputation_cache.db")

# Try to load environment variables from a .env file in backend/ or project root
for env_dir in [BACKEND_DIR, os.path.dirname(BACKEND_DIR)]:
    env_path = os.path.join(env_dir, ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        os.environ[key.strip()] = val.strip().strip('"').strip("'")
        except Exception:
            pass

VIRUSTOTAL_API_KEY_ENV = "VIRUSTOTAL_API_KEY"
VIRUSTOTAL_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls/{url_id}"
DEFAULT_CACHE_TTL_HOURS = 24
REQUEST_TIMEOUT_SECONDS = 8

CREATE_CACHE_SQL = """
CREATE TABLE IF NOT EXISTS reputation_cache (
    url TEXT PRIMARY KEY,
    checked_at TEXT NOT NULL,
    verdict TEXT NOT NULL,
    malicious_count INTEGER NOT NULL,
    suspicious_count INTEGER NOT NULL,
    harmless_count INTEGER NOT NULL,
    undetected_count INTEGER NOT NULL,
    source TEXT NOT NULL,
    error TEXT
);
"""

UPSERT_CACHE_SQL = """
INSERT INTO reputation_cache (
    url, checked_at, verdict, malicious_count, suspicious_count,
    harmless_count, undetected_count, source, error
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(url) DO UPDATE SET
    checked_at = excluded.checked_at,
    verdict = excluded.verdict,
    malicious_count = excluded.malicious_count,
    suspicious_count = excluded.suspicious_count,
    harmless_count = excluded.harmless_count,
    undetected_count = excluded.undetected_count,
    source = excluded.source,
    error = excluded.error;
"""

SELECT_CACHE_SQL = """
SELECT url, checked_at, verdict, malicious_count, suspicious_count,
       harmless_count, undetected_count, source, error
FROM reputation_cache
WHERE url = ?;
"""


def _empty_result(verdict: str, source: str, error: str | None = None) -> dict:
    """Return a normalized reputation result."""
    return {
        "enabled": source != "disabled",
        "source": source,
        "verdict": verdict,
        "malicious_count": 0,
        "suspicious_count": 0,
        "harmless_count": 0,
        "undetected_count": 0,
        "error": error,
    }


def _init_cache(db_path: str = DB_PATH) -> None:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(CREATE_CACHE_SQL)
        conn.commit()


def _url_id(url: str) -> str:
    """VirusTotal URL IDs are URL-safe base64 without padding."""
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def _row_to_result(row: sqlite3.Row) -> dict:
    return {
        "enabled": True,
        "source": row["source"],
        "verdict": row["verdict"],
        "malicious_count": int(row["malicious_count"]),
        "suspicious_count": int(row["suspicious_count"]),
        "harmless_count": int(row["harmless_count"]),
        "undetected_count": int(row["undetected_count"]),
        "error": row["error"],
    }


def _get_cached_result(url: str, ttl_hours: int, db_path: str = DB_PATH) -> dict | None:
    _init_cache(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(SELECT_CACHE_SQL, (url,)).fetchone()

    if row is None:
        return None

    checked_at = datetime.fromisoformat(row["checked_at"])
    if datetime.now(timezone.utc) - checked_at > timedelta(hours=ttl_hours):
        return None

    return _row_to_result(row)


def _save_cache(url: str, result: dict, db_path: str = DB_PATH) -> None:
    _init_cache(db_path)
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            UPSERT_CACHE_SQL,
            (
                url,
                checked_at,
                result["verdict"],
                int(result["malicious_count"]),
                int(result["suspicious_count"]),
                int(result["harmless_count"]),
                int(result["undetected_count"]),
                result["source"],
                result.get("error"),
            ),
        )
        conn.commit()


def _verdict_from_stats(stats: dict) -> str:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))

    if malicious >= 2 or (malicious >= 1 and suspicious >= 1):
        return "malicious"
    if malicious == 1 or suspicious >= 2:
        return "suspicious"
    if harmless >= 3 and malicious == 0 and suspicious == 0:
        return "clean"
    return "unknown"


def _fetch_virustotal_report(url: str, api_key: str) -> dict:
    endpoint = VIRUSTOTAL_URL_ENDPOINT.format(url_id=_url_id(url))
    request = urllib.request.Request(
        endpoint,
        headers={
            "x-apikey": api_key,
            "accept": "application/json",
        },
        method="GET",
    )

    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        payload = json.loads(response.read().decode("utf-8"))

    stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    verdict = _verdict_from_stats(stats)

    return {
        "enabled": True,
        "source": "virustotal",
        "verdict": verdict,
        "malicious_count": int(stats.get("malicious", 0)),
        "suspicious_count": int(stats.get("suspicious", 0)),
        "harmless_count": int(stats.get("harmless", 0)),
        "undetected_count": int(stats.get("undetected", 0)),
        "error": None,
    }


def check_reputation(url: str, ttl_hours: int = DEFAULT_CACHE_TTL_HOURS) -> dict:
    """
    Return an optional reputation result.

    If VIRUSTOTAL_API_KEY is missing, this returns a disabled result and makes
    no network request.
    """
    api_key = os.getenv(VIRUSTOTAL_API_KEY_ENV, "").strip()
    if not api_key:
        return _empty_result("unavailable", "disabled")

    cached = _get_cached_result(url, ttl_hours)
    if cached is not None:
        return cached

    try:
        result = _fetch_virustotal_report(url, api_key)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            result = _empty_result("unknown", "virustotal", "No existing VirusTotal URL report.")
        else:
            result = _empty_result("unavailable", "virustotal", f"HTTP {exc.code}")
    except Exception as exc:
        result = _empty_result("unavailable", "virustotal", str(exc))

    _save_cache(url, result)
    return result
