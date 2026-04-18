"""
logger_db.py
--------------------------------------------------------------------------------
Lightweight SQLite logging module for the Malicious URL Detector.

Every time the API classifies a URL, it calls log_event() to record the
result permanently. This lets you audit predictions, spot patterns, and
build a feedback loop for future model retraining.

Database location:
    backend/logs/events.db

Table: events
    id         INTEGER  -- auto-incrementing primary key
    timestamp  TEXT     -- ISO-8601 UTC timestamp (e.g. "2025-04-10T13:00:00")
    url        TEXT     -- the raw URL that was classified
    prediction INTEGER  -- model output: 0 = benign, 1 = malicious
    confidence REAL     -- probability of being malicious (0.0 – 1.0)

Public API:
    init_db()                              -- create the DB and table if needed
    log_event(url, prediction, confidence) -- insert one row
    get_recent_events(n)                   -- fetch the last n rows (optional helper)

Usage:
    from logger_db import init_db, log_event

    init_db()                          # call once at app startup
    log_event("http://evil.xyz", 1, 0.97)
"""

import os
import sqlite3
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Path configuration -- anchored to this file's location so it works
# regardless of which directory the script is run from.
# ---------------------------------------------------------------------------

# backend/src/
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))

# backend/
_BACKEND_DIR = os.path.dirname(_SRC_DIR)

# backend/logs/events.db
_DB_PATH = os.path.join(_BACKEND_DIR, "logs", "events.db")


# ---------------------------------------------------------------------------
# SQL statements
# ---------------------------------------------------------------------------

# Creates the events table if it does not already exist.
# "IF NOT EXISTS" makes this safe to call multiple times at startup.
_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT    NOT NULL,
    url        TEXT    NOT NULL,
    prediction INTEGER NOT NULL,
    confidence REAL    NOT NULL
);
"""

# Inserts one classification event into the table.
_INSERT_EVENT_SQL = """
INSERT INTO events (timestamp, url, prediction, confidence)
VALUES (?, ?, ?, ?);
"""

# Selects the most recent n events, newest first.
_SELECT_RECENT_SQL = """
SELECT id, timestamp, url, prediction, confidence
FROM events
ORDER BY id DESC
LIMIT ?;
"""


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def init_db(db_path: str = _DB_PATH) -> None:
    """
    Initialise the SQLite database.

    - Creates the  backend/logs/  directory if it does not exist.
    - Creates the  events.db  database file if it does not exist.
    - Creates the  events  table if it does not exist.

    This function is idempotent: calling it multiple times is safe and
    will not overwrite existing data.

    Parameters
    ----------
    db_path : str
        Path to the SQLite database file. Defaults to the standard location
        at  backend/logs/events.db.

    Example
    -------
    >>> init_db()
    [DB] Initialised database at .../backend/logs/events.db
    """
    # Ensure the logs/ directory exists before SQLite tries to open the file.
    logs_dir = os.path.dirname(db_path)
    os.makedirs(logs_dir, exist_ok=True)

    # connect() creates the file automatically if it does not exist.
    with sqlite3.connect(db_path) as conn:
        conn.execute(_CREATE_TABLE_SQL)
        conn.commit()

    print(f"[DB] Initialised database at {db_path}")


def log_event(
    url: str,
    prediction: int,
    confidence: float,
    db_path: str = _DB_PATH,
) -> None:
    """
    Record one URL classification event in the database.

    Parameters
    ----------
    url        : str   -- the raw URL that was classified
    prediction : int   -- 0 (benign) or 1 (malicious)
    confidence : float -- probability of being malicious, in [0.0, 1.0]
    db_path    : str   -- path to the SQLite file (uses default if omitted)

    Example
    -------
    >>> log_event("http://login.paypal.verify.xyz", 1, 0.95)
    [DB] Logged: prediction=1, confidence=0.9500, url=http://login.paypal.verify.xyz
    """
    # Generate a UTC timestamp in ISO-8601 format.
    # Example: "2025-04-10T13:45:00+00:00"
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with sqlite3.connect(db_path) as conn:
        conn.execute(_INSERT_EVENT_SQL, (timestamp, url, prediction, confidence))
        conn.commit()

    print(
        f"[DB] Logged: prediction={prediction}, "
        f"confidence={confidence:.4f}, url={url}"
    )


def get_recent_events(n: int = 20, db_path: str = _DB_PATH) -> list[dict]:
    """
    Fetch the most recent *n* classification events from the database.

    This is a convenience helper -- useful for debugging, dashboards, or
    exposing a /history endpoint in the API.

    Parameters
    ----------
    n       : int -- number of rows to return (default: 20)
    db_path : str -- path to the SQLite file

    Returns
    -------
    list[dict]
        Each dict has keys: id, timestamp, url, prediction, confidence.
        Results are ordered newest-first.

    Example
    -------
    >>> events = get_recent_events(5)
    >>> for e in events:
    ...     print(e)
    """
    if not os.path.exists(db_path):
        # Database hasn't been created yet -- return empty list gracefully.
        return []

    with sqlite3.connect(db_path) as conn:
        # Row factory makes each row behave like a dict instead of a tuple.
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(_SELECT_RECENT_SQL, (n,))
        rows = cursor.fetchall()

    # Convert sqlite3.Row objects to plain dicts for easy JSON serialisation.
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Quick self-test  (run:  python logger_db.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Running logger_db self-test...\n")

    # 1. Initialise (creates DB and table).
    init_db()

    # 2. Log a few sample events.
    test_entries = [
        ("https://www.google.com/search?q=python", 0, 0.03),
        ("http://login-secure.paypal.verify.xyz",  1, 0.97),
        ("https://www.github.com",                 0, 0.01),
        ("http://192.168.1.1/admin/login",          1, 0.88),
    ]

    for url, pred, conf in test_entries:
        log_event(url, pred, conf)

    # 3. Read back and display.
    print("\nMost recent events in the database:")
    print("-" * 70)
    events = get_recent_events(10)
    for e in events:
        label = "MALICIOUS" if e["prediction"] == 1 else "benign   "
        print(
            f"  [{e['id']:>3}] {e['timestamp']}  {label}  "
            f"conf={e['confidence']:.2f}  {e['url']}"
        )
    print(f"\nTotal events retrieved: {len(events)}")
