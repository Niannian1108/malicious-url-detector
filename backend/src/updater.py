"""
updater.py
--------------------------------------------------------------------------------
Watches the  backend/data/updates/  folder for new CSV files and automatically
triggers a model retrain whenever one is detected.

How it works:
    1. watchdog monitors  backend/data/updates/  for file-system events.
    2. When a  *.csv  file is fully written (on_closed) or moved into the
       folder (on_moved), the handler:
         a. Copies the new CSV into  backend/data/raw/  (so train_model.py
            picks it up alongside the existing training data).
         b. Runs  train_model.py  as a subprocess, which retrains on ALL
            CSVs in raw/ and overwrites  backend/models/model_v1.joblib.
    3. Detailed console logs are printed at every step.

Usage:
    python updater.py          (from backend/src/)
    python backend/src/updater.py   (from the project root)

Press Ctrl+C to stop watching.
"""

import os
import shutil
import subprocess
import sys
import time
from datetime import datetime

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


# ---------------------------------------------------------------------------
# Path configuration -- anchored to __file__ so cwd doesn't matter
# ---------------------------------------------------------------------------

# backend/src/
SRC_DIR = os.path.dirname(os.path.abspath(__file__))

# backend/
BACKEND_DIR = os.path.dirname(SRC_DIR)

# Folder to watch for incoming CSV files.
WATCH_DIR = os.path.join(BACKEND_DIR, "data", "updates")

# Destination folder that train_model.py reads from.
RAW_DIR = os.path.join(BACKEND_DIR, "data", "raw")

# train_model.py location.
TRAIN_SCRIPT = os.path.join(SRC_DIR, "train_model.py")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(msg: str) -> None:
    """Print a timestamped console message."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def _is_csv(path: str) -> bool:
    """Return True if the file path ends with .csv (case-insensitive)."""
    return path.lower().endswith(".csv")


def copy_csv_to_raw(src_path: str) -> str:
    """
    Copy *src_path* into the raw/ folder so train_model.py picks it up.

    If a file with the same name already exists in raw/, it is overwritten.

    Parameters
    ----------
    src_path : str
        Absolute path to the newly detected CSV file.

    Returns
    -------
    str
        Destination path inside raw/.
    """
    os.makedirs(RAW_DIR, exist_ok=True)
    filename = os.path.basename(src_path)
    dest_path = os.path.join(RAW_DIR, filename)
    shutil.copy2(src_path, dest_path)
    _log(f"[COPY] '{filename}'  -->  {dest_path}")
    return dest_path


def retrain_model() -> bool:
    """
    Run train_model.py in a subprocess and stream its output to the console.

    Using subprocess.run() keeps things simple and reliable:
      - The training runs in a fresh Python process (no import conflicts).
      - The return code tells us whether training succeeded.
      - stdout / stderr are printed live so you can see progress.

    Returns
    -------
    bool
        True if training completed successfully, False otherwise.
    """
    _log("[TRAIN] Starting model retraining ...")

    result = subprocess.run(
        # sys.executable gives us the exact same Python interpreter that is
        # running updater.py, so virtual-environment packages are available.
        [sys.executable, TRAIN_SCRIPT],
        # Allow train_model.py to print directly to this console.
        stdout=None,   # inherit parent's stdout
        stderr=None,   # inherit parent's stderr
    )

    if result.returncode == 0:
        _log("[TRAIN] Retraining completed successfully. Model updated.")
        return True
    else:
        _log(f"[TRAIN] ERROR: train_model.py exited with code {result.returncode}.")
        return False


# ---------------------------------------------------------------------------
# Watchdog event handler
# ---------------------------------------------------------------------------

class CSVUpdateHandler(FileSystemEventHandler):
    """
    Respond to file-system events inside the watch directory.

    We listen for two event types:
      on_closed  -- triggered when an application finishes writing a file.
                    This is the most reliable signal that a file is complete.
      on_moved   -- triggered when a file is moved/renamed into the folder
                    (e.g. a download that finishes as a temp file first).
    """

    def _handle(self, path: str) -> None:
        """
        Central handler called for a newly available file at *path*.

        Steps:
          1. Ignore non-CSV files.
          2. Copy the CSV into raw/.
          3. Trigger retraining.
        """
        if not _is_csv(path):
            return  # skip non-CSV files silently

        _log(f"[DETECT] New CSV detected: {path}")

        # Step 1: copy the file into the raw/ training data folder.
        copy_csv_to_raw(path)

        # Step 2: retrain the model on all CSVs in raw/.
        retrain_model()

    # -- watchdog callbacks --------------------------------------------------

    def on_closed(self, event):
        """
        Called when a file that was opened for writing is closed.
        This means the file has been fully written to disk.
        """
        if not event.is_directory:
            self._handle(event.src_path)

    def on_moved(self, event):
        """
        Called when a file or directory is moved or renamed.
        We check the destination path (event.dest_path) because that is
        the final location of the file.
        """
        if not event.is_directory:
            self._handle(event.dest_path)

    def on_created(self, event):
        """
        Fallback for platforms or tools that do not emit on_closed.
        We add a short sleep to give the writer time to finish before
        train_model.py reads the file.
        """
        if not event.is_directory and _is_csv(event.src_path):
            # Small delay: some tools write files non-atomically, meaning
            # the created event fires before the file is fully written.
            time.sleep(1)
            self._handle(event.src_path)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    # Make sure the watch directory exists so watchdog has something to observe.
    os.makedirs(WATCH_DIR, exist_ok=True)

    _log("=" * 60)
    _log("Malicious URL Detector -- Auto-Updater")
    _log("=" * 60)
    _log(f"Watching : {WATCH_DIR}")
    _log(f"Raw dir  : {RAW_DIR}")
    _log(f"Script   : {TRAIN_SCRIPT}")
    _log("Drop a CSV file into the watch folder to trigger retraining.")
    _log("Press Ctrl+C to stop.\n")

    # Set up the watchdog observer.
    event_handler = CSVUpdateHandler()
    observer = Observer()

    observer.schedule(
        event_handler,
        path=WATCH_DIR,
        recursive=False,   # only watch the top-level folder, not sub-folders
    )

    observer.start()

    try:
        # Keep the main thread alive; watchdog runs on a background thread.
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _log("\nCtrl+C received -- stopping watcher.")
    finally:
        observer.stop()
        observer.join()
        _log("Updater stopped.")


if __name__ == "__main__":
    main()
