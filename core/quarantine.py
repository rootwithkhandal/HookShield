"""
Quarantine engine.

Moves suspicious files to a quarantine folder instead of leaving them in place.
Quarantined files are renamed with a .quar extension and their original paths
are recorded in the database so they can be restored or permanently deleted.
"""
import logging
import os
import shutil
from datetime import datetime

from utils.dblogs import insert_log

logger = logging.getLogger(__name__)

# Default quarantine directory — sits at project root
_DEFAULT_QUARANTINE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "quarantine")
)


def _quarantine_dir() -> str:
    d = _DEFAULT_QUARANTINE_DIR
    os.makedirs(d, exist_ok=True)
    return d


def quarantine_file(file_path: str) -> str | None:
    """
    Move *file_path* into the quarantine folder.

    The file is renamed to  <timestamp>_<original_filename>.quar
    so multiple quarantines of the same filename don't collide.

    Returns the quarantine path on success, None on failure.
    """
    if not os.path.isfile(file_path):
        logger.error("Quarantine failed — not a file: %s", file_path)
        return None

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    original_name = os.path.basename(file_path)
    dest_name = f"{ts}_{original_name}.quar"
    dest_path = os.path.join(_quarantine_dir(), dest_name)

    try:
        shutil.move(file_path, dest_path)
        logger.warning("Quarantined: %s  →  %s", file_path, dest_path)
        insert_log("WARN", f"File quarantined: {original_name}", file_path)
        # Write a sidecar manifest so we know the original path
        manifest = dest_path + ".manifest"
        with open(manifest, "w") as f:
            f.write(f"original_path={file_path}\n")
            f.write(f"quarantined_at={datetime.now().isoformat()}\n")
        return dest_path
    except (OSError, shutil.Error) as e:
        logger.error("Failed to quarantine %s: %s", file_path, e)
        return None


def list_quarantined() -> list[dict]:
    """
    Return a list of all quarantined files with metadata.

    Each dict: { quarantine_path, original_path, quarantined_at, size_bytes }
    """
    qdir = _quarantine_dir()
    results = []

    for fname in os.listdir(qdir):
        if not fname.endswith(".quar"):
            continue
        qpath = os.path.join(qdir, fname)
        manifest_path = qpath + ".manifest"

        original_path = "unknown"
        quarantined_at = "unknown"

        if os.path.exists(manifest_path):
            with open(manifest_path) as f:
                for line in f:
                    if line.startswith("original_path="):
                        original_path = line.split("=", 1)[1].strip()
                    elif line.startswith("quarantined_at="):
                        quarantined_at = line.split("=", 1)[1].strip()

        results.append(
            {
                "quarantine_path": qpath,
                "filename": fname,
                "original_path": original_path,
                "quarantined_at": quarantined_at,
                "size_bytes": os.path.getsize(qpath),
            }
        )

    return sorted(results, key=lambda x: x["quarantined_at"], reverse=True)


def restore_file(quarantine_path: str) -> bool:
    """
    Restore a quarantined file to its original location.
    Returns True on success.
    """
    manifest_path = quarantine_path + ".manifest"
    if not os.path.exists(manifest_path):
        logger.error("No manifest found for %s — cannot restore.", quarantine_path)
        return False

    original_path = None
    with open(manifest_path) as f:
        for line in f:
            if line.startswith("original_path="):
                original_path = line.split("=", 1)[1].strip()

    if not original_path:
        logger.error("Manifest missing original_path for %s", quarantine_path)
        return False

    try:
        os.makedirs(os.path.dirname(original_path), exist_ok=True)
        shutil.move(quarantine_path, original_path)
        os.remove(manifest_path)
        logger.info("Restored: %s  →  %s", quarantine_path, original_path)
        insert_log("INFO", f"File restored from quarantine.", original_path)
        return True
    except (OSError, shutil.Error) as e:
        logger.error("Restore failed: %s", e)
        return False


def delete_quarantined(quarantine_path: str) -> bool:
    """Permanently delete a quarantined file and its manifest."""
    try:
        os.remove(quarantine_path)
        manifest = quarantine_path + ".manifest"
        if os.path.exists(manifest):
            os.remove(manifest)
        logger.info("Permanently deleted quarantined file: %s", quarantine_path)
        insert_log("INFO", "Quarantined file permanently deleted.", quarantine_path)
        return True
    except OSError as e:
        logger.error("Delete failed: %s", e)
        return False
