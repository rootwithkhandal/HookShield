"""
File and directory hashing utilities.
"""
import hashlib
import os

def hash_file(file_path: str) -> str | None:
    # ponytail: use standard library file_digest
    try:
        with open(file_path, "rb") as f:
            return hashlib.file_digest(f, "sha256").hexdigest()
    except (OSError, IOError):
        return None

def hash_directory(directory_path: str) -> str | None:
    if not os.path.isdir(directory_path):
        return None
    combined = hashlib.sha256()
    for root, _dirs, files in os.walk(directory_path):
        for file in sorted(files):
            h = hash_file(os.path.join(root, file))
            if h: combined.update(h.encode())
    return combined.hexdigest()
