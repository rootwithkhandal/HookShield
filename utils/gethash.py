"""
File and directory hashing utilities.
Uses SHA-256 (not MD5) for all hashing.
This module no longer executes side-effects on import.
"""
import hashlib
import os


def hash_file(file_path: str) -> str | None:
    """Return the SHA-256 hex digest of a single file, or None on error."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, IOError) as e:
        print(f"[gethash] Error hashing file {file_path}: {e}")
        return None


def hash_directory(directory_path: str) -> str | None:
    """
    Return a single SHA-256 digest representing all files in a directory tree.
    Files are processed in sorted order for deterministic results.
    Returns None if the directory does not exist.
    """
    if not os.path.isdir(directory_path):
        print(f"[gethash] Directory not found: {directory_path}")
        return None

    combined = hashlib.sha256()
    for root, _dirs, files in os.walk(directory_path):
        for file in sorted(files):
            file_path = os.path.join(root, file)
            file_hash = hash_file(file_path)
            if file_hash:
                combined.update(file_hash.encode("utf-8"))

    return combined.hexdigest()


if __name__ == "__main__":
    folder_path = input("Enter the folder path to hash: ")
    result = hash_directory(folder_path)
    if result:
        print(f"SHA-256 hash of folder: {result}")
    else:
        print("Could not hash the specified folder.")
