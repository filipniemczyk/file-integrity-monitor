"""File hashing — SHA-256."""

import hashlib
from pathlib import Path

from fim.exceptions import ScanError

_CHUNK_SIZE = 8192


def calculate_sha256(path: str) -> str:
    """
    Compute SHA-256 hash of file contents (block reads).

    Raises:
        ScanError: If the file cannot be read.
    """
    file_path = Path(path)

    if not file_path.is_file():
        raise ScanError(f"Path is not a file: {path}")

    hasher = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(_CHUNK_SIZE):
                hasher.update(chunk)
    except PermissionError as e:
        raise ScanError(f"Permission denied reading: {path}") from e
    except OSError as e:
        raise ScanError(f"Error reading file {path}: {e}") from e

    return hasher.hexdigest()
