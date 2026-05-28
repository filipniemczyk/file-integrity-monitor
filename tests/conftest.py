"""Shared pytest fixtures."""

import pytest
from pathlib import Path


@pytest.fixture
def tmp_watched_dir(tmp_path: Path) -> Path:
    """Temporary directory with sample test files."""
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "config.txt").write_text("key=value\n")
    (watched / "notes.txt").write_text("some notes\n")
    (watched / "script.sh").write_text("#!/bin/bash\necho hello\n")
    return watched


@pytest.fixture
def sample_config(tmp_path: Path, tmp_watched_dir: Path) -> dict:
    """Sample configuration dict pointing at a temporary directory."""
    db_path = str(tmp_path / "test.db")
    return {
        "monitor": {
            "paths": [str(tmp_watched_dir)],
            "exclude": ["*.log", "__pycache__"],
        },
        "database": {
            "path": db_path,
        },
        "alerts": {
            "critical": ["/etc/shadow"],
            "high": ["/etc/passwd"],
        },
    }
