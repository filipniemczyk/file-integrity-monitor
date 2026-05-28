"""Baseline management in files_baseline table."""

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from fim.exceptions import ConfigError, DatabaseError
from fim.models import FileSnapshot
from fim.scanner import scan_paths, snapshot_file

_INSERT_BASELINE = """
INSERT INTO files_baseline (path, sha256, size, mode, uid, gid, mtime)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""

_UPSERT_BASELINE = """
INSERT OR REPLACE INTO files_baseline (path, sha256, size, mode, uid, gid, mtime)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""


@dataclass
class AddBaselineResult:
    """Summary of add-baseline operation."""

    added: int
    skipped: int
    overwritten: int
    added_paths: list[str]
    skipped_paths: list[str]
    overwritten_paths: list[str]


def save_baseline(db_path: str, files: list[FileSnapshot]) -> None:
    """Replace existing baseline with a new one."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    try:
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("DELETE FROM files_baseline")
            conn.executemany(
                _INSERT_BASELINE,
                [
                    (f.path, f.sha256, f.size, f.mode, f.uid, f.gid, f.mtime)
                    for f in files
                ],
            )
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            raise DatabaseError(f"Cannot save baseline ({db_path}): {e}") from e
        finally:
            conn.close()
    except DatabaseError:
        raise
    except Exception as e:
        raise DatabaseError(f"Cannot save baseline ({db_path}): {e}") from e


def load_baseline(db_path: str) -> dict[str, FileSnapshot]:
    """Load baseline as path -> FileSnapshot mapping."""
    if not Path(db_path).exists():
        return {}

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute("SELECT * FROM files_baseline").fetchall()
        except sqlite3.Error as e:
            raise DatabaseError(f"Cannot load baseline ({db_path}): {e}") from e
        finally:
            conn.close()
    except DatabaseError:
        raise
    except Exception as e:
        raise DatabaseError(f"Cannot load baseline ({db_path}): {e}") from e

    return {
        row["path"]: FileSnapshot(
            path=row["path"],
            sha256=row["sha256"],
            size=row["size"],
            mode=row["mode"],
            uid=row["uid"],
            gid=row["gid"],
            mtime=row["mtime"],
        )
        for row in rows
    }


def collect_snapshots_for_path(
    path: str,
    *,
    recursive: bool,
    exclude: list[str],
) -> list[FileSnapshot]:
    """Build snapshots for a single file or directory (directory requires recursive)."""
    target = Path(path).resolve()

    if not target.exists():
        raise ConfigError(f"Path does not exist: {path}")

    if target.is_file():
        return [snapshot_file(str(target))]

    if target.is_dir():
        if not recursive:
            raise ConfigError("Directory path requires --recursive flag.")
        return scan_paths([str(target)], exclude)

    raise ConfigError(f"Unsupported path type: {path}")


def add_to_baseline(
    db_path: str,
    snapshots: list[FileSnapshot],
    *,
    force: bool = False,
) -> AddBaselineResult:
    """
    Add or update selected paths in baseline without replacing other records.

    Existing paths are skipped unless force=True (then they are overwritten).
    """
    if not snapshots:
        return AddBaselineResult(0, 0, 0, [], [], [])

    existing = load_baseline(db_path)
    to_write: list[FileSnapshot] = []
    added_paths: list[str] = []
    skipped_paths: list[str] = []
    overwritten_paths: list[str] = []

    for snapshot in snapshots:
        if snapshot.path in existing:
            if force:
                to_write.append(snapshot)
                overwritten_paths.append(snapshot.path)
            else:
                skipped_paths.append(snapshot.path)
        else:
            to_write.append(snapshot)
            added_paths.append(snapshot.path)

    if not to_write:
        return AddBaselineResult(
            added=len(added_paths),
            skipped=len(skipped_paths),
            overwritten=len(overwritten_paths),
            added_paths=added_paths,
            skipped_paths=skipped_paths,
            overwritten_paths=overwritten_paths,
        )

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    try:
        conn = sqlite3.connect(db_path)
        try:
            conn.executemany(
                _UPSERT_BASELINE,
                [
                    (
                        snap.path,
                        snap.sha256,
                        snap.size,
                        snap.mode,
                        snap.uid,
                        snap.gid,
                        snap.mtime,
                    )
                    for snap in to_write
                ],
            )
            conn.commit()
        except sqlite3.Error as error:
            conn.rollback()
            raise DatabaseError(f"Cannot update baseline ({db_path}): {error}") from error
        finally:
            conn.close()
    except DatabaseError:
        raise
    except Exception as error:
        raise DatabaseError(f"Cannot update baseline ({db_path}): {error}") from error

    return AddBaselineResult(
        added=len(added_paths),
        skipped=len(skipped_paths),
        overwritten=len(overwritten_paths),
        added_paths=added_paths,
        skipped_paths=skipped_paths,
        overwritten_paths=overwritten_paths,
    )
