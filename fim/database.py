"""Data layer — SQLite."""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

from fim.exceptions import DatabaseError
from fim.models import IntegrityEvent

_CREATE_FILES_BASELINE = """
CREATE TABLE IF NOT EXISTS files_baseline (
    path TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    mode TEXT NOT NULL,
    uid INTEGER NOT NULL,
    gid INTEGER NOT NULL,
    mtime REAL NOT NULL
)
"""

_CREATE_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    old_hash TEXT,
    new_hash TEXT,
    description TEXT,
    timestamp TEXT NOT NULL
)
"""


@contextmanager
def _connect(db_path: str) -> Generator[sqlite3.Connection, None, None]:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    except sqlite3.Error as e:
        if conn is not None:
            conn.rollback()
        raise DatabaseError(f"Database error ({db_path}): {e}") from e
    except Exception:
        if conn is not None:
            conn.rollback()
        raise
    finally:
        if conn is not None:
            conn.close()


def _events_columns(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("PRAGMA table_info(events)").fetchall()
    return {row[1] for row in rows}


def _upgrade_events_schema(conn: sqlite3.Connection) -> None:
    """Upgrade legacy events tables to the current schema."""
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'"
    ).fetchone()
    if not exists:
        return

    columns = _events_columns(conn)
    if "timestamp" in columns:
        return

    # Legacy databases created before the timestamp column rename.
    legacy_time_column = "detected_at"
    if legacy_time_column in columns:
        conn.execute(
            f"ALTER TABLE events RENAME COLUMN {legacy_time_column} TO timestamp"
        )
        return

    conn.execute(
        "ALTER TABLE events ADD COLUMN timestamp TEXT NOT NULL DEFAULT ''"
    )


def init_db(db_path: str) -> None:
    """Create database file and tables if they do not exist."""
    try:
        with _connect(db_path) as conn:
            conn.execute(_CREATE_FILES_BASELINE)
            conn.execute(_CREATE_EVENTS)
            _upgrade_events_schema(conn)
    except DatabaseError:
        raise
    except Exception as e:
        raise DatabaseError(f"Cannot initialize database ({db_path}): {e}") from e


def is_duplicate_alert(
    event: IntegrityEvent,
    existing: IntegrityEvent,
) -> bool:
    """
    Return True when two alerts describe the same file state change.

    Compares path, event_type, old_hash, and new_hash when present.
    For events without new_hash (e.g. DELETED), compares path, event_type, old_hash.
    """
    if event.path != existing.path:
        return False
    if event.event_type != existing.event_type:
        return False
    if event.old_hash != existing.old_hash:
        return False
    if event.new_hash is None:
        return existing.new_hash is None
    return event.new_hash == existing.new_hash


def filter_duplicate_events(
    events: list[IntegrityEvent],
    history: list[IntegrityEvent],
) -> list[IntegrityEvent]:
    """Return only events that are not already present in alert history."""
    unique: list[IntegrityEvent] = []
    known = list(history)

    for event in events:
        if any(is_duplicate_alert(event, previous) for previous in known):
            continue
        unique.append(event)
        known.append(event)

    return unique


def _rows_to_events(rows: list[sqlite3.Row]) -> list[IntegrityEvent]:
    return [
        IntegrityEvent(
            path=row["path"],
            event_type=row["event_type"],
            severity=row["severity"],
            old_hash=row["old_hash"],
            new_hash=row["new_hash"],
            description=row["description"],
            id=row["id"],
            timestamp=row["timestamp"],
        )
        for row in rows
    ]


def save_events(db_path: str, events: list[IntegrityEvent]) -> int:
    """Save new events to the events table and populate id and timestamp.

    Returns:
        Number of alerts written to the database (after deduplication).
    """
    if not events:
        return 0

    try:
        with _connect(db_path) as conn:
            rows = conn.execute(
                "SELECT id, timestamp, path, event_type, severity, "
                "old_hash, new_hash, description FROM events"
            ).fetchall()
            history = _rows_to_events(rows)
            to_save = filter_duplicate_events(events, history)

            for event in to_save:
                timestamp = datetime.now(timezone.utc).isoformat()
                cursor = conn.execute(
                    """
                    INSERT INTO events (
                        path, event_type, severity, old_hash, new_hash, description, timestamp
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.path,
                        event.event_type,
                        event.severity,
                        event.old_hash,
                        event.new_hash,
                        event.description,
                        timestamp,
                    ),
                )
                event.id = cursor.lastrowid
                event.timestamp = timestamp
            return len(to_save)
    except DatabaseError:
        raise
    except Exception as e:
        raise DatabaseError(f"Cannot save events ({db_path}): {e}") from e


def load_events(db_path: str) -> list[IntegrityEvent]:
    """Load all events from the database."""
    try:
        with _connect(db_path) as conn:
            rows = conn.execute(
                "SELECT id, timestamp, path, event_type, severity, "
                "old_hash, new_hash, description "
                "FROM events ORDER BY id DESC"
            ).fetchall()
    except DatabaseError:
        raise
    except Exception as e:
        raise DatabaseError(f"Cannot load events ({db_path}): {e}") from e

    return _rows_to_events(rows)
