"""Tests for database and baseline modules."""

import sqlite3

from fim.baseline import load_baseline, save_baseline
from fim.database import (
    filter_duplicate_events,
    init_db,
    is_duplicate_alert,
    load_events,
    save_events,
)
from fim.models import FileSnapshot, IntegrityEvent, EventType, Severity


def _sample_snapshot(path: str = "/tmp/a.txt") -> FileSnapshot:
    return FileSnapshot(
        path=path,
        sha256="abc",
        size=10,
        mode="100644",
        uid=1000,
        gid=1000,
        mtime=1.0,
    )


def test_baseline_save_and_load(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_db(db_path)

    files = [_sample_snapshot("/tmp/a.txt"), _sample_snapshot("/tmp/b.txt")]
    save_baseline(db_path, files)

    loaded = load_baseline(db_path)
    assert len(loaded) == 2
    assert loaded["/tmp/a.txt"].sha256 == "abc"


def test_baseline_replaces_previous(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_db(db_path)

    save_baseline(db_path, [_sample_snapshot("/tmp/old.txt")])
    save_baseline(db_path, [_sample_snapshot("/tmp/new.txt")])

    loaded = load_baseline(db_path)
    assert len(loaded) == 1
    assert "/tmp/new.txt" in loaded
    assert "/tmp/old.txt" not in loaded


def test_upgrade_legacy_events_schema(tmp_path):
    db_path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            old_hash TEXT,
            new_hash TEXT,
            description TEXT,
            detected_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        INSERT INTO events (
            path, event_type, severity, old_hash, new_hash, description, detected_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "/tmp/legacy.txt",
            EventType.MODIFIED,
            Severity.MEDIUM,
            "old",
            "new",
            "legacy",
            "2026-01-01T00:00:00+00:00",
        ),
    )
    conn.commit()
    conn.close()

    init_db(db_path)
    loaded = load_events(db_path)

    assert len(loaded) == 1
    assert loaded[0].timestamp == "2026-01-01T00:00:00+00:00"


def test_events_save_and_load(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_db(db_path)

    events = [
        IntegrityEvent(
            path="/tmp/a.txt",
            event_type=EventType.MODIFIED,
            severity=Severity.MEDIUM,
            old_hash="old",
            new_hash="new",
            description="test",
        )
    ]
    save_events(db_path, events)
    loaded = load_events(db_path)

    assert len(loaded) == 1
    assert loaded[0].id is not None
    assert loaded[0].timestamp is not None
    assert loaded[0].event_type == EventType.MODIFIED
    assert loaded[0].old_hash == "old"


def test_is_duplicate_alert_modified_same_hashes():
    first = IntegrityEvent(
        path="/tmp/a.txt",
        event_type=EventType.MODIFIED,
        severity=Severity.MEDIUM,
        old_hash="AAA",
        new_hash="BBB",
    )
    second = IntegrityEvent(
        path="/tmp/a.txt",
        event_type=EventType.MODIFIED,
        severity=Severity.MEDIUM,
        old_hash="AAA",
        new_hash="BBB",
    )
    assert is_duplicate_alert(second, first)


def test_is_duplicate_alert_modified_different_new_hash():
    first = IntegrityEvent(
        path="/tmp/a.txt",
        event_type=EventType.MODIFIED,
        severity=Severity.MEDIUM,
        old_hash="AAA",
        new_hash="BBB",
    )
    second = IntegrityEvent(
        path="/tmp/a.txt",
        event_type=EventType.MODIFIED,
        severity=Severity.MEDIUM,
        old_hash="AAA",
        new_hash="CCC",
    )
    assert not is_duplicate_alert(second, first)


def test_is_duplicate_alert_deleted_same_old_hash():
    first = IntegrityEvent(
        path="/tmp/a.txt",
        event_type=EventType.DELETED,
        severity=Severity.MEDIUM,
        old_hash="AAA",
    )
    second = IntegrityEvent(
        path="/tmp/a.txt",
        event_type=EventType.DELETED,
        severity=Severity.MEDIUM,
        old_hash="AAA",
    )
    assert is_duplicate_alert(second, first)


def test_save_events_skips_duplicate_modified_alert(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_db(db_path)

    event = IntegrityEvent(
        path="/tmp/a.txt",
        event_type=EventType.MODIFIED,
        severity=Severity.MEDIUM,
        old_hash="AAA",
        new_hash="BBB",
    )
    assert save_events(db_path, [event]) == 1
    assert save_events(db_path, [event]) == 0

    loaded = load_events(db_path)
    assert len(loaded) == 1


def test_save_events_stores_new_alert_when_new_hash_changes(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_db(db_path)

    first = IntegrityEvent(
        path="/tmp/a.txt",
        event_type=EventType.MODIFIED,
        severity=Severity.MEDIUM,
        old_hash="AAA",
        new_hash="BBB",
    )
    second = IntegrityEvent(
        path="/tmp/a.txt",
        event_type=EventType.MODIFIED,
        severity=Severity.MEDIUM,
        old_hash="AAA",
        new_hash="CCC",
    )
    assert save_events(db_path, [first]) == 1
    assert save_events(db_path, [second]) == 1

    loaded = load_events(db_path)
    assert len(loaded) == 2
    hashes = {row.new_hash for row in loaded}
    assert hashes == {"BBB", "CCC"}


def test_filter_duplicate_events_within_same_batch():
    first = IntegrityEvent(
        path="/tmp/a.txt",
        event_type=EventType.MODIFIED,
        severity=Severity.MEDIUM,
        old_hash="AAA",
        new_hash="BBB",
    )
    second = IntegrityEvent(
        path="/tmp/a.txt",
        event_type=EventType.MODIFIED,
        severity=Severity.MEDIUM,
        old_hash="AAA",
        new_hash="BBB",
    )
    filtered = filter_duplicate_events([first, second], [])
    assert len(filtered) == 1


def test_events_have_unique_ids(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_db(db_path)

    events = [
        IntegrityEvent(
            path="/tmp/a.txt",
            event_type=EventType.CREATED,
            severity=Severity.LOW,
        ),
        IntegrityEvent(
            path="/tmp/b.txt",
            event_type=EventType.DELETED,
            severity=Severity.MEDIUM,
        ),
    ]
    save_events(db_path, events)

    assert events[0].id is not None
    assert events[1].id is not None
    assert events[0].id != events[1].id
    assert events[0].timestamp is not None
    assert events[1].timestamp is not None
