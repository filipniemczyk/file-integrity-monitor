"""Tests for reporter module."""

from io import StringIO

from rich.console import Console

import fim.reporter as reporter_module
from fim.database import init_db, load_events, save_events
from fim.models import EventType, IntegrityEvent, ScanStats, Severity
from fim.reporter import (
    build_scan_stats,
    export_json,
    print_events,
    print_scan_summary,
)


def test_print_events_shows_id_and_timestamp(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_db(db_path)

    save_events(
        db_path,
        [
            IntegrityEvent(
                path="/tmp/report.txt",
                event_type=EventType.MODIFIED,
                severity=Severity.MEDIUM,
                old_hash="old",
                new_hash="new",
                description="demo",
            )
        ],
    )
    events = load_events(db_path)

    buffer = StringIO()
    original_console = reporter_module._console
    reporter_module._console = Console(file=buffer, width=240, force_terminal=True)
    try:
        print_events(events)
        output = buffer.getvalue()
    finally:
        reporter_module._console = original_console

    assert str(events[0].id) in output
    assert "Timestamp" in output
    assert events[0].timestamp in output
    assert "MODIFIED" in output
    assert events[0].path[:6] in output


def test_export_json_includes_id_and_timestamp(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_db(db_path)

    save_events(
        db_path,
        [
            IntegrityEvent(
                path="/tmp/json.txt",
                event_type=EventType.CREATED,
                severity=Severity.LOW,
                new_hash="hash",
            )
        ],
    )
    events = load_events(db_path)
    json_path = tmp_path / "report.json"
    export_json(events, str(json_path))

    content = json_path.read_text(encoding="utf-8")
    assert f'"id": {events[0].id}' in content
    assert f'"timestamp": "{events[0].timestamp}"' in content


def test_build_scan_stats_counts_by_type_and_severity():
    events = [
        IntegrityEvent(
            path="/tmp/a.txt",
            event_type=EventType.MODIFIED,
            severity=Severity.MEDIUM,
            old_hash="a",
            new_hash="b",
        ),
        IntegrityEvent(
            path="/tmp/b.txt",
            event_type=EventType.CREATED,
            severity=Severity.LOW,
            new_hash="c",
        ),
        IntegrityEvent(
            path="/tmp/c.txt",
            event_type=EventType.MODIFIED,
            severity=Severity.HIGH,
            old_hash="d",
            new_hash="e",
        ),
    ]

    stats = build_scan_stats(
        files_scanned=42,
        events=events,
        new_alerts_saved=2,
        duration_seconds=0.21,
    )

    assert stats.files_scanned == 42
    assert stats.detected_changes == 3
    assert stats.new_alerts_saved == 2
    assert stats.duration_seconds == 0.21
    assert stats.by_event_type == {EventType.MODIFIED: 2, EventType.CREATED: 1}
    assert stats.by_severity == {Severity.MEDIUM: 1, Severity.LOW: 1, Severity.HIGH: 1}


def test_print_scan_summary_shows_core_fields():
    stats = ScanStats(
        files_scanned=42,
        detected_changes=0,
        new_alerts_saved=0,
        duration_seconds=0.21,
    )

    buffer = StringIO()
    original_console = reporter_module._console
    reporter_module._console = Console(file=buffer, width=120, force_terminal=True)
    try:
        print_scan_summary(stats)
        output = buffer.getvalue()
    finally:
        reporter_module._console = original_console

    assert "Scan completed." in output
    assert "Files scanned: 42" in output
    assert "Detected changes: 0" in output
    assert "New alerts saved: 0" in output
    assert "Scan duration: 0.21 s" in output
    assert "By event type:" in output
    assert "By severity:" in output
