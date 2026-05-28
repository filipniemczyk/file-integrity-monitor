"""Tests for analyzer module."""

from fim.analyzer import calculate_severity, compare_snapshots
from fim.models import UNREADABLE_CONTENT_HASH, EventType, FileSnapshot, Severity


def _snap(
    path: str,
    sha256: str = "hash1",
    size: int = 100,
    mode: str = "100644",
    uid: int = 1000,
    gid: int = 1000,
    mtime: float = 1.0,
) -> FileSnapshot:
    return FileSnapshot(
        path=path,
        sha256=sha256,
        size=size,
        mode=mode,
        uid=uid,
        gid=gid,
        mtime=mtime,
    )


def test_created_event():
    current = [_snap("/tmp/new.txt")]
    baseline: dict[str, FileSnapshot] = {}

    events = compare_snapshots(current, baseline)
    assert len(events) == 1
    assert events[0].event_type == EventType.CREATED


def test_deleted_event():
    current: list[FileSnapshot] = []
    baseline = {"/tmp/gone.txt": _snap("/tmp/gone.txt")}

    events = compare_snapshots(current, baseline)
    assert len(events) == 1
    assert events[0].event_type == EventType.DELETED


def test_modified_event():
    current = [_snap("/tmp/file.txt", sha256="newhash")]
    baseline = {"/tmp/file.txt": _snap("/tmp/file.txt", sha256="oldhash")}

    events = compare_snapshots(current, baseline)
    assert len(events) == 1
    assert events[0].event_type == EventType.MODIFIED
    assert events[0].old_hash == "oldhash"
    assert events[0].new_hash == "newhash"


def test_mtime_changed_event():
    current = [_snap("/tmp/file.txt", mtime=2.0)]
    baseline = {"/tmp/file.txt": _snap("/tmp/file.txt", mtime=1.0)}

    events = compare_snapshots(current, baseline)
    assert len(events) == 1
    assert events[0].event_type == EventType.MTIME_CHANGED
    assert "mtime 1.0 -> 2.0" in events[0].description


def test_permission_changed_event():
    current = [_snap("/tmp/file.txt", mode="100600")]
    baseline = {"/tmp/file.txt": _snap("/tmp/file.txt", mode="100644")}

    events = compare_snapshots(current, baseline)
    assert len(events) == 1
    assert events[0].event_type == EventType.PERMISSION_CHANGED
    assert "mode 100644 -> 100600" in events[0].description


def test_owner_changed_event():
    current = [_snap("/tmp/file.txt", uid=0)]
    baseline = {"/tmp/file.txt": _snap("/tmp/file.txt", uid=1000)}

    events = compare_snapshots(current, baseline)
    assert len(events) == 1
    assert events[0].event_type == EventType.OWNER_CHANGED
    assert "uid 1000 -> 0" in events[0].description


def test_group_changed_event():
    current = [_snap("/tmp/file.txt", gid=0)]
    baseline = {"/tmp/file.txt": _snap("/tmp/file.txt", gid=1000)}

    events = compare_snapshots(current, baseline)
    assert len(events) == 1
    assert events[0].event_type == EventType.GROUP_CHANGED
    assert "gid 1000 -> 0" in events[0].description


def test_size_changed_event():
    current = [_snap("/tmp/file.txt", size=200)]
    baseline = {"/tmp/file.txt": _snap("/tmp/file.txt", size=100)}

    events = compare_snapshots(current, baseline)
    assert len(events) == 1
    assert events[0].event_type == EventType.SIZE_CHANGED
    assert "size 100 -> 200" in events[0].description


def test_metadata_changed_inherits_highest_severity():
    current = [_snap("/tmp/file.txt", mode="100600", uid=0, gid=0)]
    baseline = {"/tmp/file.txt": _snap("/tmp/file.txt", mode="100644", uid=1000, gid=1000)}

    events = compare_snapshots(current, baseline)
    assert len(events) == 1
    assert events[0].event_type == EventType.METADATA_CHANGED
    assert events[0].severity == Severity.HIGH


def test_metadata_changed_mode_and_mtime_uses_medium():
    current = [_snap("/tmp/file.txt", mode="100600", mtime=2.0)]
    baseline = {"/tmp/file.txt": _snap("/tmp/file.txt", mode="100644", mtime=1.0)}

    events = compare_snapshots(current, baseline)
    assert len(events) == 1
    assert events[0].event_type == EventType.METADATA_CHANGED
    assert events[0].severity == Severity.MEDIUM


def test_multiple_metadata_changes_use_fallback_type():
    current = [_snap("/tmp/file.txt", mode="100600", mtime=2.0)]
    baseline = {"/tmp/file.txt": _snap("/tmp/file.txt", mode="100644", mtime=1.0)}

    events = compare_snapshots(current, baseline)
    assert len(events) == 1
    assert events[0].event_type == EventType.METADATA_CHANGED
    assert "mode 100644 -> 100600" in events[0].description
    assert "mtime 1.0 -> 2.0" in events[0].description


def test_content_change_has_priority_over_metadata():
    current = [_snap("/tmp/file.txt", sha256="newhash", mode="100600", mtime=2.0)]
    baseline = {"/tmp/file.txt": _snap("/tmp/file.txt", sha256="oldhash", mode="100644", mtime=1.0)}

    events = compare_snapshots(current, baseline)
    event_types = {event.event_type for event in events}

    assert len(events) == 1
    assert event_types == {EventType.MODIFIED}


def test_calculate_severity_critical_path_legacy_fallback():
    assert calculate_severity("/etc/shadow", EventType.MODIFIED, None) == Severity.CRITICAL


def test_calculate_severity_modified_default_legacy_fallback():
    assert calculate_severity("/tmp/random.txt", EventType.MODIFIED, None) == Severity.MEDIUM


def test_unreadable_hash_allows_owner_changed_detection():
    current = [_snap("/tmp/file.txt", sha256=UNREADABLE_CONTENT_HASH, uid=0)]
    baseline = {"/tmp/file.txt": _snap("/tmp/file.txt", sha256="realhash", uid=1000)}

    events = compare_snapshots(current, baseline)
    assert len(events) == 1
    assert events[0].event_type == EventType.OWNER_CHANGED


def test_calculate_severity_metadata_types_legacy_fallback():
    assert calculate_severity("/tmp/a.txt", EventType.PERMISSION_CHANGED, None) == Severity.MEDIUM
    assert calculate_severity("/tmp/a.txt", EventType.OWNER_CHANGED, None) == Severity.HIGH
    assert calculate_severity("/tmp/a.txt", EventType.GROUP_CHANGED, None) == Severity.HIGH
    assert calculate_severity("/tmp/a.txt", EventType.SIZE_CHANGED, None) == Severity.MEDIUM
    assert calculate_severity("/tmp/a.txt", EventType.MTIME_CHANGED, None) == Severity.LOW
    assert calculate_severity("/tmp/a.txt", EventType.METADATA_CHANGED, None) == Severity.MEDIUM
