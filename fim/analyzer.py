"""Compare current state with baseline."""

from typing import Any

from fim.models import UNREADABLE_CONTENT_HASH, EventType, FileSnapshot, IntegrityEvent, Severity
from fim.severity import has_severity_config, max_severity, severity_from_config

_CRITICAL_PATHS = {
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh/authorized_keys",
}

_HIGH_PATHS = {
    "/etc/passwd",
    "/etc/group",
    "/etc/ssh",
}

_METADATA_SEVERITY = {
    EventType.PERMISSION_CHANGED: Severity.MEDIUM,
    EventType.OWNER_CHANGED: Severity.HIGH,
    EventType.GROUP_CHANGED: Severity.HIGH,
    EventType.SIZE_CHANGED: Severity.MEDIUM,
    EventType.MTIME_CHANGED: Severity.LOW,
    EventType.METADATA_CHANGED: Severity.MEDIUM,
}

_SINGLE_FIELD_EVENT_TYPES = {
    "mode": EventType.PERMISSION_CHANGED,
    "uid": EventType.OWNER_CHANGED,
    "gid": EventType.GROUP_CHANGED,
    "size": EventType.SIZE_CHANGED,
    "mtime": EventType.MTIME_CHANGED,
}


def compare_snapshots(
    current: list[FileSnapshot],
    baseline: dict[str, FileSnapshot],
    config: dict[str, Any] | None = None,
) -> list[IntegrityEvent]:
    """Compare current scan with baseline and return detected events."""
    events: list[IntegrityEvent] = []
    current_map = {s.path: s for s in current}
    all_paths = set(current_map) | set(baseline)

    for path in sorted(all_paths):
        cur = current_map.get(path)
        base = baseline.get(path)

        if cur is not None and base is None:
            events.append(
                IntegrityEvent(
                    path=path,
                    event_type=EventType.CREATED,
                    severity=calculate_severity(path, EventType.CREATED, config),
                    new_hash=cur.sha256,
                    description="New file detected during scan.",
                )
            )
        elif cur is None and base is not None:
            events.append(
                IntegrityEvent(
                    path=path,
                    event_type=EventType.DELETED,
                    severity=calculate_severity(path, EventType.DELETED, config),
                    old_hash=base.sha256,
                    description="File from baseline is missing in current scan.",
                )
            )
        elif cur is not None and base is not None:
            if _content_modified(cur, base):
                events.append(
                    IntegrityEvent(
                        path=path,
                        event_type=EventType.MODIFIED,
                        severity=calculate_severity(path, EventType.MODIFIED, config),
                        old_hash=base.sha256,
                        new_hash=cur.sha256,
                        description="File content changed (different SHA-256 hash).",
                    )
                )
            elif _metadata_changed(cur, base):
                events.extend(_build_metadata_events(path, cur, base, config))

    return events


def calculate_severity(
    path: str,
    event_type: str,
    config: dict[str, Any] | None = None,
) -> str:
    """Determine event severity from YAML rules or legacy fallback logic."""
    if has_severity_config(config):
        return severity_from_config(path, config)  # type: ignore[arg-type]

    return _legacy_severity(path, event_type)


def _legacy_severity(path: str, event_type: str) -> str:
    """Legacy severity when severity section is not configured."""
    normalized = path.rstrip("/")

    for critical in _CRITICAL_PATHS:
        if normalized == critical or normalized.startswith(critical + "/"):
            return Severity.CRITICAL

    for high in _HIGH_PATHS:
        if normalized == high or normalized.startswith(high + "/"):
            return Severity.HIGH

    if event_type in (EventType.MODIFIED, EventType.DELETED):
        return Severity.MEDIUM

    if event_type in _METADATA_SEVERITY:
        return _METADATA_SEVERITY[event_type]

    if event_type == EventType.CREATED:
        return Severity.LOW

    return Severity.LOW


def _content_modified(cur: FileSnapshot, base: FileSnapshot) -> bool:
    """True when verified content hash changed (not when content is unreadable)."""
    if cur.sha256 == UNREADABLE_CONTENT_HASH:
        return False
    return cur.sha256 != base.sha256


def _metadata_changed(cur: FileSnapshot, base: FileSnapshot) -> bool:
    return bool(_collect_metadata_changes(cur, base))


def _collect_metadata_changes(
    cur: FileSnapshot,
    base: FileSnapshot,
) -> list[tuple[str, str]]:
    changes: list[tuple[str, str]] = []

    if cur.mode != base.mode:
        changes.append(("mode", f"mode {base.mode} -> {cur.mode}"))
    if cur.uid != base.uid:
        changes.append(("uid", f"uid {base.uid} -> {cur.uid}"))
    if cur.gid != base.gid:
        changes.append(("gid", f"gid {base.gid} -> {cur.gid}"))
    if cur.size != base.size:
        changes.append(("size", f"size {base.size} -> {cur.size}"))
    if cur.mtime != base.mtime:
        changes.append(("mtime", f"mtime {base.mtime} -> {cur.mtime}"))

    return changes


def _resolve_metadata_event_type(changes: list[tuple[str, str]]) -> str:
    if len(changes) == 1:
        field_name = changes[0][0]
        return _SINGLE_FIELD_EVENT_TYPES[field_name]
    return EventType.METADATA_CHANGED


def _metadata_severity(
    path: str,
    changes: list[tuple[str, str]],
    config: dict[str, Any] | None,
) -> str:
    """Use the highest severity among individual metadata change types."""
    severities = [
        calculate_severity(path, _SINGLE_FIELD_EVENT_TYPES[field_name], config)
        for field_name, _ in changes
    ]
    return max_severity(*severities)


def _build_metadata_events(
    path: str,
    cur: FileSnapshot,
    base: FileSnapshot,
    config: dict[str, Any] | None = None,
) -> list[IntegrityEvent]:
    changes = _collect_metadata_changes(cur, base)
    if not changes:
        return []

    event_type = _resolve_metadata_event_type(changes)
    description = ", ".join(part for _, part in changes)
    if event_type == EventType.METADATA_CHANGED:
        severity = _metadata_severity(path, changes, config)
    else:
        severity = calculate_severity(path, event_type, config)

    return [
        IntegrityEvent(
            path=path,
            event_type=event_type,
            severity=severity,
            old_hash=base.sha256,
            new_hash=cur.sha256,
            description=description,
        )
    ]


def _metadata_description(cur: FileSnapshot, base: FileSnapshot) -> str:
    """Backward-compatible helper for tests and callers."""
    changes = _collect_metadata_changes(cur, base)
    return ", ".join(part for _, part in changes)
