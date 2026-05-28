"""Single-file verification against baseline."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fim.analyzer import compare_snapshots
from fim.models import EventType, FileSnapshot, IntegrityEvent
from fim.scanner import snapshot_file


class VerifyStatus:
    OK = "OK"
    NOT_IN_BASELINE = "NOT_IN_BASELINE"
    DELETED = "DELETED"
    MISSING = "MISSING"


@dataclass
class VerifyResult:
    """Result of verifying one file against baseline."""

    status: str
    path: str
    events: list[IntegrityEvent]
    description: str


def verify_file(
    path: str,
    config: dict[str, Any],
    baseline: dict[str, FileSnapshot],
) -> VerifyResult:
    """
    Compare a single file with its baseline entry.

    Does not write alerts to the database.
    """
    resolved = str(Path(path).resolve())
    base_snapshot = baseline.get(resolved)
    file_path = Path(resolved)

    if base_snapshot is None:
        return VerifyResult(
            status=VerifyStatus.NOT_IN_BASELINE,
            path=resolved,
            events=[],
            description="File is not present in baseline.",
        )

    if not file_path.is_file():
        return VerifyResult(
            status=VerifyStatus.DELETED,
            path=resolved,
            events=[],
            description="File was in baseline but is missing on disk.",
        )

    current = snapshot_file(resolved)
    events = compare_snapshots([current], {resolved: base_snapshot}, config)

    if not events:
        return VerifyResult(
            status=VerifyStatus.OK,
            path=resolved,
            events=[],
            description="File matches baseline.",
        )

    primary = _resolve_verify_status(events)
    description = "; ".join(event.description for event in events if event.description)
    return VerifyResult(
        status=primary,
        path=resolved,
        events=events,
        description=description,
    )


def _resolve_verify_status(events: list[IntegrityEvent]) -> str:
    """Map analyzer events to verify status label."""
    event_types = {event.event_type for event in events}

    if EventType.MODIFIED in event_types:
        return EventType.MODIFIED

    if len(event_types) == 1:
        return next(iter(event_types))

    if EventType.METADATA_CHANGED in event_types:
        return EventType.METADATA_CHANGED

    return events[0].event_type


def is_verify_success(status: str) -> bool:
    return status == VerifyStatus.OK
