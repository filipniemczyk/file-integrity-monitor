"""Data models — contract between modules."""

from dataclasses import dataclass, field


@dataclass
class FileSnapshot:
    """Point-in-time snapshot of a file."""

    path: str
    sha256: str
    size: int
    mode: str
    uid: int
    gid: int
    mtime: float


@dataclass
class IntegrityEvent:
    """Integrity event detected when comparing against baseline."""

    path: str
    event_type: str
    severity: str
    old_hash: str | None = None
    new_hash: str | None = None
    description: str | None = None
    id: int | None = None
    timestamp: str | None = None


# Placeholder when file metadata is readable but content cannot be hashed.
UNREADABLE_CONTENT_HASH = "__UNREADABLE__"


class EventType:
    CREATED = "CREATED"
    DELETED = "DELETED"
    MODIFIED = "MODIFIED"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"
    OWNER_CHANGED = "OWNER_CHANGED"
    GROUP_CHANGED = "GROUP_CHANGED"
    SIZE_CHANGED = "SIZE_CHANGED"
    MTIME_CHANGED = "MTIME_CHANGED"
    METADATA_CHANGED = "METADATA_CHANGED"


class Severity:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ScanStats:
    """Summary statistics for a completed scan."""

    files_scanned: int
    detected_changes: int
    new_alerts_saved: int
    duration_seconds: float
    by_event_type: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
