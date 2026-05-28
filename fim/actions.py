"""Shared operations for CLI and GUI — wraps existing project modules."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fim.analyzer import compare_snapshots
from fim.baseline import add_to_baseline, collect_snapshots_for_path, load_baseline, save_baseline
from fim.baseline_report import filter_baseline_records, format_baseline_hash, format_baseline_mtime
from fim.config import load_config
from fim.database import init_db, load_events, save_events
from fim.html_report import export_html
from fim.models import EventType, FileSnapshot, IntegrityEvent, ScanStats, Severity
from fim.reporter import build_scan_stats, export_json
from fim.scanner import scan_paths
from fim.verify import VerifyStatus, verify_file

_SECURITY_CONFIG_NAME = "config.security.yaml"


@dataclass
class ActionResult:
    """Generic action result for GUI or scripting."""

    success: bool
    message: str
    changes_detected: bool = False


@dataclass
class InitActionResult(ActionResult):
    files_in_baseline: int = 0
    duration_seconds: float = 0.0


@dataclass
class ScanActionResult(ActionResult):
    events: list[IntegrityEvent] = field(default_factory=list)
    stats: ScanStats | None = None


@dataclass
class VerifyActionResult(ActionResult):
    status: str = ""
    path: str = ""
    description: str = ""
    events: list[IntegrityEvent] = field(default_factory=list)
    severity: str | None = None
    old_hash: str | None = None
    new_hash: str | None = None


@dataclass
class AddBaselineActionResult(ActionResult):
    added: int = 0
    skipped: int = 0
    overwritten: int = 0


def is_security_config_path(config_path: str) -> bool:
    return Path(config_path).name == _SECURITY_CONFIG_NAME


def security_config_warning() -> str:
    return (
        "System security configuration may require running the program with sudo. "
        "Some files may be skipped due to missing permissions. "
        "The GUI does not elevate privileges automatically."
    )


def _db_path(config: dict[str, Any]) -> str:
    return config["database"]["path"]


def _run_scan(config: dict[str, Any]) -> list[FileSnapshot]:
    return scan_paths(config["monitor"]["paths"], config["monitor"]["exclude"])


def format_config_preview(config: dict[str, Any], config_path: str) -> str:
    """Build read-only configuration summary text for GUI."""
    lines = [
        f"Config file: {config_path}",
        f"Database: {config['database']['path']}",
        f"Hash algorithm: {config.get('hash', {}).get('algorithm', 'sha256')}",
        "",
        "MONITOR PATHS:",
    ]
    lines.extend(f"  - {path}" for path in config["monitor"]["paths"])

    exclude = config["monitor"]["exclude"]
    if isinstance(exclude, dict):
        lines.extend(["", "EXCLUDE PATHS:"])
        lines.extend(f"  - {path}" for path in exclude.get("paths", []))
        lines.extend(["", "EXCLUDE PATTERNS:"])
        lines.extend(f"  - {pattern}" for pattern in exclude.get("patterns", []))
    else:
        lines.extend(["", "EXCLUDE:"])
        lines.extend(f"  - {item}" for item in exclude)

    if "severity" in config:
        severity = config["severity"]
        lines.extend(["", f"SEVERITY DEFAULT: {severity.get('default', Severity.LOW)}"])
        lines.extend(["", "SEVERITY RULES:"])
        for level, patterns in severity.get("rules", {}).items():
            lines.append(f"  {level}:")
            lines.extend(f"    - {pattern}" for pattern in patterns)

    if "alerts" in config:
        lines.extend(["", "ALERTS (mapped to severity rules):"])
        for level, patterns in config["alerts"].items():
            lines.append(f"  {level}:")
            lines.extend(f"    - {pattern}" for pattern in patterns)

    return "\n".join(lines)


def filter_events(
    events: list[IntegrityEvent],
    *,
    limit: int | None = None,
    event_type: str | None = None,
    severity: str | None = None,
) -> list[IntegrityEvent]:
    """Filter loaded events for GUI report view."""
    filtered = list(events)

    if event_type and event_type not in ("", "ALL"):
        filtered = [event for event in filtered if event.event_type == event_type]

    if severity and severity not in ("", "ALL"):
        filtered = [event for event in filtered if event.severity == severity]

    if limit is not None and limit > 0:
        filtered = filtered[:limit]

    return filtered


def load_config_for_gui(config_path: str) -> dict[str, Any]:
    return load_config(config_path)


def run_init(config_path: str) -> InitActionResult:
    """Create baseline from monitored paths (same as CLI init)."""
    started = time.perf_counter()
    cfg = load_config(config_path)
    db_path = _db_path(cfg)
    init_db(db_path)
    snapshots = _run_scan(cfg)
    save_baseline(db_path, snapshots)
    duration = time.perf_counter() - started
    return InitActionResult(
        success=True,
        message=(
            f"Baseline saved.\n"
            f"Files in baseline: {len(snapshots)}\n"
            f"Duration: {duration:.2f} s"
        ),
        files_in_baseline=len(snapshots),
        duration_seconds=duration,
    )


def run_scan(config_path: str) -> ScanActionResult:
    """Scan and compare against baseline (same as CLI scan)."""
    cfg = load_config(config_path)
    db_path = _db_path(cfg)
    init_db(db_path)

    started_at = time.perf_counter()
    current = _run_scan(cfg)
    baseline = load_baseline(db_path)
    if not baseline:
        return ScanActionResult(
            success=False,
            message="Baseline is empty. Run Init first.",
        )

    events = compare_snapshots(current, baseline, cfg)
    new_alerts_saved = save_events(db_path, events)
    duration_seconds = time.perf_counter() - started_at
    stats = build_scan_stats(
        files_scanned=len(current),
        events=events,
        new_alerts_saved=new_alerts_saved,
        duration_seconds=duration_seconds,
    )

    message = (
        f"Scan completed in {duration_seconds:.2f} s\n"
        f"Files scanned: {stats.files_scanned}\n"
        f"Detected changes: {stats.detected_changes}\n"
        f"New alerts saved: {stats.new_alerts_saved}\n"
        f"By event type: {stats.by_event_type or '(none)'}\n"
        f"By severity: {stats.by_severity or '(none)'}"
    )
    return ScanActionResult(
        success=True,
        message=message,
        changes_detected=bool(events),
        events=events,
        stats=stats,
    )


def run_load_events(config_path: str) -> list[IntegrityEvent]:
    cfg = load_config(config_path)
    db_path = _db_path(cfg)
    if not Path(db_path).exists():
        return []
    init_db(db_path)
    return load_events(db_path)


def run_load_baseline(
    config_path: str,
    *,
    contains: str | None = None,
    limit: int | None = None,
) -> list[FileSnapshot]:
    cfg = load_config(config_path)
    db_path = _db_path(cfg)
    if not Path(db_path).exists():
        return []
    baseline = load_baseline(db_path)
    return filter_baseline_records(baseline, contains=contains, limit=limit)


def run_verify(config_path: str, file_path: str) -> VerifyActionResult:
    cfg = load_config(config_path)
    db_path = _db_path(cfg)
    baseline = load_baseline(db_path)
    if not baseline:
        return VerifyActionResult(
            success=False,
            message="Baseline is empty. Run Init first.",
            path=file_path,
        )

    result = verify_file(file_path, cfg, baseline)
    severity = result.events[0].severity if result.events else None
    old_hash = result.events[0].old_hash if result.events else None
    new_hash = result.events[0].new_hash if result.events else None

    return VerifyActionResult(
        success=True,
        message=f"Verify result: {result.status}\n{result.description}",
        changes_detected=result.status != VerifyStatus.OK,
        status=result.status,
        path=result.path,
        description=result.description,
        events=list(result.events),
        severity=severity,
        old_hash=old_hash,
        new_hash=new_hash,
    )


def run_add_baseline(
    config_path: str,
    target_path: str,
    *,
    recursive: bool = False,
    force: bool = False,
    reason: str | None = None,
) -> AddBaselineActionResult:
    cfg = load_config(config_path)
    db_path = _db_path(cfg)
    init_db(db_path)
    snapshots = collect_snapshots_for_path(
        target_path,
        recursive=recursive,
        exclude=cfg["monitor"]["exclude"],
    )
    result = add_to_baseline(db_path, snapshots, force=force)

    message = (
        f"Added: {result.added}\n"
        f"Skipped (already in baseline): {result.skipped}\n"
        f"Overwritten: {result.overwritten}"
    )
    if reason:
        message = f"Reason: {reason}\n{message}"

    return AddBaselineActionResult(
        success=True,
        message=message,
        added=result.added,
        skipped=result.skipped,
        overwritten=result.overwritten,
    )


def run_export_json(events: list[IntegrityEvent], output_path: str) -> ActionResult:
    export_json(events, output_path)
    return ActionResult(
        success=True,
        message=f"JSON saved: {output_path}\nEvents exported: {len(events)}",
    )


def run_export_html_report(
    config_path: str,
    output_path: str,
    *,
    events: list[IntegrityEvent] | None = None,
) -> ActionResult:
    cfg = load_config(config_path)
    db_path = _db_path(cfg)

    if events is None:
        if not Path(db_path).exists():
            return ActionResult(
                success=False,
                message=f"Database file not found: {db_path}",
            )
        events = load_events(db_path)

    saved = export_html(events, output_path)
    return ActionResult(
        success=True,
        message=f"HTML report saved: {saved}\nEvents exported: {len(events)}",
    )


def event_type_choices() -> list[str]:
    return [
        "ALL",
        EventType.CREATED,
        EventType.DELETED,
        EventType.MODIFIED,
        EventType.PERMISSION_CHANGED,
        EventType.OWNER_CHANGED,
        EventType.GROUP_CHANGED,
        EventType.SIZE_CHANGED,
        EventType.MTIME_CHANGED,
        EventType.METADATA_CHANGED,
    ]


def severity_choices() -> list[str]:
    return ["ALL", Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def baseline_display_row(snapshot: FileSnapshot, *, full_hash: bool) -> tuple:
    return (
        snapshot.path,
        format_baseline_hash(snapshot.sha256, full_hash=full_hash),
        str(snapshot.size),
        snapshot.mode,
        str(snapshot.uid),
        str(snapshot.gid),
        format_baseline_mtime(snapshot.mtime),
    )
