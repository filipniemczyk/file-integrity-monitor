"""Recursive directory scanning."""

from pathlib import Path

from rich.console import Console

from fim.exceptions import ScanError
from fim.hasher import calculate_sha256
from fim.models import UNREADABLE_CONTENT_HASH, FileSnapshot
from fim.monitor_paths import ExcludeRules, expand_monitor_paths, is_excluded, normalize_exclude_rules

_console = Console(stderr=True)


def snapshot_file(path: str) -> FileSnapshot:
    """Build a snapshot for a single file (used by verify)."""
    return _build_snapshot(Path(path).resolve())


def scan_paths(
    paths: list[str],
    exclude: list[str] | dict[str, list[str]] | ExcludeRules,
) -> list[FileSnapshot]:
    """
    Recursively scan paths and return snapshots for all files.

    Skips symlinks and exclude rules. Logs a warning and continues on
    permission errors. Glob patterns in paths are expanded before scanning.
    """
    exclude_rules = (
        exclude
        if isinstance(exclude, ExcludeRules)
        else normalize_exclude_rules(exclude)
    )
    snapshots: list[FileSnapshot] = []
    seen_paths: set[str] = set()

    for raw_path in expand_monitor_paths(paths):
        path = Path(raw_path).resolve()

        if not path.exists():
            _console.print(f"[yellow]Path does not exist, skipping:[/yellow] {path}")
            continue

        if path.is_file():
            if not is_excluded(path, exclude_rules):
                _try_snapshot(path, snapshots, seen_paths)
        elif path.is_dir():
            _scan_directory(path, exclude_rules, snapshots, seen_paths)
        else:
            _console.print(f"[yellow]Unsupported path type, skipping:[/yellow] {path}")

    snapshots.sort(key=lambda s: s.path)
    return snapshots


def _scan_directory(
    directory: Path,
    exclude: ExcludeRules,
    snapshots: list[FileSnapshot],
    seen_paths: set[str],
) -> None:
    try:
        entries = list(directory.iterdir())
    except PermissionError:
        _console.print(
            f"[yellow]Permission denied for directory, skipping:[/yellow] {directory}"
        )
        return

    for entry in entries:
        if is_excluded(entry, exclude):
            continue

        if entry.is_symlink():
            continue

        if entry.is_dir():
            _scan_directory(entry, exclude, snapshots, seen_paths)
        elif entry.is_file():
            _try_snapshot(entry, snapshots, seen_paths)


def _try_snapshot(
    path: Path,
    snapshots: list[FileSnapshot],
    seen_paths: set[str],
) -> None:
    try:
        snapshot = _build_snapshot(path)
    except ScanError as e:
        _console.print(f"[yellow]Warning:[/yellow] {e}")
        return

    if snapshot.path in seen_paths:
        return

    seen_paths.add(snapshot.path)
    snapshots.append(snapshot)


def _build_snapshot(path: Path) -> FileSnapshot:
    resolved = path.resolve()

    try:
        file_stat = resolved.stat()
    except PermissionError as e:
        raise ScanError(f"Permission denied reading metadata: {resolved}") from e
    except OSError as e:
        raise ScanError(f"Error reading metadata for {resolved}: {e}") from e

    mode_str = oct(file_stat.st_mode)[2:]
    try:
        sha256 = calculate_sha256(str(resolved))
    except ScanError as e:
        if "Permission denied" not in str(e):
            raise
        _console.print(
            f"[yellow]Warning:[/yellow] Cannot hash file (metadata still recorded): {resolved}"
        )
        sha256 = UNREADABLE_CONTENT_HASH

    return FileSnapshot(
        path=str(resolved),
        sha256=sha256,
        size=file_stat.st_size,
        mode=mode_str,
        uid=file_stat.st_uid,
        gid=file_stat.st_gid,
        mtime=file_stat.st_mtime,
    )
