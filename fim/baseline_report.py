"""Read-only baseline listing for CLI."""

from datetime import datetime

from rich.console import Console
from rich.table import Table

from fim.models import FileSnapshot

_console = Console()

_HASH_PREFIX_LEN = 12


def filter_baseline_records(
    baseline: dict[str, FileSnapshot],
    *,
    contains: str | None = None,
    limit: int | None = None,
) -> list[FileSnapshot]:
    """Return baseline snapshots sorted by path, optionally filtered and limited."""
    records = sorted(baseline.values(), key=lambda snapshot: snapshot.path)

    if contains is not None:
        needle = contains.lower()
        records = [snapshot for snapshot in records if needle in snapshot.path.lower()]

    if limit is not None:
        records = records[:limit]

    return records


def format_baseline_hash(sha256: str, *, full_hash: bool) -> str:
    """Return full or shortened SHA-256 for display."""
    if full_hash or len(sha256) <= _HASH_PREFIX_LEN:
        return sha256
    return f"{sha256[:_HASH_PREFIX_LEN]}..."


def format_baseline_mtime(mtime: float) -> str:
    """Format mtime for baseline table output."""
    return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")


def print_baseline_table(
    records: list[FileSnapshot],
    *,
    full_hash: bool = False,
) -> None:
    """Display baseline records as a Rich table."""
    table = Table(title="Baseline", expand=True)
    table.add_column("Path", min_width=24, overflow="fold")
    table.add_column("SHA-256", min_width=20)
    table.add_column("Size", min_width=8, justify="right")
    table.add_column("Mode", min_width=8)
    table.add_column("UID", min_width=6, justify="right")
    table.add_column("GID", min_width=6, justify="right")
    table.add_column("Mtime", min_width=19)

    for snapshot in records:
        table.add_row(
            snapshot.path,
            format_baseline_hash(snapshot.sha256, full_hash=full_hash),
            str(snapshot.size),
            snapshot.mode,
            str(snapshot.uid),
            str(snapshot.gid),
            format_baseline_mtime(snapshot.mtime),
        )

    _console.print(table)
