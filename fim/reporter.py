"""Output formatting and reporting."""

import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from fim.html_report import export_html  # re-export for convenience
from fim.models import IntegrityEvent, ScanStats

_console = Console()

_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


def print_events(events: list[IntegrityEvent]) -> None:
    """Display events as a Rich table."""
    if not events:
        _console.print("[green]No changes detected.[/green]")
        return

    table = Table(title="Integrity events", expand=True)
    table.add_column("ID", min_width=4)
    table.add_column("Timestamp", min_width=32)
    table.add_column("Severity", style="bold", min_width=8)
    table.add_column("Event type", min_width=16)
    table.add_column("Path", min_width=20)
    table.add_column("Old hash", min_width=12)
    table.add_column("New hash", min_width=12)
    table.add_column("Description", min_width=16)

    for event in events:
        style = _SEVERITY_STYLE.get(event.severity, "")
        table.add_row(
            str(event.id) if event.id is not None else "-",
            event.timestamp or "-",
            f"[{style}]{event.severity}[/{style}]" if style else event.severity,
            event.event_type,
            event.path,
            event.old_hash or "-",
            event.new_hash or "-",
            event.description or "-",
        )

    _console.print(table)


def build_scan_stats(
    files_scanned: int,
    events: list[IntegrityEvent],
    new_alerts_saved: int,
    duration_seconds: float,
) -> ScanStats:
    """Build scan summary statistics from scan results."""
    return ScanStats(
        files_scanned=files_scanned,
        detected_changes=len(events),
        new_alerts_saved=new_alerts_saved,
        duration_seconds=duration_seconds,
        by_event_type=dict(Counter(event.event_type for event in events)),
        by_severity=dict(Counter(event.severity for event in events)),
    )


def print_scan_summary(stats: ScanStats) -> None:
    """Display scan summary statistics using Rich."""
    lines = [
        "[bold green]Scan completed.[/bold green]",
        f"Files scanned: {stats.files_scanned}",
        f"Detected changes: {stats.detected_changes}",
        f"New alerts saved: {stats.new_alerts_saved}",
        f"Scan duration: {stats.duration_seconds:.2f} s",
    ]

    lines.append("")
    lines.append("[bold]By event type:[/bold]")
    if stats.by_event_type:
        for event_type, count in sorted(stats.by_event_type.items()):
            lines.append(f"  {event_type}: {count}")
    else:
        lines.append("  (none)")

    lines.append("[bold]By severity:[/bold]")
    if stats.by_severity:
        for severity, count in sorted(stats.by_severity.items()):
            lines.append(f"  {severity}: {count}")
    else:
        lines.append("  (none)")

    _console.print(
        Panel(
            "\n".join(lines),
            title="Scan summary",
            border_style="green",
        )
    )


def export_json(events: list[IntegrityEvent], output_path: str) -> None:
    """Write events to an indented JSON file."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    payload = [asdict(e) for e in events]
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
