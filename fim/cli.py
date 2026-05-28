"""Command-line interface — Click."""

import time
from pathlib import Path

import click
from rich.console import Console

from fim import __version__
from fim.analyzer import compare_snapshots
from fim.baseline import add_to_baseline, collect_snapshots_for_path, load_baseline, save_baseline
from fim.baseline_report import filter_baseline_records, print_baseline_table
from fim.config import load_config
from fim.database import init_db, load_events, save_events
from fim.exceptions import ConfigError, DatabaseError, FIMError, ScanError
from fim.exit_codes import (
    EXIT_APPLICATION_ERROR,
    EXIT_CHANGES_DETECTED,
    EXIT_CONFIG_ERROR,
    EXIT_DATABASE_ERROR,
    EXIT_SCAN_ERROR,
    EXIT_SUCCESS,
)
from fim.reporter import build_scan_stats, export_json, print_events, print_scan_summary
from fim.scanner import scan_paths
from fim.verify import is_verify_success, verify_file
from fim.verify_report import print_verify_result

_console = Console()

_config_option = click.option(
    "--config",
    "-c",
    default="config.example.yaml",
    show_default=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to YAML configuration file.",
)


def _db_path(config: dict) -> str:
    return config["database"]["path"]


def _run_scan(config: dict) -> list:
    paths = config["monitor"]["paths"]
    exclude = config["monitor"]["exclude"]
    return scan_paths(paths, exclude)


def _exit_code_for_error(error: BaseException) -> int:
    if isinstance(error, ConfigError):
        return EXIT_CONFIG_ERROR
    if isinstance(error, DatabaseError):
        return EXIT_DATABASE_ERROR
    if isinstance(error, ScanError):
        return EXIT_SCAN_ERROR
    if isinstance(error, FIMError):
        return EXIT_APPLICATION_ERROR
    return EXIT_APPLICATION_ERROR


def _fail(ctx: click.Context, error: BaseException) -> None:
    _console.print(f"[red]Error:[/red] {error}")
    ctx.exit(_exit_code_for_error(error))


@click.group()
@click.version_option(version=__version__, prog_name="fim")
def cli() -> None:
    """File Integrity Monitor — detect unauthorized file changes."""


@cli.command()
@click.pass_context
@_config_option
def init(ctx: click.Context, config: str) -> None:
    """Create baseline — save current state of monitored files."""
    try:
        cfg = load_config(config)
        db_path = _db_path(cfg)
        init_db(db_path)
        snapshots = _run_scan(cfg)
        save_baseline(db_path, snapshots)
        _console.print(
            f"[green]Baseline saved.[/green] Files in baseline: [bold]{len(snapshots)}[/bold]"
        )
        ctx.exit(EXIT_SUCCESS)
    except (ConfigError, ScanError, DatabaseError, FIMError) as error:
        _fail(ctx, error)


@cli.command()
@click.pass_context
@_config_option
def scan(ctx: click.Context, config: str) -> None:
    """Scan files and compare against baseline."""
    try:
        cfg = load_config(config)
        db_path = _db_path(cfg)
        init_db(db_path)
        started_at = time.perf_counter()
        current = _run_scan(cfg)
        baseline = load_baseline(db_path)
        if not baseline:
            _console.print(
                "[yellow]Baseline is empty. Run first:[/yellow] python -m fim init"
            )
            ctx.exit(EXIT_APPLICATION_ERROR)
        events = compare_snapshots(current, baseline, cfg)
        new_alerts_saved = save_events(db_path, events)
        duration_seconds = time.perf_counter() - started_at
        print_events(events)
        print_scan_summary(
            build_scan_stats(
                files_scanned=len(current),
                events=events,
                new_alerts_saved=new_alerts_saved,
                duration_seconds=duration_seconds,
            )
        )
        if events:
            ctx.exit(EXIT_CHANGES_DETECTED)
        ctx.exit(EXIT_SUCCESS)
    except (ConfigError, ScanError, DatabaseError, FIMError) as error:
        _fail(ctx, error)


@cli.command("add-baseline")
@click.pass_context
@click.option(
    "--path",
    "target_path",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=True),
    help="File or directory to add to baseline.",
)
@click.option(
    "--recursive",
    is_flag=True,
    default=False,
    help="Required when --path is a directory.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite baseline entry if the path already exists.",
)
@click.option(
    "--reason",
    default=None,
    help="Optional note shown in the command summary.",
)
@_config_option
def add_baseline(
    ctx: click.Context,
    target_path: str,
    recursive: bool,
    force: bool,
    reason: str | None,
    config: str,
) -> None:
    """Add specific file(s) to baseline without full init."""
    try:
        cfg = load_config(config)
        db_path = _db_path(cfg)
        init_db(db_path)
        snapshots = collect_snapshots_for_path(
            target_path,
            recursive=recursive,
            exclude=cfg["monitor"]["exclude"],
        )
        result = add_to_baseline(db_path, snapshots, force=force)

        if reason:
            _console.print(f"[dim]Reason:[/dim] {reason}")
        _console.print("[green]Baseline update completed.[/green]")
        _console.print(f"Added: [bold]{result.added}[/bold]")
        _console.print(f"Skipped (already in baseline): [bold]{result.skipped}[/bold]")
        _console.print(f"Overwritten: [bold]{result.overwritten}[/bold]")
        ctx.exit(EXIT_SUCCESS)
    except (ConfigError, ScanError, DatabaseError, FIMError) as error:
        _fail(ctx, error)


@cli.command("list-baseline")
@click.pass_context
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Maximum number of baseline records to display.",
)
@click.option(
    "--contains",
    default=None,
    help="Show only records whose path contains this text (case-insensitive).",
)
@click.option(
    "--full-hash",
    is_flag=True,
    default=False,
    help="Show full SHA-256 instead of a shortened value.",
)
@_config_option
def list_baseline(
    ctx: click.Context,
    limit: int | None,
    contains: str | None,
    full_hash: bool,
    config: str,
) -> None:
    """List trusted baseline records (read-only)."""
    try:
        cfg = load_config(config)
        db_path = _db_path(cfg)

        if not Path(db_path).exists():
            raise DatabaseError(f"Database file not found: {db_path}")

        baseline = load_baseline(db_path)
        if not baseline:
            _console.print(
                "[yellow]Baseline is empty. Run first:[/yellow] python -m fim init"
            )
            ctx.exit(EXIT_APPLICATION_ERROR)

        records = filter_baseline_records(
            baseline,
            contains=contains,
            limit=limit,
        )
        if contains is not None and not records:
            _console.print(
                "[yellow]No baseline entries match filter:[/yellow] "
                f"{contains!r}"
            )
            ctx.exit(EXIT_SUCCESS)

        print_baseline_table(records, full_hash=full_hash)
        shown = len(records)
        total = len(baseline)
        if shown < total:
            _console.print(
                f"[dim]Showing {shown} of {total} baseline record(s).[/dim]"
            )
        else:
            _console.print(
                f"[dim]Total baseline records: {total}[/dim]"
            )
        ctx.exit(EXIT_SUCCESS)
    except (ConfigError, DatabaseError, FIMError) as error:
        _fail(ctx, error)


@cli.command()
@click.pass_context
@click.option(
    "--path",
    "file_path",
    required=True,
    type=click.Path(exists=False, dir_okay=False),
    help="Path to a single file to verify against baseline.",
)
@_config_option
def verify(ctx: click.Context, file_path: str, config: str) -> None:
    """Verify one file against baseline without saving alerts."""
    try:
        cfg = load_config(config)
        db_path = _db_path(cfg)
        baseline = load_baseline(db_path)
        if not baseline:
            _console.print(
                "[yellow]Baseline is empty. Run first:[/yellow] python -m fim init"
            )
            ctx.exit(EXIT_APPLICATION_ERROR)
        result = verify_file(file_path, cfg, baseline)
        print_verify_result(result)
        if is_verify_success(result.status):
            ctx.exit(EXIT_SUCCESS)
        ctx.exit(EXIT_CHANGES_DETECTED)
    except (ConfigError, ScanError, DatabaseError, FIMError) as error:
        _fail(ctx, error)


@cli.command()
@click.pass_context
@_config_option
@click.option(
    "--json",
    "json_path",
    default=None,
    help="Also write results to a JSON file.",
)
def report(ctx: click.Context, config: str, json_path: str | None) -> None:
    """Show event history from the database."""
    try:
        cfg = load_config(config)
        db_path = _db_path(cfg)
        events = load_events(db_path)
        print_events(events)
        if json_path:
            export_json(events, json_path)
            _console.print(f"[green]JSON saved:[/green] {json_path}")
        ctx.exit(EXIT_SUCCESS)
    except (ConfigError, DatabaseError, FIMError) as error:
        _fail(ctx, error)
