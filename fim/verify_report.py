"""Display output for verify command."""

from rich.console import Console

from fim.verify import VerifyResult, VerifyStatus

_console = Console()

_STATUS_STYLE = {
    VerifyStatus.OK: "green",
    VerifyStatus.NOT_IN_BASELINE: "yellow",
    VerifyStatus.DELETED: "red",
    VerifyStatus.MISSING: "red",
}


def print_verify_result(result: VerifyResult) -> None:
    """Print verify outcome to the terminal."""
    style = _STATUS_STYLE.get(result.status, "yellow")
    _console.print(f"[bold {style}]Verify result:[/] {result.status}")
    _console.print(f"Path: {result.path}")

    if result.description:
        _console.print(f"Details: {result.description}")

    for event in result.events:
        _console.print(
            f"  - {event.event_type} [{event.severity}] "
            f"old={event.old_hash or '-'} new={event.new_hash or '-'}"
        )
