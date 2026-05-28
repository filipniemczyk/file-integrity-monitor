"""Tests for HTML report export."""

from pathlib import Path

from click.testing import CliRunner

from fim.cli import cli
from fim.database import init_db, save_events
from fim.exit_codes import EXIT_SUCCESS
from fim.html_report import build_html_report, export_html
from fim.models import EventType, IntegrityEvent, ScanStats, Severity


def test_build_html_report_escapes_content():
    document = build_html_report(
        [
            IntegrityEvent(
                path='/tmp/<script>alert("x")</script>.txt',
                event_type=EventType.MODIFIED,
                severity=Severity.HIGH,
                old_hash="a",
                new_hash="b",
                description='Say "hello"',
            )
        ],
        title="Test & Report",
    )

    assert "&lt;script&gt;alert" in document
    assert '/tmp/<script>alert("x")</script>.txt' not in document
    assert "Test &amp; Report" in document
    assert "background:#ea580c" in document
    assert "filterTable" in document


def test_export_html_writes_file(tmp_path: Path):
    events = [
        IntegrityEvent(
            path="/tmp/demo.txt",
            event_type=EventType.CREATED,
            severity=Severity.LOW,
            new_hash="abc",
            id=1,
            timestamp="2026-05-28T12:00:00+00:00",
        )
    ]
    stats = ScanStats(
        files_scanned=10,
        detected_changes=1,
        new_alerts_saved=1,
        duration_seconds=0.5,
    )
    output = tmp_path / "reports" / "report.html"

    saved = export_html(events, str(output), stats=stats)

    assert saved == output.resolve()
    content = output.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "/tmp/demo.txt" in content
    assert "Files scanned: 10" in content
    assert "CREATED" in content
    assert "File Integrity Monitor" in content


def test_cli_report_html_option(tmp_path: Path):
    config = tmp_path / "config.yaml"
    db_path = tmp_path / "test.db"
    config.write_text(
        f"""
monitor:
  paths:
    - {tmp_path.as_posix()}
database:
  path: {db_path.as_posix()}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    init_db(str(db_path))
    save_events(
        str(db_path),
        [
            IntegrityEvent(
                path="/tmp/x.txt",
                event_type=EventType.MODIFIED,
                severity=Severity.MEDIUM,
                old_hash="1",
                new_hash="2",
            )
        ],
    )

    html_out = tmp_path / "out.html"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "report",
            "--config",
            str(config),
            "--html",
            str(html_out),
        ],
    )

    assert result.exit_code == EXIT_SUCCESS
    assert html_out.exists()
    html_content = html_out.read_text(encoding="utf-8")
    assert "Events (" in html_content or "File Integrity Monitor" in html_content


def test_cli_export_html_command(tmp_path: Path):
    config = tmp_path / "config.yaml"
    db_path = tmp_path / "test.db"
    config.write_text(
        f"""
monitor:
  paths:
    - {tmp_path.as_posix()}
database:
  path: {db_path.as_posix()}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    init_db(str(db_path))
    save_events(
        str(db_path),
        [
            IntegrityEvent(
                path="/tmp/y.txt",
                event_type=EventType.DELETED,
                severity=Severity.HIGH,
                old_hash="old",
            )
        ],
    )

    html_out = tmp_path / "export.html"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "export-html",
            "--config",
            str(config),
            "-o",
            str(html_out),
        ],
    )

    assert result.exit_code == EXIT_SUCCESS
    assert "HTML report saved" in result.output
    assert html_out.exists()
