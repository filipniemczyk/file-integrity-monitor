"""Tests for GUI module and actions used by GUI."""

from click.testing import CliRunner

from fim.actions import filter_events, format_config_preview, is_security_config_path
from fim.cli import cli
from fim.config import load_config
from fim.models import EventType, IntegrityEvent, Severity


def test_gui_package_importable():
    from fim.gui import launch_gui

    assert callable(launch_gui)


def test_gui_subcommand_exists():
    runner = CliRunner()
    result = runner.invoke(cli, ["gui", "--help"])
    assert result.exit_code == 0
    assert "gui" in result.output.lower() or "graphical" in result.output.lower()


def test_filter_events_limit_and_severity():
    events = [
        IntegrityEvent("/a", EventType.CREATED, Severity.LOW),
        IntegrityEvent("/b", EventType.MODIFIED, Severity.HIGH),
        IntegrityEvent("/c", EventType.MODIFIED, Severity.CRITICAL),
    ]
    filtered = filter_events(events, limit=2, severity=Severity.HIGH)
    assert len(filtered) == 1
    assert filtered[0].path == "/b"


def test_format_config_preview_includes_paths(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
monitor:
  paths:
    - ./watched
  exclude:
    paths: []
    patterns:
      - "*.log"
database:
  path: test.db
severity:
  default: low
  rules:
    low:
      - ./watched
""".strip()
        + "\n",
        encoding="utf-8",
    )
    cfg = load_config(str(config_path))
    preview = format_config_preview(cfg, str(config_path))
    assert "./watched" in preview
    assert "test.db" in preview
    assert "SEVERITY" in preview


def test_is_security_config_path():
    assert is_security_config_path("config.security.yaml")
    assert not is_security_config_path("config.example.yaml")
