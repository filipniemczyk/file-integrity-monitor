"""Tests for CLI exit codes."""

from pathlib import Path

from click.testing import CliRunner

from fim.cli import cli
from fim.exit_codes import (
    EXIT_CHANGES_DETECTED,
    EXIT_CONFIG_ERROR,
    EXIT_SUCCESS,
)


def _write_config(path: Path, watched_dir: Path, db_name: str = "test.db") -> Path:
    config_path = path / "config.yaml"
    config_path.write_text(
        f"""
monitor:
  paths:
    - {watched_dir.as_posix()}
  exclude:
    - ".gitkeep"
database:
  path: {db_name}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return config_path


def test_scan_without_changes_exits_0(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "file.txt").write_text("baseline\n", encoding="utf-8")
    config = _write_config(tmp_path, watched)

    runner = CliRunner()
    assert runner.invoke(cli, ["init", "--config", str(config)]).exit_code == EXIT_SUCCESS

    result = runner.invoke(cli, ["scan", "--config", str(config)])
    assert result.exit_code == EXIT_SUCCESS


def test_scan_with_changes_exits_1(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    file_path = watched / "file.txt"
    file_path.write_text("baseline\n", encoding="utf-8")
    config = _write_config(tmp_path, watched)

    runner = CliRunner()
    runner.invoke(cli, ["init", "--config", str(config)])
    file_path.write_text("baseline\nchanged\n", encoding="utf-8")

    result = runner.invoke(cli, ["scan", "--config", str(config)])
    assert result.exit_code == EXIT_CHANGES_DETECTED


def test_invalid_config_exits_2(tmp_path: Path):
    config = tmp_path / "invalid.yaml"
    config.write_text("monitor: {}\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--config", str(config)])

    assert result.exit_code == EXIT_CONFIG_ERROR
