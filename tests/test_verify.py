"""Tests for single-file verify command."""

from pathlib import Path

from click.testing import CliRunner

from fim.cli import cli
from fim.exit_codes import EXIT_CHANGES_DETECTED, EXIT_SUCCESS
from fim.verify import VerifyStatus, verify_file
from fim.baseline import load_baseline, save_baseline
from fim.config import load_config
from fim.database import init_db
from fim.scanner import scan_paths


def _write_config(path: Path, watched_dir: Path, db_name: str = "test.db") -> Path:
    config_path = path / "config.yaml"
    config_path.write_text(
        f"""
monitor:
  paths:
    - {watched_dir.as_posix()}
  exclude: []
database:
  path: {db_name}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return config_path


def _init_baseline(config_path: Path, watched: Path, db_path: Path) -> None:
    cfg = load_config(str(config_path))
    init_db(str(db_path))
    snapshots = scan_paths([str(watched)], [])
    save_baseline(str(db_path), snapshots)


def test_verify_matching_file(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    file_path = watched / "file.txt"
    file_path.write_text("baseline\n", encoding="utf-8")
    config = _write_config(tmp_path, watched)
    db_path = tmp_path / "test.db"
    _init_baseline(config, watched, db_path)

    cfg = load_config(str(config))
    baseline = load_baseline(str(db_path))
    result = verify_file(str(file_path), cfg, baseline)

    assert result.status == VerifyStatus.OK


def test_verify_modified_file(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    file_path = watched / "file.txt"
    file_path.write_text("baseline\n", encoding="utf-8")
    config = _write_config(tmp_path, watched)
    db_path = tmp_path / "test.db"
    _init_baseline(config, watched, db_path)
    file_path.write_text("baseline\nchanged\n", encoding="utf-8")

    cfg = load_config(str(config))
    baseline = load_baseline(str(db_path))
    result = verify_file(str(file_path), cfg, baseline)

    assert result.status == "MODIFIED"


def test_verify_deleted_file(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    file_path = watched / "file.txt"
    file_path.write_text("baseline\n", encoding="utf-8")
    config = _write_config(tmp_path, watched)
    db_path = tmp_path / "test.db"
    _init_baseline(config, watched, db_path)
    file_path.unlink()

    cfg = load_config(str(config))
    baseline = load_baseline(str(db_path))
    result = verify_file(str(file_path), cfg, baseline)

    assert result.status == VerifyStatus.DELETED


def test_verify_not_in_baseline(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    baseline_file = watched / "baseline.txt"
    baseline_file.write_text("baseline\n", encoding="utf-8")
    config = _write_config(tmp_path, watched)
    db_path = tmp_path / "test.db"
    _init_baseline(config, watched, db_path)

    other_file = watched / "other.txt"
    other_file.write_text("other\n", encoding="utf-8")

    cfg = load_config(str(config))
    baseline = load_baseline(str(db_path))
    result = verify_file(str(other_file), cfg, baseline)

    assert result.status == VerifyStatus.NOT_IN_BASELINE


def test_verify_cli_ok_exit_code(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    file_path = watched / "file.txt"
    file_path.write_text("baseline\n", encoding="utf-8")
    config = _write_config(tmp_path, watched)

    runner = CliRunner()
    runner.invoke(cli, ["init", "--config", str(config)])
    result = runner.invoke(
        cli,
        ["verify", "--path", str(file_path), "--config", str(config)],
    )

    assert result.exit_code == EXIT_SUCCESS
    assert "OK" in result.output


def test_verify_cli_modified_exit_code(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    file_path = watched / "file.txt"
    file_path.write_text("baseline\n", encoding="utf-8")
    config = _write_config(tmp_path, watched)

    runner = CliRunner()
    runner.invoke(cli, ["init", "--config", str(config)])
    file_path.write_text("modified\n", encoding="utf-8")
    result = runner.invoke(
        cli,
        ["verify", "--path", str(file_path), "--config", str(config)],
    )

    assert result.exit_code == EXIT_CHANGES_DETECTED
    assert "MODIFIED" in result.output
