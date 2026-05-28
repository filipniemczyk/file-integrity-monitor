"""Tests for list-baseline command."""

from pathlib import Path

from click.testing import CliRunner

from fim.baseline import load_baseline
from fim.baseline_report import filter_baseline_records, format_baseline_hash
from fim.cli import cli
from fim.config import load_config
from fim.exit_codes import EXIT_APPLICATION_ERROR, EXIT_DATABASE_ERROR, EXIT_SUCCESS
from fim.scanner import snapshot_file


def _write_config(
    path: Path,
    watched_dir: Path,
    db_path: Path | None = None,
) -> Path:
    if db_path is None:
        db_path = path / "test.db"
    config_path = path / "config.yaml"
    config_path.write_text(
        f"""
monitor:
  paths:
    - {watched_dir.as_posix()}
  exclude: []
database:
  path: {db_path.as_posix()}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return config_path


def test_list_baseline_shows_records(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    file_path = watched / "alpha.txt"
    file_path.write_text("content\n", encoding="utf-8")
    config = _write_config(tmp_path, watched)

    runner = CliRunner()
    runner.invoke(cli, ["init", "--config", str(config)])
    result = runner.invoke(cli, ["list-baseline", "--config", str(config)])

    assert result.exit_code == EXIT_SUCCESS
    assert "Baseline" in result.output
    assert "Total baseline records: 1" in result.output

    cfg = load_config(str(config))
    baseline = load_baseline(cfg["database"]["path"])
    assert any("alpha.txt" in path for path in baseline)


def test_list_baseline_limit(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (watched / name).write_text(f"{name}\n", encoding="utf-8")
    config = _write_config(tmp_path, watched)

    runner = CliRunner()
    runner.invoke(cli, ["init", "--config", str(config)])
    result = runner.invoke(
        cli,
        ["list-baseline", "--config", str(config), "--limit", "2"],
    )

    assert result.exit_code == EXIT_SUCCESS
    assert "Showing 2 of 3" in result.output


def test_list_baseline_contains_filter(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "normal.txt").write_text("n\n", encoding="utf-8")
    ssh_file = watched / "ssh_config.txt"
    ssh_file.write_text("ssh\n", encoding="utf-8")
    config = _write_config(tmp_path, watched)

    runner = CliRunner()
    runner.invoke(cli, ["init", "--config", str(config)])
    result = runner.invoke(
        cli,
        ["list-baseline", "--config", str(config), "--contains", "ssh"],
    )

    assert result.exit_code == EXIT_SUCCESS
    assert "Showing 1 of 2" in result.output

    cfg = load_config(str(config))
    filtered = filter_baseline_records(load_baseline(cfg["database"]["path"]), contains="ssh")
    assert len(filtered) == 1
    assert "ssh_config.txt" in filtered[0].path


def test_list_baseline_full_hash(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    file_path = watched / "file.txt"
    file_path.write_text("data\n", encoding="utf-8")
    config = _write_config(tmp_path, watched)
    full_hash = snapshot_file(str(file_path)).sha256

    runner = CliRunner()
    runner.invoke(cli, ["init", "--config", str(config)])
    short = runner.invoke(cli, ["list-baseline", "--config", str(config)])
    full = runner.invoke(
        cli,
        ["list-baseline", "--config", str(config), "--full-hash"],
    )

    assert short.exit_code == EXIT_SUCCESS
    assert full.exit_code == EXIT_SUCCESS
    assert full_hash[:16] in full.output
    assert f"{full_hash[:12]}..." in short.output
    assert full_hash not in short.output


def test_list_baseline_empty_message(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    config = _write_config(tmp_path, watched)

    runner = CliRunner()
    runner.invoke(cli, ["init", "--config", str(config)])
    result = runner.invoke(cli, ["list-baseline", "--config", str(config)])

    assert result.exit_code == EXIT_APPLICATION_ERROR
    assert "Baseline is empty" in result.output


def test_list_baseline_missing_database(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    config = _write_config(tmp_path, watched, db_path=tmp_path / "missing.db")

    runner = CliRunner()
    result = runner.invoke(cli, ["list-baseline", "--config", str(config)])

    assert result.exit_code == EXIT_DATABASE_ERROR
    assert "Database file not found" in result.output


def test_filter_baseline_records_contains_case_insensitive():
    from fim.models import FileSnapshot

    baseline = {
        "/etc/SSH/config": FileSnapshot(
            path="/etc/SSH/config",
            sha256="a" * 64,
            size=1,
            mode="100644",
            uid=0,
            gid=0,
            mtime=0.0,
        ),
        "/tmp/other": FileSnapshot(
            path="/tmp/other",
            sha256="b" * 64,
            size=1,
            mode="100644",
            uid=0,
            gid=0,
            mtime=0.0,
        ),
    }
    filtered = filter_baseline_records(baseline, contains="ssh")
    assert len(filtered) == 1
    assert filtered[0].path == "/etc/SSH/config"


def test_format_baseline_hash_short_and_full():
    digest = "a" * 64
    assert format_baseline_hash(digest, full_hash=False) == f"{'a' * 12}..."
    assert format_baseline_hash(digest, full_hash=True) == digest
