"""Tests for add-baseline command and baseline upsert logic."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from fim.baseline import add_to_baseline, collect_snapshots_for_path, load_baseline, save_baseline
from fim.cli import cli
from fim.config import load_config
from fim.database import init_db
from fim.exceptions import ConfigError
from fim.exit_codes import EXIT_CONFIG_ERROR, EXIT_SUCCESS
from fim.scanner import snapshot_file


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


def test_add_new_file_to_baseline(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    existing = watched / "existing.txt"
    existing.write_text("keep\n", encoding="utf-8")
    new_file = watched / "new.txt"
    new_file.write_text("new\n", encoding="utf-8")

    db_path = tmp_path / "test.db"
    init_db(str(db_path))
    save_baseline(str(db_path), [snapshot_file(str(existing))])

    result = add_to_baseline(
        str(db_path),
        [snapshot_file(str(new_file))],
        force=False,
    )

    baseline = load_baseline(str(db_path))
    assert result.added == 1
    assert result.skipped == 0
    assert len(baseline) == 2
    assert str(existing.resolve()) in baseline
    assert str(new_file.resolve()) in baseline


def test_existing_entry_skipped_without_force(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    file_path = watched / "file.txt"
    file_path.write_text("v1\n", encoding="utf-8")
    db_path = tmp_path / "test.db"

    init_db(str(db_path))
    original = snapshot_file(str(file_path))
    save_baseline(str(db_path), [original])

    file_path.write_text("v2\n", encoding="utf-8")
    updated = snapshot_file(str(file_path))
    result = add_to_baseline(str(db_path), [updated], force=False)

    baseline = load_baseline(str(db_path))
    assert result.added == 0
    assert result.skipped == 1
    assert baseline[str(file_path.resolve())].sha256 == original.sha256


def test_force_overwrites_only_target_record(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    keep_file = watched / "keep.txt"
    target = watched / "target.txt"
    keep_file.write_text("keep\n", encoding="utf-8")
    target.write_text("v1\n", encoding="utf-8")

    db_path = tmp_path / "test.db"
    init_db(str(db_path))
    keep_snap = snapshot_file(str(keep_file))
    target_v1 = snapshot_file(str(target))
    save_baseline(str(db_path), [keep_snap, target_v1])

    target.write_text("v2\n", encoding="utf-8")
    target_v2 = snapshot_file(str(target))
    result = add_to_baseline(str(db_path), [target_v2], force=True)

    baseline = load_baseline(str(db_path))
    assert result.overwritten == 1
    assert result.added == 0
    assert baseline[str(keep_file.resolve())].sha256 == keep_snap.sha256
    assert baseline[str(target.resolve())].sha256 == target_v2.sha256


def test_directory_without_recursive_raises_error(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()

    with pytest.raises(ConfigError, match="--recursive"):
        collect_snapshots_for_path(str(watched), recursive=False, exclude=[])


def test_directory_with_recursive_adds_files(tmp_path: Path):
    watched = tmp_path / "watched"
    sub = watched / "sub"
    sub.mkdir(parents=True)
    (watched / "root.txt").write_text("root\n", encoding="utf-8")
    (sub / "nested.txt").write_text("nested\n", encoding="utf-8")

    db_path = tmp_path / "test.db"
    init_db(str(db_path))
    save_baseline(str(db_path), [])

    snapshots = collect_snapshots_for_path(str(watched), recursive=True, exclude=[])
    result = add_to_baseline(str(db_path), snapshots, force=False)

    baseline = load_baseline(str(db_path))
    assert result.added == 2
    assert len(baseline) == 2


def test_other_baseline_records_unchanged(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    stable = watched / "stable.txt"
    stable.write_text("stable\n", encoding="utf-8")
    extra = watched / "extra.txt"
    extra.write_text("extra\n", encoding="utf-8")

    db_path = tmp_path / "test.db"
    init_db(str(db_path))
    stable_snap = snapshot_file(str(stable))
    save_baseline(str(db_path), [stable_snap])

    add_to_baseline(str(db_path), [snapshot_file(str(extra))], force=False)
    baseline = load_baseline(str(db_path))

    assert baseline[str(stable.resolve())].sha256 == stable_snap.sha256
    assert str(extra.resolve()) in baseline


def test_add_baseline_cli_adds_file(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    config = _write_config(tmp_path, watched)

    runner = CliRunner()
    runner.invoke(cli, ["init", "--config", str(config)])
    new_file = watched / "new.txt"
    new_file.write_text("new\n", encoding="utf-8")
    result = runner.invoke(
        cli,
        [
            "add-baseline",
            "--path",
            str(new_file),
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == EXIT_SUCCESS
    assert "Added: 1" in result.output


def test_add_baseline_directory_without_recursive_exits_2(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    config = _write_config(tmp_path, watched)

    runner = CliRunner()
    runner.invoke(cli, ["init", "--config", str(config)])
    result = runner.invoke(
        cli,
        [
            "add-baseline",
            "--path",
            str(watched),
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == EXIT_CONFIG_ERROR
