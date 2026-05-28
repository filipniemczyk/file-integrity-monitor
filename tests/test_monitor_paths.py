"""Tests for monitor path expansion and exclude rules."""

from pathlib import Path

from fim.monitor_paths import (
    ExcludeRules,
    expand_monitor_paths,
    is_excluded,
    normalize_exclude_rules,
)
from fim.scanner import scan_paths


def test_expand_monitor_paths_glob(tmp_path: Path):
    home = tmp_path / "home"
    user_a = home / "alice"
    user_b = home / "bob"
    (user_a / ".ssh").mkdir(parents=True)
    (user_b / ".ssh").mkdir(parents=True)
    (user_a / ".ssh" / "authorized_keys").write_text("key-a\n", encoding="utf-8")
    (user_b / ".ssh" / "authorized_keys").write_text("key-b\n", encoding="utf-8")

    pattern = str(home / "*" / ".ssh" / "authorized_keys").replace("\\", "/")
    expanded = expand_monitor_paths([pattern])

    assert len(expanded) == 2
    snapshots = scan_paths(expanded, exclude=ExcludeRules((), ()))
    paths = {snapshot.path for snapshot in snapshots}
    assert any("alice" in path for path in paths)
    assert any("bob" in path for path in paths)


def test_exclude_paths_prefix(tmp_path: Path):
    watched = tmp_path / "watched"
    proc_like = tmp_path / "proc"
    watched.mkdir()
    proc_like.mkdir()
    (watched / "keep.txt").write_text("ok\n", encoding="utf-8")
    (proc_like / "skip.txt").write_text("skip\n", encoding="utf-8")

    exclude = ExcludeRules(paths=(str(proc_like),), patterns=())
    snapshots = scan_paths([str(watched), str(proc_like)], exclude=exclude)

    assert any("keep.txt" in snapshot.path for snapshot in snapshots)
    assert not any("skip.txt" in snapshot.path for snapshot in snapshots)


def test_exclude_patterns_and_directory_names(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "keep.txt").write_text("ok\n", encoding="utf-8")
    (watched / "skip.log").write_text("log\n", encoding="utf-8")
    git_dir = watched / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("git\n", encoding="utf-8")
    cache = watched / "__pycache__"
    cache.mkdir()
    (cache / "mod.pyc").write_text("cache\n", encoding="utf-8")

    exclude = normalize_exclude_rules(
        {
            "paths": [],
            "patterns": ["*.log", ".git", "__pycache__"],
        }
    )
    snapshots = scan_paths([str(watched)], exclude=exclude)

    assert any("keep.txt" in snapshot.path for snapshot in snapshots)
    assert not any("skip.log" in snapshot.path for snapshot in snapshots)
    assert not any(".git" in snapshot.path for snapshot in snapshots)
    assert not any("__pycache__" in snapshot.path for snapshot in snapshots)


def test_is_excluded_under_path_prefix(tmp_path: Path):
    proc = tmp_path / "proc" / "1"
    proc.mkdir(parents=True)
    assert is_excluded(proc, ExcludeRules(paths=(str(tmp_path / "proc"),), patterns=()))


def test_normalize_exclude_legacy_list():
    rules = normalize_exclude_rules(["*.log", "/tmp", ".git"])
    assert "*.log" in rules.patterns
    assert ".git" in rules.patterns
    assert "/tmp" in rules.paths
