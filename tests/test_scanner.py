"""Tests for scanner module."""

from fim.scanner import scan_paths


def test_scan_paths_finds_files(tmp_watched_dir):
    snapshots = scan_paths([str(tmp_watched_dir)], exclude=[])

    paths = {s.path for s in snapshots}
    assert any(p.endswith("config.txt") for p in paths)
    assert any(p.endswith("notes.txt") for p in paths)
    assert len(snapshots) >= 3


def test_scan_paths_excludes_patterns(tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "keep.txt").write_text("ok")
    (watched / "skip.log").write_text("log")
    cache = watched / "__pycache__"
    cache.mkdir()
    (cache / "cached.pyc").write_text("cache")

    snapshots = scan_paths(
        [str(watched)],
        exclude=["*.log", "__pycache__"],
    )

    assert any("keep.txt" in s.path for s in snapshots)
    assert not any(s.path.endswith("skip.log") for s in snapshots)
    assert not any("__pycache__" in s.path for s in snapshots)


def test_scan_paths_deduplicates_overlapping_roots(tmp_path):
    """Same resolved file must not appear twice when roots overlap."""
    root = tmp_path / "watched"
    subdir = root / "sub"
    subdir.mkdir(parents=True)
    nested = subdir / "demo.txt"
    nested.write_text("demo\n", encoding="utf-8")

    snapshots = scan_paths([str(root), str(subdir)], exclude=[])

    assert len(snapshots) == 1
    assert snapshots[0].path == str(nested.resolve())
