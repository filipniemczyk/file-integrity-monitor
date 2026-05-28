"""Expand monitor paths and normalize exclude rules."""

from __future__ import annotations

import fnmatch
import glob
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console

_console = Console(stderr=True)


@dataclass(frozen=True)
class ExcludeRules:
    """Exclude rules: full path prefixes and name/glob patterns."""

    paths: tuple[str, ...]
    patterns: tuple[str, ...]


def _has_glob(path: str) -> bool:
    return any(char in path for char in "*?[]")


def expand_monitor_paths(paths: list[str]) -> list[str]:
    """
    Expand glob patterns in monitor paths (e.g. /home/*/.bashrc).

    Non-glob paths are returned unchanged. Missing glob matches log a warning.
    """
    expanded: list[str] = []

    for raw_path in paths:
        if not _has_glob(raw_path):
            expanded.append(raw_path)
            continue

        matches = sorted(glob.glob(raw_path))
        if not matches:
            _console.print(
                f"[yellow]No matches for monitor path pattern, skipping:[/yellow] {raw_path}"
            )
            continue

        expanded.extend(matches)

    return expanded


def normalize_exclude_rules(exclude: Any) -> ExcludeRules:
    """
    Normalize monitor.exclude to path prefixes and patterns.

    Supports legacy list format and mapping with paths/patterns keys.
    """
    if exclude is None:
        return ExcludeRules((), ())

    if isinstance(exclude, list):
        path_rules: list[str] = []
        pattern_rules: list[str] = []
        for item in exclude:
            rule = str(item).strip()
            if not rule:
                continue
            if rule.startswith("/") or rule.startswith("./"):
                path_rules.append(rule.rstrip("/"))
            else:
                pattern_rules.append(rule)
        return ExcludeRules(tuple(path_rules), tuple(pattern_rules))

    if isinstance(exclude, dict):
        raw_paths = exclude.get("paths", [])
        raw_patterns = exclude.get("patterns", [])
        if raw_paths is None:
            raw_paths = []
        if raw_patterns is None:
            raw_patterns = []
        if not isinstance(raw_paths, list):
            raise ValueError("'monitor.exclude.paths' must be a list.")
        if not isinstance(raw_patterns, list):
            raise ValueError("'monitor.exclude.patterns' must be a list.")
        return ExcludeRules(
            tuple(str(path).strip().rstrip("/") for path in raw_paths if str(path).strip()),
            tuple(str(pattern).strip() for pattern in raw_patterns if str(pattern).strip()),
        )

    raise ValueError("'monitor.exclude' must be a list or a mapping with paths/patterns.")


def is_excluded(path: Path, exclude: ExcludeRules) -> bool:
    """Return True when a path or any parent segment should be skipped."""
    resolved = path.resolve()
    path_posix = resolved.as_posix()

    for prefix in exclude.paths:
        prefix_norm = prefix.replace("\\", "/").rstrip("/")
        if path_posix == prefix_norm or path_posix.startswith(prefix_norm + "/"):
            return True

    for pattern in exclude.patterns:
        if _pattern_matches_path(resolved, pattern):
            return True

    return False


def _pattern_matches_path(path: Path, pattern: str) -> bool:
    pattern_norm = pattern.replace("\\", "/")
    path_posix = path.as_posix()
    name = path.name

    if "/" in pattern_norm:
        if fnmatch.fnmatch(path_posix, pattern_norm):
            return True
        return fnmatch.fnmatch(name, pattern_norm)

    if fnmatch.fnmatch(name, pattern_norm):
        return True

    return any(fnmatch.fnmatch(part, pattern_norm) for part in path.parts)
