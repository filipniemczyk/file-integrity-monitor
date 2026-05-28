"""Path-based severity rules from configuration."""

import fnmatch
from pathlib import Path
from typing import Any

from fim.models import Severity

_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

_LEVEL_ALIASES = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    Severity.LOW.lower(): Severity.LOW,
    Severity.MEDIUM.lower(): Severity.MEDIUM,
    Severity.HIGH.lower(): Severity.HIGH,
    Severity.CRITICAL.lower(): Severity.CRITICAL,
}


def normalize_severity_level(level: str) -> str:
    """Convert config level name to Severity constant."""
    key = level.strip().lower()
    if key not in _LEVEL_ALIASES:
        raise ValueError(f"Unsupported severity level: {level}")
    return _LEVEL_ALIASES[key]


def max_severity(*levels: str) -> str:
    return max(levels, key=lambda level: _SEVERITY_RANK.get(level, 0))


def path_matches_pattern(path: str, pattern: str) -> bool:
    """Match absolute paths against exact paths or glob patterns."""
    normalized = path.replace("\\", "/")
    pattern_norm = pattern.replace("\\", "/").strip()

    if not pattern_norm:
        return False

    if any(char in pattern_norm for char in "*?[]"):
        if fnmatch.fnmatch(normalized, pattern_norm):
            return True
        if fnmatch.fnmatch(Path(normalized).name, pattern_norm):
            return True
        return any(fnmatch.fnmatch(part, pattern_norm) for part in normalized.split("/"))

    exact = pattern_norm.rstrip("/")
    if normalized == exact:
        return True
    if normalized.startswith(exact + "/"):
        return True

    relative = exact.lstrip("./")
    if relative and f"/{relative}/" in f"{normalized}/":
        return True
    if relative and normalized.endswith(f"/{relative}"):
        return True

    return False


def severity_from_config(path: str, config: dict[str, Any]) -> str:
    """Resolve severity for a path using severity.rules and severity.default."""
    severity_cfg = config["severity"]
    matched: list[str] = []

    for level, patterns in severity_cfg.get("rules", {}).items():
        for pattern in patterns:
            if path_matches_pattern(path, pattern):
                matched.append(level)

    if matched:
        return max_severity(*matched)

    return severity_cfg["default"]


def has_severity_config(config: dict[str, Any] | None) -> bool:
    return bool(config and isinstance(config.get("severity"), dict))
