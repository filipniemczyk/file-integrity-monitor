"""Load and validate YAML configuration."""

from pathlib import Path
from typing import Any

import yaml

from fim.exceptions import ConfigError
from fim.monitor_paths import normalize_exclude_rules
from fim.severity import normalize_severity_level

_DEFAULT_EXCLUDE = ["*.log", "*.tmp", "__pycache__", ".git"]
_ALERT_LEVELS = ("critical", "high", "medium", "low")
_DEFAULT_DB_PATH = "fim.db"
_DEFAULT_HASH_ALGORITHM = "sha256"
_VALID_RULE_LEVELS = {"critical", "high", "medium", "low"}


def load_config(path: str) -> dict[str, Any]:
    """
    Load YAML file and return configuration with defaults applied.

    Raises:
        ConfigError: If the file is missing, invalid, or required fields are absent.
    """
    config_path = Path(path)

    if not config_path.exists():
        raise ConfigError(f"Configuration file does not exist: {path}")

    if not config_path.is_file():
        raise ConfigError(f"Path is not a file: {path}")

    try:
        with open(config_path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(f"YAML parsing error: {e}") from e

    if not isinstance(raw, dict):
        raise ConfigError("Configuration file must be a YAML mapping.")

    if "monitor" not in raw:
        raise ConfigError("Missing 'monitor' section in configuration.")

    monitor = raw["monitor"]
    if not isinstance(monitor, dict):
        raise ConfigError("'monitor' section must be a mapping.")

    if "paths" not in monitor:
        raise ConfigError("Missing 'monitor.paths' in configuration.")

    if not isinstance(monitor["paths"], list):
        raise ConfigError("'monitor.paths' must be a list of paths.")

    if not monitor["paths"]:
        raise ConfigError("'monitor.paths' cannot be empty.")

    if "exclude" not in monitor or monitor["exclude"] is None:
        monitor["exclude"] = list(_DEFAULT_EXCLUDE)

    try:
        exclude_rules = normalize_exclude_rules(monitor["exclude"])
    except ValueError as error:
        raise ConfigError(str(error)) from error

    monitor["exclude"] = {
        "paths": list(exclude_rules.paths),
        "patterns": list(exclude_rules.patterns),
    }

    if "database" not in raw or not isinstance(raw.get("database"), dict):
        raw["database"] = {}

    if "path" not in raw["database"] or not raw["database"]["path"]:
        raw["database"]["path"] = _DEFAULT_DB_PATH

    if "hash" not in raw or not isinstance(raw.get("hash"), dict):
        raw["hash"] = {}

    if "algorithm" not in raw["hash"] or not raw["hash"]["algorithm"]:
        raw["hash"]["algorithm"] = _DEFAULT_HASH_ALGORITHM

    _apply_alerts_config(raw)
    _apply_severity_config(raw)

    return raw


def _apply_alerts_config(raw: dict[str, Any]) -> None:
    """Map alerts.<level> paths to severity.rules for path-based severity."""
    if "alerts" not in raw:
        return

    alerts = raw["alerts"]
    if not isinstance(alerts, dict):
        raise ConfigError("'alerts' section must be a mapping.")

    for level_name in alerts:
        if str(level_name).lower() not in _ALERT_LEVELS:
            raise ConfigError(f"Unsupported alerts level: {level_name}")

    normalized_rules: dict[str, list[str]] = {}
    for level_name in _ALERT_LEVELS:
        patterns = alerts.get(level_name, [])
        if patterns is None:
            patterns = []
        if not isinstance(patterns, list):
            raise ConfigError(f"alerts.{level_name} must be a list of paths.")
        normalized_rules[normalize_severity_level(level_name)] = [
            str(pattern) for pattern in patterns
        ]

    severity = raw.setdefault("severity", {})
    if not isinstance(severity, dict):
        raise ConfigError("'severity' section must be a mapping when used with alerts.")

    if "default" not in severity or not severity["default"]:
        severity["default"] = "low"

    severity["rules"] = normalized_rules


def _apply_severity_config(raw: dict[str, Any]) -> None:
    if "severity" not in raw:
        return

    severity = raw["severity"]
    if not isinstance(severity, dict):
        raise ConfigError("'severity' section must be a mapping.")

    default = severity.get("default", "low")
    try:
        severity["default"] = normalize_severity_level(str(default))
    except ValueError as error:
        raise ConfigError(f"Invalid severity.default: {default}") from error

    rules = severity.get("rules", {})
    if rules is None:
        rules = {}
    if not isinstance(rules, dict):
        raise ConfigError("'severity.rules' must be a mapping.")

    normalized_rules: dict[str, list[str]] = {}
    for level_name, patterns in rules.items():
        level_key = str(level_name).lower()
        if level_key not in _VALID_RULE_LEVELS:
            raise ConfigError(f"Unsupported severity rules level: {level_name}")

        if not isinstance(patterns, list):
            raise ConfigError(f"severity.rules.{level_name} must be a list.")

        normalized_rules[normalize_severity_level(level_key)] = [str(pattern) for pattern in patterns]

    severity["rules"] = normalized_rules
