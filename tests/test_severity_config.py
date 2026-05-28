"""Tests for YAML-driven severity rules."""

import pytest

from fim.analyzer import calculate_severity
from fim.config import load_config
from fim.exceptions import ConfigError
from fim.models import EventType, Severity
from fim.severity import path_matches_pattern, severity_from_config


def _severity_config() -> dict:
    return {
        "severity": {
            "default": Severity.LOW,
            "rules": {
                Severity.CRITICAL: [
                    "/etc/shadow",
                    "/etc/sudoers",
                    "/root/.ssh/authorized_keys",
                ],
                Severity.HIGH: [
                    "/etc/passwd",
                    "/etc/group",
                    "/etc/ssh",
                    "/etc/systemd/system",
                ],
                Severity.MEDIUM: ["*.service", "*.conf", "*.sh"],
                Severity.LOW: ["./watched"],
            },
        }
    }


def test_path_matches_glob_sh():
    assert path_matches_pattern("/opt/scripts/backup.sh", "*.sh")


def test_path_matches_watched_prefix():
    assert path_matches_pattern("/home/kali/Projects/fim-project/watched/a.txt", "./watched")


def test_etc_shadow_is_critical():
    config = _severity_config()
    assert calculate_severity("/etc/shadow", EventType.MODIFIED, config) == Severity.CRITICAL


def test_sh_pattern_is_medium():
    config = _severity_config()
    path = "/var/www/deploy.sh"
    assert calculate_severity(path, EventType.CREATED, config) == Severity.MEDIUM


def test_watched_file_is_low():
    config = _severity_config()
    path = "/home/kali/Projects/fim-project/watched/a.txt"
    assert calculate_severity(path, EventType.MODIFIED, config) == Severity.LOW


def test_multiple_matches_use_highest_level():
    config = _severity_config()
    path = "/etc/shadow"
    assert severity_from_config(path, config) == Severity.CRITICAL

    path_both = "/etc/systemd/system/app.service"
    assert severity_from_config(path_both, config) == Severity.HIGH


def test_default_when_no_rule_matches():
    config = _severity_config()
    assert calculate_severity("/tmp/unknown.dat", EventType.MODIFIED, config) == Severity.LOW


def test_legacy_fallback_without_severity_config():
    assert calculate_severity("/tmp/random.txt", EventType.MODIFIED, None) == Severity.MEDIUM
    assert calculate_severity("/etc/shadow", EventType.MODIFIED, None) == Severity.CRITICAL


def test_load_config_parses_severity(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
monitor:
  paths:
    - ./watched
severity:
  default: medium
  rules:
    critical:
      - /etc/shadow
""".strip()
        + "\n",
        encoding="utf-8",
    )

    config = load_config(str(config_path))
    assert config["severity"]["default"] == Severity.MEDIUM
    assert config["severity"]["rules"][Severity.CRITICAL] == ["/etc/shadow"]
    assert isinstance(config["monitor"]["exclude"], dict)


def test_load_config_maps_alerts_to_severity(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
monitor:
  paths:
    - ./watched
alerts:
  critical:
    - /etc/shadow
  high:
    - /etc/passwd
  medium: []
  low:
    - ./watched
""".strip()
        + "\n",
        encoding="utf-8",
    )

    config = load_config(str(config_path))
    assert config["severity"]["rules"][Severity.CRITICAL] == ["/etc/shadow"]
    assert config["severity"]["rules"][Severity.HIGH] == ["/etc/passwd"]


def test_load_config_rejects_invalid_severity_level(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
monitor:
  paths:
    - ./watched
severity:
  default: urgent
""".strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError):
        load_config(str(config_path))
