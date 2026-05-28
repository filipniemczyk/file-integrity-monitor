"""Tests for config.security.yaml and alerts-driven severity."""

from pathlib import Path

from fim.config import load_config
from fim.models import Severity
from fim.severity import severity_from_config


def test_load_config_example_has_no_severity_rules(tmp_path: Path):
    project_root = Path(__file__).resolve().parents[1]
    config = load_config(str(project_root / "config.example.yaml"))

    assert "severity" not in config
    assert "alerts" not in config
    assert config["monitor"]["paths"] == ["./watched"]
    assert isinstance(config["monitor"]["exclude"], dict)
    assert "*.log" in config["monitor"]["exclude"]["patterns"]


def test_load_security_config_maps_alerts_to_severity():
    project_root = Path(__file__).resolve().parents[1]
    config = load_config(str(project_root / "config.security.yaml"))

    assert "/etc/shadow" in config["severity"]["rules"][Severity.CRITICAL]
    assert "/home/*/.bashrc" in config["severity"]["rules"][Severity.MEDIUM]
    assert "./watched" in config["severity"]["rules"][Severity.LOW]
    assert "/proc" in config["monitor"]["exclude"]["paths"]
    assert ".git" in config["monitor"]["exclude"]["patterns"]
    assert any("/home/*/" in path for path in config["monitor"]["paths"])
    assert severity_from_config("/etc/shadow", config) == Severity.CRITICAL
    assert severity_from_config("/etc/hosts", config) == Severity.MEDIUM
