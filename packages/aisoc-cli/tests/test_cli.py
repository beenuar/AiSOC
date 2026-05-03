"""Tests for aisoc-cli commands."""
import json
import os
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from aisoc_cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


def test_plugin_scaffold(runner, tmp_path):
    result = runner.invoke(cli, ["plugin", "scaffold", "test-enricher", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0
    plugin_dir = tmp_path / "test-enricher"
    assert (plugin_dir / "plugin.yaml").exists()
    assert (plugin_dir / "plugin.py").exists()
    manifest = yaml.safe_load((plugin_dir / "plugin.yaml").read_text())
    assert manifest["id"] == "test-enricher"


def test_plugin_validate_valid(runner, tmp_path):
    plugin_dir = tmp_path / "my-plugin"
    plugin_dir.mkdir()
    manifest = {
        "id": "my-plugin",
        "name": "My Plugin",
        "version": "0.1.0",
        "plugin_type": "enricher",
        "description": "Test plugin",
        "author": "Test Author",
    }
    (plugin_dir / "plugin.yaml").write_text(yaml.dump(manifest))
    (plugin_dir / "plugin.py").write_text("# plugin")
    result = runner.invoke(cli, ["plugin", "validate", str(plugin_dir)])
    assert result.exit_code == 0
    assert "Validation passed" in result.output


def test_plugin_validate_missing_field(runner, tmp_path):
    plugin_dir = tmp_path / "bad-plugin"
    plugin_dir.mkdir()
    manifest = {"id": "bad-plugin", "name": "Bad"}  # missing required fields
    (plugin_dir / "plugin.yaml").write_text(yaml.dump(manifest))
    result = runner.invoke(cli, ["plugin", "validate", str(plugin_dir)])
    assert result.exit_code != 0
    assert "FAILED" in result.output


def test_detection_validate_basic(runner, tmp_path):
    rule_file = tmp_path / "test.yaml"
    rule = {
        "title": "Test Rule",
        "id": "test-123",
        "status": "experimental",
        "description": "Test",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"selection": {"CommandLine|contains": "malware"}, "condition": "selection"},
    }
    rule_file.write_text(yaml.dump(rule))
    result = runner.invoke(cli, ["detection", "validate", str(rule_file), "--sigma-cli", "nonexistent-sigma"])
    assert result.exit_code == 0
    assert "passed" in result.output
