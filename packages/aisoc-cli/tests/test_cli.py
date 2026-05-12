"""Tests for aisoc-cli commands."""
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
    assert manifest["plugin_type"] == "enricher"


def test_plugin_new_alias(runner, tmp_path):
    """``plugin new`` is the canonical name; ``plugin scaffold`` is the alias."""
    result = runner.invoke(cli, ["plugin", "new", "another-enricher", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "another-enricher" / "plugin.yaml").exists()


@pytest.mark.parametrize(
    "plugin_type,expected_files",
    [
        ("enricher", ["plugin.yaml", "plugin.py", "README.md"]),
        ("connector", ["plugin.yaml", "connector.py", "README.md"]),
        ("responder", ["plugin.yaml", "plugin.py", "README.md"]),
        ("detection", ["plugin.yaml", "rules/example.yaml", "README.md"]),
        ("widget", ["plugin.yaml", "widget.py", "README.md"]),
    ],
)
def test_plugin_new_per_type(runner, tmp_path, plugin_type, expected_files):
    """Every plugin type renders its full template tree with substitutions."""
    name = f"My {plugin_type.title()}"
    result = runner.invoke(
        cli,
        [
            "plugin",
            "new",
            name,
            "--type",
            plugin_type,
            "--output-dir",
            str(tmp_path),
            "--author",
            "Tester <tester@example.com>",
        ],
    )
    assert result.exit_code == 0, result.output

    slug = f"my-{plugin_type}"
    plugin_dir = tmp_path / slug
    for rel in expected_files:
        assert (plugin_dir / rel).exists(), f"{plugin_type} is missing {rel}"

    manifest = yaml.safe_load((plugin_dir / "plugin.yaml").read_text())
    assert manifest["id"] == slug
    assert manifest["name"] == name
    assert manifest["plugin_type"] == plugin_type
    assert manifest["author"] == "Tester <tester@example.com>"

    # No leftover $slug / $name placeholders should remain anywhere.
    for path in plugin_dir.rglob("*"):
        if path.is_file():
            text = path.read_text()
            assert "$slug" not in text, f"$slug not substituted in {path}"
            assert "$name" not in text, f"$name not substituted in {path}"
            assert "$author" not in text, f"$author not substituted in {path}"


def test_plugin_new_existing_dir_fails(runner, tmp_path):
    (tmp_path / "dup").mkdir()
    result = runner.invoke(
        cli, ["plugin", "new", "dup", "--output-dir", str(tmp_path)]
    )
    assert result.exit_code != 0
    assert "already exists" in result.output


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
