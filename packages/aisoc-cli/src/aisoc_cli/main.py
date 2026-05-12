"""
AiSOC CLI — scaffold, validate, and publish plugins and detections.

Commands:
  aisoc plugin new <name>           Scaffold a typed plugin from disk templates
  aisoc plugin scaffold <name>      Alias for `plugin new` (backwards compat)
  aisoc plugin validate [path]      Validate plugin.yaml against JSON Schema
  aisoc plugin publish [path]       Sign with Ed25519 key + POST to AiSOC API
  aisoc detection validate <file>   Validate Sigma rule syntax
  aisoc keygen                      Generate an Ed25519 signing key pair
"""
from __future__ import annotations

import base64
import json
import sys
from importlib import resources
from pathlib import Path
from string import Template
from typing import Any

import click
import httpx
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from jsonschema import ValidationError, validate
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

PLUGIN_TYPES = ("enricher", "connector", "responder", "detection", "widget")
DEFAULT_AUTHOR = "Your Name <you@example.com>"

# ── Schemas ───────────────────────────────────────────────────────────────────

PLUGIN_MANIFEST_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["id", "name", "version", "plugin_type", "description", "author"],
    "properties": {
        "id": {"type": "string", "pattern": "^[a-z0-9_-]+$"},
        "name": {"type": "string"},
        "version": {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"},
        "plugin_type": {
            "type": "string",
            "enum": ["enricher", "connector", "responder", "detection", "widget"],
        },
        "description": {"type": "string"},
        "author": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "min_aisoc_version": {"type": "string"},
        "config_schema": {"type": "object"},
        "entry_point": {"type": "string"},
        "runtime": {"type": "string", "enum": ["python", "oci"]},
    },
    "additionalProperties": True,
}

# ── Template loading ──────────────────────────────────────────────────────────


def _templates_root() -> Path:
    """Return the on-disk root of the bundled templates directory.

    Uses ``importlib.resources`` so this works whether the package is run from
    a source checkout or installed into site-packages.
    """
    pkg_files = resources.files("aisoc_cli") / "templates"
    return Path(str(pkg_files))


def _render_templates(plugin_type: str, target: Path, substitutions: dict[str, str]) -> list[Path]:
    """Render every ``*.tmpl`` file under ``templates/<plugin_type>/`` into ``target``.

    The directory layout under the template root is preserved verbatim. Each
    ``foo.ext.tmpl`` becomes ``foo.ext`` in the output, with ``$slug``,
    ``$name``, and ``$author`` substituted via ``string.Template`` (so we never
    fight Python ``.format()`` over real curly braces in YAML/JSON).
    """
    root = _templates_root() / plugin_type
    if not root.is_dir():
        raise click.ClickException(
            f"No templates bundled for plugin_type='{plugin_type}'. "
            f"Expected directory: {root}"
        )

    written: list[Path] = []
    for src in sorted(root.rglob("*.tmpl")):
        rel = src.relative_to(root)
        # Strip the trailing ".tmpl" suffix from the filename only.
        out_rel = rel.with_name(rel.name[: -len(".tmpl")])
        out_path = target / out_rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        rendered = Template(src.read_text()).safe_substitute(substitutions)
        out_path.write_text(rendered)
        written.append(out_path)
    return written


# ── CLI root ──────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(package_name="aisoc-cli")
def cli() -> None:
    """AiSOC Developer CLI — build, validate, and publish plugins & detections."""


# ── plugin group ──────────────────────────────────────────────────────────────

@cli.group()
def plugin() -> None:
    """Plugin management commands."""


def _scaffold_plugin(name: str, output_dir: str, plugin_type: str, author: str) -> Path:
    """Shared implementation for ``plugin new`` and ``plugin scaffold``."""
    if plugin_type not in PLUGIN_TYPES:
        raise click.ClickException(
            f"Unknown plugin_type='{plugin_type}'. Expected one of: {', '.join(PLUGIN_TYPES)}"
        )

    slug = name.lower().replace(" ", "-").replace("_", "-")
    out = Path(output_dir) / slug
    if out.exists():
        console.print(f"[red]Directory already exists: {out}[/red]")
        sys.exit(1)
    out.mkdir(parents=True)

    substitutions = {"slug": slug, "name": name, "author": author}
    written = _render_templates(plugin_type, out, substitutions)

    files_listing = "\n".join(f"  • {p}" for p in written)
    console.print(
        Panel(
            f"[green]{plugin_type.capitalize()} plugin scaffolded at[/green] [bold]{out}[/bold]\n\n"
            f"Files created:\n{files_listing}\n\n"
            f"Next steps:\n"
            f"  1. Edit [bold]{out}/plugin.yaml[/bold] to fill in metadata\n"
            f"  2. Implement the entry point referenced by [bold]plugin.yaml[/bold]\n"
            f"  3. Run [bold]aisoc plugin validate {out}[/bold] to check",
            title="[bold green]Scaffold complete[/bold green]",
        )
    )
    return out


@plugin.command("new")
@click.argument("name")
@click.option("--output-dir", "-o", default=".", help="Directory to create plugin in")
@click.option(
    "--type",
    "plugin_type",
    default="enricher",
    type=click.Choice(list(PLUGIN_TYPES)),
    help="Plugin type",
)
@click.option(
    "--author",
    default=DEFAULT_AUTHOR,
    show_default=True,
    help="Author string written into plugin.yaml",
)
def plugin_new(name: str, output_dir: str, plugin_type: str, author: str) -> None:
    """Scaffold a new plugin from the bundled templates for its type."""
    _scaffold_plugin(name, output_dir, plugin_type, author)


@plugin.command("scaffold")
@click.argument("name")
@click.option("--output-dir", "-o", default=".", help="Directory to create plugin in")
@click.option(
    "--type",
    "plugin_type",
    default="enricher",
    type=click.Choice(list(PLUGIN_TYPES)),
    help="Plugin type",
)
@click.option(
    "--author",
    default=DEFAULT_AUTHOR,
    show_default=True,
    help="Author string written into plugin.yaml",
)
def plugin_scaffold(name: str, output_dir: str, plugin_type: str, author: str) -> None:
    """Alias for ``aisoc plugin new`` (kept for backwards compatibility)."""
    _scaffold_plugin(name, output_dir, plugin_type, author)


@plugin.command("validate")
@click.argument("path", default=".", type=click.Path(exists=True))
def plugin_validate(path: str) -> None:
    """Validate plugin.yaml against the AiSOC manifest schema."""
    plugin_dir = Path(path)
    manifest_file = plugin_dir / "plugin.yaml" if plugin_dir.is_dir() else plugin_dir

    if not manifest_file.exists():
        console.print(f"[red]plugin.yaml not found at {manifest_file}[/red]")
        sys.exit(1)

    with manifest_file.open() as f:
        manifest = yaml.safe_load(f)

    errors: list[str] = []
    try:
        validate(manifest, PLUGIN_MANIFEST_SCHEMA)
    except ValidationError as exc:
        errors.append(str(exc.message))

    # Check entry point exists
    if plugin_dir.is_dir():
        entry = manifest.get("entry_point", "plugin.py")
        if not (plugin_dir / entry).exists():
            errors.append(f"entry_point '{entry}' not found in plugin directory")

    if errors:
        console.print("[red bold]Validation FAILED[/red bold]")
        for err in errors:
            console.print(f"  [red]-[/red] {err}")
        sys.exit(1)
    else:
        console.print(f"[green bold]Validation passed[/green bold] — {manifest_file}")
        _print_manifest_table(manifest)


@plugin.command("publish")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--api-url",
    envvar="AISOC_API_URL",
    default="http://localhost:8000",
    show_default=True,
    help="AiSOC API base URL",
)
@click.option(
    "--api-key",
    envvar="AISOC_API_KEY",
    required=True,
    help="AiSOC API key (or set AISOC_API_KEY env var)",
)
@click.option(
    "--private-key",
    envvar="AISOC_SIGNING_KEY",
    default="~/.aisoc/signing.key",
    show_default=True,
    help="Path to Ed25519 private key PEM file",
)
def plugin_publish(path: str, api_url: str, api_key: str, private_key: str) -> None:
    """Sign and publish a plugin to the AiSOC community marketplace."""
    import io
    import tarfile

    plugin_dir = Path(path)
    manifest_file = plugin_dir / "plugin.yaml"
    if not manifest_file.exists():
        console.print(f"[red]plugin.yaml not found in {plugin_dir}[/red]")
        sys.exit(1)

    # Validate first
    with manifest_file.open() as f:
        manifest = yaml.safe_load(f)
    try:
        validate(manifest, PLUGIN_MANIFEST_SCHEMA)
    except ValidationError as exc:
        console.print(f"[red]Manifest validation failed:[/red] {exc.message}")
        sys.exit(1)

    # Load signing key
    key_path = Path(private_key).expanduser()
    if not key_path.exists():
        console.print(f"[red]Signing key not found: {key_path}[/red]")
        console.print("Run [bold]aisoc keygen[/bold] to generate a key pair.")
        sys.exit(1)

    private_key_obj = _load_private_key(key_path)

    # Create tarball in memory
    console.print(f"Packaging [bold]{plugin_dir}[/bold]...")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(str(plugin_dir), arcname=manifest["id"])
    tarball = buf.getvalue()

    # Sign the tarball
    signature = private_key_obj.sign(tarball)
    sig_b64 = base64.b64encode(signature).decode()

    # POST to API
    console.print(f"Publishing to [bold]{api_url}[/bold]...")
    with httpx.Client(base_url=api_url, headers={"Authorization": f"Bearer {api_key}"}) as client:
        resp = client.post(
            "/api/v1/plugins/publish",
            content=tarball,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Plugin-Signature": sig_b64,
                "X-Plugin-Manifest": json.dumps(manifest),
            },
            timeout=60,
        )
        if resp.status_code not in (200, 201):
            console.print(f"[red]Publish failed ({resp.status_code}):[/red] {resp.text}")
            sys.exit(1)
        data = resp.json()

    console.print(
        Panel(
            f"[green]Plugin submitted for review[/green]\n\n"
            f"  ID:     {data.get('id', 'unknown')}\n"
            f"  Status: {data.get('status', 'pending')}\n\n"
            f"An admin will review your submission. You'll be notified when approved.",
            title="[bold green]Published[/bold green]",
        )
    )


# ── detection group ───────────────────────────────────────────────────────────

@cli.group()
def detection() -> None:
    """Detection rule management commands."""


@detection.command("validate")
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--sigma-cli",
    default="sigma",
    help="Path to sigma-cli binary (default: sigma on PATH)",
)
def detection_validate(file: str, sigma_cli: str) -> None:
    """Validate a Sigma detection rule file using sigma-cli."""
    import subprocess

    rule_path = Path(file)
    console.print(f"Validating [bold]{rule_path}[/bold]...")

    # Try sigma-cli first
    try:
        result = subprocess.run(
            [sigma_cli, "check", str(rule_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            console.print(f"[green bold]Valid Sigma rule[/green bold] — {rule_path}")
            if result.stdout:
                console.print(result.stdout)
        else:
            console.print("[red bold]Invalid Sigma rule[/red bold]")
            if result.stderr:
                console.print(result.stderr)
            if result.stdout:
                console.print(result.stdout)
            sys.exit(1)
    except FileNotFoundError:
        # Fall back to basic YAML + field validation
        console.print(
            f"[yellow]sigma-cli not found ('{sigma_cli}'), falling back to basic YAML validation[/yellow]"
        )
        _basic_sigma_validate(rule_path)


# ── keygen command ────────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--output-dir",
    default="~/.aisoc",
    show_default=True,
    help="Directory to store generated key files",
)
def keygen(output_dir: str) -> None:
    """Generate an Ed25519 signing key pair for plugin publishing."""
    out = Path(output_dir).expanduser()
    out.mkdir(parents=True, exist_ok=True)

    priv_path = out / "signing.key"
    pub_path = out / "signing.pub"

    if priv_path.exists():
        if not click.confirm(f"Key already exists at {priv_path}. Overwrite?"):
            console.print("Aborted.")
            return

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_pem)
    priv_path.chmod(0o600)
    pub_path.write_bytes(pub_pem)

    console.print(
        Panel(
            f"[green]Key pair generated[/green]\n\n"
            f"  Private key: [bold]{priv_path}[/bold] (keep secret!)\n"
            f"  Public key:  [bold]{pub_path}[/bold]\n\n"
            f"Register your public key with the AiSOC marketplace before publishing:\n"
            f"  [bold]aisoc plugin publish --private-key {priv_path} <plugin-dir>[/bold]",
            title="[bold green]Key Generation Complete[/bold green]",
        )
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_private_key(path: Path) -> Ed25519PrivateKey:
    pem_data = path.read_bytes()
    key = serialization.load_pem_private_key(pem_data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        console.print("[red]Key must be an Ed25519 private key[/red]")
        sys.exit(1)
    return key


def _print_manifest_table(manifest: dict[str, Any]) -> None:
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    for field in ["id", "name", "version", "plugin_type", "description", "author"]:
        table.add_row(field, str(manifest.get(field, "")))
    console.print(table)


def _basic_sigma_validate(rule_path: Path) -> None:
    """Minimal Sigma rule validation without sigma-cli."""
    required_fields = ["title", "id", "status", "description", "logsource", "detection"]
    with rule_path.open() as f:
        rule = yaml.safe_load(f)

    missing = [f for f in required_fields if f not in rule]
    if missing:
        console.print(f"[red bold]Missing required Sigma fields:[/red bold] {', '.join(missing)}")
        sys.exit(1)

    if "condition" not in rule.get("detection", {}):
        console.print("[red bold]detection.condition is required[/red bold]")
        sys.exit(1)

    console.print(f"[green bold]Basic Sigma validation passed[/green bold] — {rule_path}")
    console.print("[yellow]Install sigma-cli for full validation: pip install sigma-cli[/yellow]")


if __name__ == "__main__":
    cli()
