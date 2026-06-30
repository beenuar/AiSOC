"""
AiSOC CLI — scaffold, validate, publish, and operate.

Commands:
  aisoc plugin new <name>           Scaffold a typed plugin from disk templates
  aisoc plugin scaffold <name>      Alias for `plugin new` (backwards compat)
  aisoc plugin validate [path]      Validate plugin.yaml against JSON Schema
  aisoc plugin publish [path]       Sign with Ed25519 key + POST to AiSOC API
  aisoc detection validate <file>   Validate Sigma rule syntax
  aisoc keygen                      Generate an Ed25519 signing key pair
  aisoc serve [--detach]            Start the dev stack via docker compose
  aisoc db upgrade                  Run database migrations against the dev stack
  aisoc mcp serve [--transport]     Launch the MCP server for IDE assistants
  aisoc mcp install --host <h>      Wire AiSOC into Claude / Cursor / Continue
  aisoc submit <file>               POST an alert/event JSON payload to the AiSOC API
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
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


# ── Repo / compose helpers ────────────────────────────────────────────────────

def _find_repo_root(start: Path | None = None) -> Path:
    """Walk up from ``start`` (default: cwd) looking for a docker-compose root.

    A repo root here is any directory containing either ``docker-compose.yml``
    or ``infra/compose/docker-compose.dev.yml``. Falls back to the current
    working directory if no match is found, so the underlying
    ``docker compose`` invocation can still produce a sensible error message.
    """
    current = (start or Path.cwd()).resolve()
    for candidate in [current, *current.parents]:
        if (candidate / "docker-compose.yml").exists() or (
            candidate / "infra" / "compose" / "docker-compose.dev.yml"
        ).exists() or (candidate / "docker-compose.dev.yml").exists():
            return candidate
    return current


def _compose_file_arg(repo_root: Path) -> list[str]:
    """Pick the right ``-f`` arg for docker compose.

    Prefers ``infra/compose/docker-compose.dev.yml`` (the dev-aliased entry
    point in the post-tidy layout) when present, then the legacy root path,
    otherwise falls back to the base ``docker-compose.yml``.
    """
    new_dev = repo_root / "infra" / "compose" / "docker-compose.dev.yml"
    if new_dev.exists():
        return ["-f", str(new_dev)]
    legacy_dev = repo_root / "docker-compose.dev.yml"
    if legacy_dev.exists():
        return ["-f", str(legacy_dev)]
    return ["-f", str(repo_root / "docker-compose.yml")]


def _require_docker() -> None:
    """Hard-fail with a friendly message if docker is not on PATH."""
    if shutil.which("docker") is None:
        console.print(
            "[red bold]docker not found on PATH[/red bold]\n\n"
            "Install Docker Desktop or Docker Engine, then retry. See:\n"
            "  https://docs.docker.com/engine/install/"
        )
        sys.exit(1)


# ── serve command ─────────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--detach/--no-detach",
    "detach",
    default=True,
    show_default=True,
    help="Run docker compose up in detached mode (default: detached).",
)
@click.option(
    "--build/--no-build",
    "build",
    default=False,
    show_default=True,
    help="Force a rebuild of changed images before starting.",
)
def serve(detach: bool, build: bool) -> None:
    """Start the AiSOC dev stack via docker compose.

    Resolves the closest docker-compose root walking up from the cwd, prefers
    ``infra/compose/docker-compose.dev.yml`` if it exists (legacy root path is
    still honoured), and shells out to ``docker compose -f <file> up``. Treat
    this as the founder-style one-liner equivalent of the documented
    ``docker compose up -d``.
    """
    _require_docker()
    repo_root = _find_repo_root()
    cmd = ["docker", "compose", *_compose_file_arg(repo_root), "up"]
    if detach:
        cmd.append("-d")
    if build:
        cmd.append("--build")

    console.print(
        Panel(
            f"[bold]cwd:[/bold] {repo_root}\n"
            f"[bold]cmd:[/bold] {' '.join(cmd)}",
            title="[bold green]aisoc serve[/bold green]",
        )
    )
    result = subprocess.run(cmd, cwd=str(repo_root))
    if result.returncode != 0:
        sys.exit(result.returncode)


# ── db group ──────────────────────────────────────────────────────────────────

@cli.group()
def db() -> None:
    """Database lifecycle commands."""


@db.command("upgrade")
@click.option(
    "--service",
    default="api",
    show_default=True,
    help="docker compose service that owns the migrations.",
)
def db_upgrade(service: str) -> None:
    """Apply pending SQL migrations against the running dev stack.

    Delegates to ``docker compose exec <service> python -m
    app.scripts.run_migrations``, which is the custom forward-only migration
    runner under ``services/api``. Requires the stack to already be up
    (``aisoc serve``).
    """
    _require_docker()
    repo_root = _find_repo_root()
    cmd = [
        "docker",
        "compose",
        *_compose_file_arg(repo_root),
        "exec",
        "-T",
        service,
        "python",
        "-m",
        "app.scripts.run_migrations",
    ]
    console.print(
        Panel(
            f"[bold]cwd:[/bold] {repo_root}\n"
            f"[bold]cmd:[/bold] {' '.join(cmd)}",
            title="[bold green]aisoc db upgrade[/bold green]",
        )
    )
    result = subprocess.run(cmd, cwd=str(repo_root))
    if result.returncode != 0:
        console.print(
            "[yellow]If the stack is not up yet, run [bold]aisoc serve[/bold] "
            "first, then re-run this command.[/yellow]"
        )
        sys.exit(result.returncode)


# ── mcp group ─────────────────────────────────────────────────────────────────

@cli.group()
def mcp() -> None:
    """Model Context Protocol (MCP) commands."""


def _resolve_mcp_entry(repo_root: Path) -> tuple[list[str], str] | None:
    """Return (argv, label) for invoking the local MCP build, or None.

    Looks for a built ``services/mcp/dist/index.js`` next to ``package.json``.
    Returns None if the build artifact is missing, so callers can fall back to
    ``npx @aisoc/mcp``.
    """
    dist = repo_root / "services" / "mcp" / "dist" / "index.js"
    if dist.exists():
        node = shutil.which("node") or "node"
        return [node, str(dist)], f"node {dist.relative_to(repo_root)}"
    return None


def _mcp_argv(repo_root: Path, subcommand: str, extra: list[str]) -> tuple[list[str], str]:
    """Build the argv for an MCP subcommand, preferring local dist over npx."""
    local = _resolve_mcp_entry(repo_root)
    if local is not None:
        argv, label = local
        return [*argv, subcommand, *extra], f"{label} {subcommand} {' '.join(extra)}".strip()

    npx = shutil.which("npx") or "npx"
    return (
        [npx, "@aisoc/mcp", subcommand, *extra],
        f"npx @aisoc/mcp {subcommand} {' '.join(extra)}".strip(),
    )


@mcp.command("serve")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "http"]),
    default="stdio",
    show_default=True,
    help="MCP transport (stdio for IDE assistants, http for remote agents).",
)
@click.option(
    "--port",
    type=int,
    default=None,
    help="Port for the http transport (ignored when --transport=stdio).",
)
def mcp_serve(transport: str, port: int | None) -> None:
    """Launch the MCP server that exposes AiSOC to IDE assistants.

    Prefers the locally built ``services/mcp/dist/index.js`` (from
    ``pnpm --filter @aisoc/mcp build``). Falls back to ``npx @aisoc/mcp``
    when no local build is available.
    """
    repo_root = _find_repo_root()
    extra: list[str] = ["--transport", transport]
    if transport == "http" and port is not None:
        extra.extend(["--port", str(port)])

    argv, label = _mcp_argv(repo_root, "serve", extra)
    console.print(
        Panel(
            f"[bold]cwd:[/bold] {repo_root}\n"
            f"[bold]cmd:[/bold] {label}",
            title="[bold green]aisoc mcp serve[/bold green]",
        )
    )
    # Replace this process with node so stdio is fully transparent — required
    # for IDE assistants that pipe MCP frames over stdin/stdout.
    os.execvp(argv[0], argv)


@mcp.command("install")
@click.option(
    "--host",
    type=click.Choice(["claude", "cursor", "continue", "cody"]),
    required=True,
    help="IDE assistant to wire AiSOC into.",
)
def mcp_install(host: str) -> None:
    """Register the AiSOC MCP server with the given IDE assistant.

    Thin wrapper over ``aisoc-mcp install --host <host>`` that picks the local
    dist build when available and falls back to ``npx @aisoc/mcp`` otherwise.
    """
    repo_root = _find_repo_root()
    argv, label = _mcp_argv(repo_root, "install", ["--host", host])

    console.print(
        Panel(
            f"[bold]cwd:[/bold] {repo_root}\n"
            f"[bold]cmd:[/bold] {label}",
            title="[bold green]aisoc mcp install[/bold green]",
        )
    )
    result = subprocess.run(argv, cwd=str(repo_root))
    if result.returncode != 0:
        sys.exit(result.returncode)


# ── submit command ───────────────────────────────────────────────────────────
#
# `aisoc submit <file>` lets the founder-flow demo and any operator land a
# canned OCSF/Okta-shaped payload on the local dev stack in one command.
# It POSTs to the API's direct-write submit endpoint, which synthesises an
# Alert row from the event batch and writes it straight to the database — so
# the result is visible in the web console within the same second.
#
#     POST {api_url}/api/v1/alerts/submit
#     Authorization: Bearer <token>          # optional in dev mode
#     { connector_id, connector_type, source_format, events: [...] }
#
# This deliberately bypasses the Kafka detect/correlate/fuse pipeline (which
# fresh clones don't run by default) so the documented "alert in seconds"
# quickstart promise actually holds.
#
# The fixture format is intentionally forgiving — the file may be:
#   * { "events": [...], "connector_id": ..., "connector_type": ..., "source_format": ... }
#   * a bare JSON list of event dicts
#   * a single event dict (auto-wrapped)
# Any keys present in a dict-shaped fixture override the matching CLI flags.
#
# Backward compatibility: pre-W3 versions of this command POSTed to the Go
# ingest service at port 8081 with an ``X-Tenant-ID`` header. We keep the
# ``--ingest-url`` flag and ``AISOC_INGEST_URL`` env var as deprecated aliases
# for ``--api-url`` / ``AISOC_API_URL`` so existing demo scripts and the v1.0
# video voiceover keep working. The tenant id, when not derivable from the
# bearer token (dev mode bypass), comes from ``--tenant-id`` /
# ``AISOC_TENANT_ID`` and is still echoed in the request panel.

_DEFAULT_API_URL = "http://127.0.0.1:8000"
_DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"
_DEFAULT_CONNECTOR_ID = "aisoc-cli-submit"
_DEFAULT_CONNECTOR_TYPE = "okta_system_log"
_DEFAULT_SOURCE_FORMAT = "json"


def _coerce_events(payload: Any) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Normalize a parsed JSON payload into (events, fixture_overrides).

    Returns the event list plus any connector_id / connector_type /
    source_format overrides that a dict-shaped fixture wants to pin.
    """
    overrides: dict[str, str] = {}
    if isinstance(payload, list):
        events = payload
    elif isinstance(payload, dict):
        if "events" in payload and isinstance(payload["events"], list):
            events = payload["events"]
            for key in ("connector_id", "connector_type", "source_format"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    overrides[key] = value
        else:
            events = [payload]
    else:
        raise click.ClickException(
            "Payload must be a JSON object, a list of events, "
            "or an object with an 'events' list."
        )

    cleaned: list[dict[str, Any]] = []
    for idx, event in enumerate(events):
        if not isinstance(event, dict):
            raise click.ClickException(
                f"Event at index {idx} is not a JSON object (got {type(event).__name__})."
            )
        cleaned.append(event)

    if not cleaned:
        raise click.ClickException("No events to submit — the payload is empty.")

    return cleaned, overrides


def _resolve_api_url(api_url: str, ingest_url: str | None) -> str:
    """Pick the effective API base URL, honouring deprecated `--ingest-url`.

    Precedence (highest first):
      1. ``--ingest-url`` / ``AISOC_INGEST_URL`` (deprecated, prints a warning)
      2. ``--api-url`` / ``AISOC_API_URL``
      3. default ``http://127.0.0.1:8000``
    """
    if ingest_url:
        console.print(
            "[yellow]--ingest-url / AISOC_INGEST_URL is deprecated; "
            "use --api-url / AISOC_API_URL instead.[/yellow]"
        )
        return ingest_url
    return api_url


@cli.command()
@click.argument(
    "file",
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
)
@click.option(
    "--api-url",
    envvar="AISOC_API_URL",
    default=_DEFAULT_API_URL,
    show_default=True,
    help="Base URL for the AiSOC API (e.g. http://127.0.0.1:8000).",
)
@click.option(
    "--ingest-url",
    envvar="AISOC_INGEST_URL",
    default=None,
    show_default=False,
    help="DEPRECATED alias for --api-url; overrides --api-url when set.",
)
@click.option(
    "--api-key",
    envvar="AISOC_API_KEY",
    default=None,
    show_default=False,
    help=(
        "AiSOC bearer token. Optional in dev mode (the API resolves an "
        "unauthenticated request to the demo tenant)."
    ),
)
@click.option(
    "--tenant-id",
    envvar="AISOC_TENANT_ID",
    default=_DEFAULT_TENANT_ID,
    show_default=True,
    help="Tenant UUID — informational; the API derives tenant from the bearer token.",
)
@click.option(
    "--connector-id",
    default=_DEFAULT_CONNECTOR_ID,
    show_default=True,
    help="connector_id field on the synthesised alert.",
)
@click.option(
    "--connector-type",
    default=_DEFAULT_CONNECTOR_TYPE,
    show_default=True,
    help="connector_type field — used for routing and tag inference (e.g. okta_system_log).",
)
@click.option(
    "--source-format",
    default=_DEFAULT_SOURCE_FORMAT,
    show_default=True,
    help="source_format hint, echoed onto the alert for downstream parsers.",
)
@click.option(
    "--timeout",
    type=float,
    default=30.0,
    show_default=True,
    help="HTTP timeout in seconds.",
)
def submit(
    file: Path,
    api_url: str,
    ingest_url: str | None,
    api_key: str | None,
    tenant_id: str,
    connector_id: str,
    connector_type: str,
    source_format: str,
    timeout: float,
) -> None:
    """Submit a JSON alert/event payload to the AiSOC API.

    Reads ``FILE``, normalises it into the submit envelope, and POSTs to
    ``{api_url}/api/v1/alerts/submit``. The API synthesises one ``Alert`` row
    from the batch and writes it directly to the database, so the result is
    visible in ``GET /api/v1/alerts`` and the web console within the same
    second — bypassing the Kafka pipeline that fresh clones don't run.

    Used by the quickstart video script to drop a lateral-movement alert
    into the stack in one command.
    """
    try:
        raw = file.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - click handles `exists=True`
        raise click.ClickException(f"Could not read {file}: {exc}") from exc

    # Strip a leading BOM, which `json.loads` otherwise refuses.
    if raw.startswith("\ufeff"):
        raw = raw.lstrip("\ufeff")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"{file} is not valid JSON: {exc}") from exc

    events, overrides = _coerce_events(payload)
    connector_id = overrides.get("connector_id", connector_id)
    connector_type = overrides.get("connector_type", connector_type)
    source_format = overrides.get("source_format", source_format)

    effective_url = _resolve_api_url(api_url, ingest_url)
    url = f"{effective_url.rstrip('/')}/api/v1/alerts/submit"
    body = {
        "connector_id": connector_id,
        "connector_type": connector_type,
        "source_format": source_format,
        "events": events,
    }

    console.print(
        Panel(
            f"[bold]file:[/bold] {file}\n"
            f"[bold]url:[/bold] {url}\n"
            f"[bold]tenant:[/bold] {tenant_id}\n"
            f"[bold]connector_id:[/bold] {connector_id}\n"
            f"[bold]connector_type:[/bold] {connector_type}\n"
            f"[bold]source_format:[/bold] {source_format}\n"
            f"[bold]events:[/bold] {len(events)}",
            title="[bold green]aisoc submit[/bold green]",
        )
    )

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        console.print(
            f"[red]AiSOC API unreachable at {url}:[/red] {exc}\n"
            "Is the dev stack running? Try [bold]aisoc serve[/bold] first."
        )
        sys.exit(1)

    if resp.status_code >= 400:
        console.print(
            f"[red]AiSOC API returned {resp.status_code}:[/red] {resp.text[:500]}"
        )
        sys.exit(1)

    try:
        data = resp.json()
    except ValueError:
        console.print(
            f"[red]AiSOC API returned non-JSON ({resp.status_code}):[/red] "
            f"{resp.text[:200]}"
        )
        sys.exit(1)

    alert_id = data.get("id", "-")
    alert_severity = data.get("severity", "-")
    alert_title = data.get("title", "-")
    alert_tenant = data.get("tenant_id", "-")

    console.print(
        Panel(
            f"[bold]status:[/bold] {resp.status_code}\n"
            f"[bold]alert_id:[/bold] {alert_id}\n"
            f"[bold]tenant_id:[/bold] {alert_tenant}\n"
            f"[bold]severity:[/bold] {alert_severity}\n"
            f"[bold]title:[/bold] {alert_title}",
            title="[bold green]alert created[/bold green]",
        )
    )


if __name__ == "__main__":
    cli()
