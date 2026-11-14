"""State that lives in a container's writable layer is state an image pull deletes.

The defect this exists to prevent
---------------------------------
Four directories held real operator state in the container's writable layer,
where `docker compose pull && up -d` destroys it. `rg "/opt/aisoc"` across
every compose file and Helm template returned zero hits, and `grafana`,
`prometheus` and `alertmanager` carried read-only config bind mounts and
nothing else.

What was lost on every recreate:

* **installed plugins** — `AISOC_PLUGINS_DIR` defaults to
  `/opt/aisoc/plugins` and `plugin_manager.py` extracts OCI plugin layers
  there. Also `/opt/aisoc/plugin-keys`, the trusted Ed25519 keys an operator
  installs to make signed third-party plugins loadable at all; same tree,
  same defect, and losing it turns every signed plugin into a refusal.
* **Grafana's `/var/lib/grafana`** — every dashboard an operator built in the
  UI, plus users, annotations and UI-created alert rules. This is the worst
  of the four because the work is irreplaceable and the loss is silent: the
  service comes back up with the provisioned dashboards and no sign that
  anything else ever existed.
* **Prometheus's `/prometheus`** — all metrics history, so every
  before-and-after comparison an operator was keeping.
* **Alertmanager's `/alertmanager`** — silences, so a deliberately muted
  alert starts firing again mid-incident.

The monitoring three sit behind `profiles: monitoring`, so this is not the
default surface — but an operator who enabled it got no warning, and
`--storage.path=/alertmanager` on the command line reads exactly like
persistence to anyone checking.

`tempo` already had `tempo_data`, which is the tell: persistence was
understood in this file and these four were simply missed.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "docker-compose.yml"
CHART = ROOT / "infra" / "helm" / "aisoc"


class _ComposeLoader(yaml.SafeLoader):
    """PyYAML plus Compose's `!reset` / `!override` merge tags."""


def _drop_tag(loader: yaml.Loader, node: yaml.Node) -> object:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


for _tag in ("!reset", "!override"):
    _ComposeLoader.add_constructor(_tag, _drop_tag)


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.load(BASE.read_text(encoding="utf-8"), Loader=_ComposeLoader)


def _mounts(service: dict) -> dict[str, str]:
    """container path -> source, for the long and short mount syntaxes."""
    out: dict[str, str] = {}
    for entry in service.get("volumes") or []:
        if isinstance(entry, str):
            parts = entry.split(":")
            if len(parts) >= 2:
                out[parts[1]] = parts[0]
        elif isinstance(entry, dict):
            out[entry.get("target", "")] = entry.get("source", "")
    return out


#: container path -> what an operator loses when it is not persisted.
AT_RISK = {
    "api": {
        "/opt/aisoc/plugins": "every installed plugin",
        "/opt/aisoc/plugin-keys": "every trusted plugin-signing key",
    },
    "grafana": {"/var/lib/grafana": "every dashboard, user and annotation created in the UI"},
    "prometheus": {"/prometheus": "all metrics history"},
    "alertmanager": {"/alertmanager": "every silence"},
}


@pytest.mark.parametrize("service", sorted(AT_RISK))
def test_state_directories_are_on_named_volumes(compose: dict, service: str) -> None:
    spec = compose["services"][service]
    mounts = _mounts(spec)
    declared = compose.get("volumes") or {}
    for path, loses in AT_RISK[service].items():
        assert path in mounts, f"{service} does not mount {path}, so `docker compose pull && up -d` destroys {loses}"
        source = mounts[path]
        assert not source.startswith("."), (
            f"{service}:{path} is a bind mount ({source}); it must be a named volume "
            "so `make down` keeps it and only `make clean` removes it"
        )
        assert source in declared, f"{source} is mounted but not declared under top-level `volumes:`"


def test_the_mounts_are_writable(compose: dict) -> None:
    """A `:ro` mount here would persist nothing and break the writer.

    The config mounts beside them are correctly read-only, which is exactly
    how a state mount gets the suffix copied onto it.
    """
    for service, paths in AT_RISK.items():
        for entry in compose["services"][service].get("volumes") or []:
            if isinstance(entry, str):
                parts = entry.split(":")
                if len(parts) >= 2 and parts[1] in paths:
                    assert "ro" not in parts[2:], f"{service}:{parts[1]} is mounted read-only"


def test_tempo_still_has_its_volume(compose: dict) -> None:
    """The control. Every assertion above would also pass on a file where
    somebody had deleted the one persistence that was already correct."""
    assert "/var/tempo" in _mounts(compose["services"]["tempo"])


# ── Helm ─────────────────────────────────────────────────────────────────────


def test_chart_offers_plugin_persistence() -> None:
    """`coreApi` is disabled in this chart ("Replaced by services.api
    above"), so the key is `services.api` — asserting against `api` would
    have been a test of a block nothing renders."""
    values = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    api = (values.get("services") or {}).get("api")
    assert isinstance(api, dict), "values.yaml has no `services.api` block"
    persistence = (api.get("plugins") or {}).get("persistence")
    assert isinstance(persistence, dict), "no `services.api.plugins.persistence` block"
    assert "size" in persistence
    assert "enabled" in persistence


def test_chart_has_a_pvc_and_mounts_it() -> None:
    """A PVC nothing mounts is the repository's most-repeated defect shape:
    it exists, it is correct, and no caller reaches it."""
    templates = list((CHART / "templates").glob("*.yaml"))
    pvc = [p for p in templates if "PersistentVolumeClaim" in p.read_text(encoding="utf-8")]
    assert pvc, "the chart declares no PersistentVolumeClaim for plugin state"
    mounted = [
        p for p in templates if "/opt/aisoc/plugins" in p.read_text(encoding="utf-8") and "volumeMounts" in p.read_text(encoding="utf-8")
    ]
    assert mounted, "no template mounts /opt/aisoc/plugins into the API pod"


def test_run_migrations_is_a_real_value_and_not_only_a_sentence() -> None:
    """`helm upgrade --set runMigrations=true` was documented and existed
    nowhere else in the repository.

    `--set` on a value nothing reads is accepted silently, so an operator
    following the documentation got an upgrade that reported success having
    applied no migration at all. This asserts the value exists *and* that a
    template reads it, because either half alone is still inert.
    """
    values = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    assert "runMigrations" in values, "no `runMigrations` key in values.yaml"
    assert values["runMigrations"] is False, (
        "runMigrations must default off: a schema change has no undo, and the flag is the operator's consent"
    )
    readers = [p for p in (CHART / "templates").glob("*.yaml") if ".Values.runMigrations" in p.read_text(encoding="utf-8")]
    assert readers, "nothing in templates/ reads .Values.runMigrations"


def test_the_migration_job_runs_in_strict_mode() -> None:
    """Without `AISOC_MIGRATIONS_STRICT` the runner logs each failure and
    returns: the Job exits 0, the hook passes, and the upgrade proceeds onto
    a partially-applied schema. That is worse than having no Job, because it
    manufactures evidence the migration succeeded."""
    job = CHART / "templates" / "migrations-job.yaml"
    assert job.is_file(), "no migration Job template"
    body = job.read_text(encoding="utf-8")
    assert "AISOC_MIGRATIONS_STRICT" in body
    assert "run_migrations" in body
    assert "pre-upgrade" in body, (
        "the Job is not a pre-upgrade hook, so it does not run before the Deployment is patched with the new image"
    )
