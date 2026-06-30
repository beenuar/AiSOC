# Detection Importers

Tools for pulling detection content from upstream open-source projects and converting it into AiSOC's native YAML schema. Every imported rule carries a populated `provenance` block so the source is always traceable.

## Layout

| Importer | Upstream | Output | Status |
|---|---|---|---|
| [`sigma_importer.py`](sigma_importer.py) | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | `detections/sigma-imports/<category>/` | working |
| [`car_importer.py`](car_importer.py) | [mitre-attack/car](https://github.com/mitre-attack/car) | `detections/car-imports/` | working |
| [`chronicle_importer.py`](chronicle_importer.py) | [chronicle/detection-rules](https://github.com/chronicle/detection-rules) | `detections/chronicle-imports/` | scaffolded |
| [`splunk_importer.py`](splunk_importer.py) | [splunk/security_content](https://github.com/splunk/security_content) | `detections/splunk-imports/` | scaffolded |
| [`import.py`](import.py) | (orchestrator) | runs every importer in turn | working |

## Provenance schema

Every imported rule carries a top-level `provenance` block:

```yaml
provenance:
  source: SigmaHQ/sigma          # short upstream identifier
  source_id: 5e957c0a-...        # upstream rule id (UUID for Sigma, CAR-YYYY-MM-NNN for CAR, etc.)
  source_commit: a1b2c3d         # short SHA of the upstream commit we imported from
  license: DRL-1.1               # upstream license SPDX-ish identifier
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
  imported_at: 2026-05-04        # YYYY-MM-DD when the importer wrote this file
  imported_by: sigma_importer    # which importer produced this file
  upstream_path: rules/cloud/aws/aws_root_login.yml  # original path inside the upstream repo
```

This block is required for every rule under `detections/sigma-imports/`, `detections/car-imports/`, `detections/splunk-imports/`, and `detections/chronicle-imports/`. The validator ([`scripts/validate_detections.py`](../../scripts/validate_detections.py)) enforces it.

Native rules under `detections/cloud/`, `detections/identity/`, etc. carry `provenance.source: native` and do not require a `source_commit`.

## Quality tiers

| Tier | Path | Validation | Fixture required | Visibility |
|---|---|---|---|---|
| **Native** | `detections/<category>/` | full schema + fixture replay | yes | `tier: stable` |
| **Imported (verified)** | `detections/<source>-imports/<category>/` | schema + parse + MITRE mapping | no | `tier: imported` |
| **Imported (quarantine)** | `detections/<source>-imports/_quarantine/` | parse only, `enabled: false` | no | `tier: quarantine`, hidden by default |
| **Community** | `detections/community/` | schema + fixture replay | yes | `tier: community` |

## Running an importer

Each importer is idempotent and pinned to a specific upstream commit. To upgrade the corpus:

```bash
# 1. update the SIGMA_COMMIT, CAR_COMMIT, etc. constants in tools/detection_import/import_orchestrator.py
# 2. run the orchestrator (from the repo root):
python3 -m tools.detection_import.import_orchestrator

# 3. validate
python3 scripts/validate_detections.py

# 4. rebuild the marketplace index
pnpm marketplace:build && pnpm marketplace:check
```

The orchestrator clones each upstream repo into `.import-cache/` (gitignored), reads from a pinned commit, and writes converted rules to the appropriate `detections/<source>-imports/` directory.

## Why pinned commits?

Detection rules drift. SigmaHQ moves a rule from `experimental/` into `stable/`, the CAR project renames a model, Splunk security_content reshapes its YAML. Pinning to a commit means our shipped corpus is reproducible: anyone running the orchestrator against the same commit gets the same rule files. Bumping is a deliberate PR.

## Adding a new importer

1. Create `tools/detection_import/<name>_importer.py` with a `def import_rules(commit: str, *, output_root: Path | None = None) -> list[ImportedRule]` entrypoint.
2. Wire it into `tools/detection_import/import_orchestrator.py`.
3. Document the upstream license in [`.github/LICENSES.md`](../../.github/LICENSES.md).
4. Update [`detections/README.md`](../../detections/README.md) with the new tier.
