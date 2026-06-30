# Third-Party Content Licenses

AiSOC ships under [Apache-2.0](LICENSE). Some content under [`detections/`](detections/) is **imported** from upstream open-source detection corpora and is redistributed under each upstream project's own license. Every imported rule carries a `provenance` block documenting its source, upstream id, commit SHA, and license, so you can always trace a rule back to its origin.

This file is the canonical attribution registry. It is updated automatically when [`tools/detection-import/import.py`](tools/detection-import/import.py) runs.

> ⚠️ **If you redistribute AiSOC's detection corpus** (e.g. ship it as part of a managed-service offering), you are responsible for honoring every upstream license below in your own attribution notices.

---

## Imported detection sources

### SigmaHQ — `detections/sigma-imports/`

| Field | Value |
|---|---|
| **Upstream repo** | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| **License** | [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License) |
| **License classification** | Permissive, redistribution-allowed with attribution |
| **Imported via** | [`tools/detection-import/sigma_importer.py`](tools/detection-import/sigma_importer.py) |
| **Provenance file** | every rule carries `provenance.source: SigmaHQ/sigma`, `provenance.source_id: <upstream uuid>`, `provenance.source_commit: <sha>` |

DRL-1.1 summary: you may use, modify, and redistribute Sigma rules provided you keep attribution intact. Each imported rule retains its upstream `id` (UUID) inside the `provenance` block.

### MITRE Cyber Analytics Repository (CAR) — `detections/car-imports/`

| Field | Value |
|---|---|
| **Upstream repo** | [mitre-attack/car](https://github.com/mitre-attack/car) |
| **License** | [Apache-2.0](https://github.com/mitre-attack/car/blob/master/LICENSE) |
| **Imported via** | [`tools/detection-import/car_importer.py`](tools/detection-import/car_importer.py) |
| **Provenance file** | every rule carries `provenance.source: mitre-attack/car`, `provenance.source_id: CAR-YYYY-MM-NNN`, `provenance.source_commit: <sha>` |

### Splunk Security Content — `detections/splunk-imports/`

| Field | Value |
|---|---|
| **Upstream repo** | [splunk/security_content](https://github.com/splunk/security_content) |
| **License** | [Apache-2.0](https://github.com/splunk/security_content/blob/develop/LICENSE) |
| **Imported via** | [`tools/detection-import/splunk_importer.py`](tools/detection-import/splunk_importer.py) |
| **Note** | SPL → Sigma transpile is best-effort. Rules that don't round-trip cleanly are emitted with `enabled: false` and surfaced in [`detections/REVIEW.md`](detections/REVIEW.md). |

### Chronicle Detection Rules — `detections/chronicle-imports/`

| Field | Value |
|---|---|
| **Upstream repo** | [chronicle/detection-rules](https://github.com/chronicle/detection-rules) |
| **License** | [Apache-2.0](https://github.com/chronicle/detection-rules/blob/main/LICENSE) |
| **Imported via** | [`tools/detection-import/chronicle_importer.py`](tools/detection-import/chronicle_importer.py) |
| **Note** | YARA-L 2.0 → Sigma conversion covers ~60% of upstream rules cleanly. The hard cases (statistical aggregations, `match` clauses with windowed joins) are deferred and tracked in [`detections/REVIEW.md`](detections/REVIEW.md). |

### Atomic Red Team mappings — `detections/atomic-imports/` (planned)

| Field | Value |
|---|---|
| **Upstream repo** | [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) |
| **License** | [MIT](https://github.com/redcanaryco/atomic-red-team/blob/master/LICENSE.txt) |
| **Note** | Used for fixture generation only — atomics are test payloads, not detection logic. We import them to drive purple-team replay, not as standalone rules. |

---

## Native AiSOC content

Everything under `detections/cloud/`, `detections/identity/`, `detections/endpoint/`, `detections/network/`, `detections/application/`, and `detections/data-exfil/` is **native AiSOC content** authored against AiSOC's own normalized event schema. Native rules are licensed under [Apache-2.0](LICENSE) and carry a `provenance.source: native` marker.

`detections/community/` carries community contributions, also under Apache-2.0 with the contributor named in the provenance block.

---

## Plugins

Each plugin under [`plugins/`](plugins/) declares its own license in `plugin.yaml`. Plugins shipped with AiSOC core are MIT or Apache-2.0; community plugins under `plugins/community/` may declare any OSI-approved license.

---

## How to add a new imported source

1. Add an importer to [`tools/detection-import/`](tools/detection-import/) that emits the AiSOC YAML schema with a populated `provenance` block.
2. Add a section to this file describing the upstream license and any redistribution caveats.
3. Run `python3 scripts/validate_detections.py` and `pnpm marketplace:build` to confirm the new rules parse and surface.

---

_Last updated by `tools/detection-import/import.py` on first run; subsequent runs only append new sources, never rewrite the file._
