---
title: Detection Coverage
description: |
  AiSOC v1.0 ships a curated set of MITRE ATT&CK-mapped
  detections covering the eight buyer-prioritised threat
  families. This page is generated from the on-disk corpus
  via ``scripts/curate_detections.py`` — it is the source
  of truth for what we promise in v1.0.
sidebar_position: 2
---

# Detection Coverage

Generated: `2026-07-11T13:45:01Z`

## Headline numbers

- **Curated v1.0 detections**: `416` (target: ≥ 300)
- **Total rules considered**: `1054` (quality floor: 0.55)
- **Unique MITRE techniques covered**: `117`

## Coverage by buyer family

| Family | Count | Target | Covered |
|---|---|---|---|
| **Ransomware** | 48 | ≥ 25 | ✅ |
| **Credential Access** | 84 | ≥ 25 | ✅ |
| **Lateral Movement** | 33 | ≥ 25 | ✅ |
| **Data Exfiltration** | 41 | ≥ 25 | ✅ |
| **Cloud** | 100 | ≥ 25 | ✅ |
| **Identity** | 100 | ≥ 25 | ✅ |
| **Supply Chain** | 36 | ≥ 25 | ✅ |
| **Kubernetes / Containers** | 73 | ≥ 25 | ✅ |

## Distribution

### By tier

- `imported`: 42
- `native`: 374

### By severity

- `critical`: 99
- `high`: 208
- `low`: 6
- `medium`: 103

### By category

- `_migrated`: 1
- `application`: 29
- `cloud`: 165
- `data-exfil`: 20
- `endpoint`: 117
- `identity`: 72
- `network`: 12

## How to audit

The curated rule IDs are listed in [`marketplace/curated.json`](https://github.com/aisoc-platform/aisoc/blob/main/marketplace/curated.json) under each family. Every entry has a `path` field pointing at the on-disk YAML. Run `pnpm marketplace:curate --check` in CI to enforce drift; run `python3 scripts/curate_detections.py` locally to regenerate.

