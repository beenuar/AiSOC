# Threat Actor Attribution Engine

> **Status:** v0. Ships with a hardcoded catalog of three public actor
> profiles (APT28, APT29, Lazarus). Suitable as a foundation; not yet a
> replacement for analyst judgement.

## Overview

The Threat Actor Attribution Engine scores observed indicators (IOCs),
MITRE ATT&CK techniques, used tools, and target sectors against a small
in-memory catalog of well-documented threat actors and returns the best
match above a configurable confidence threshold.

It is reachable two ways:

1. Directly via the `threatintel` service HTTP API.
2. Automatically from the LangGraph investigation pipeline (the agent
   calls the API during the investigation node and records the result on
   the investigation state).

## Scoring model

The score for each candidate actor is the weighted sum of four
components, multiplied by the actor's baseline profile-confidence:

| Component | Weight | What it measures                                           |
| --------- | -----: | ---------------------------------------------------------- |
| TTP       |   0.40 | Overlap between observed and known MITRE ATT&CK techniques |
| Tool      |   0.30 | Substring matches of known tool names against IOC values   |
| Target    |   0.20 | Overlap between observed and known target sectors          |
| IOC       |   0.10 | Exact value matches against the `threatintel-iocs` index   |

The default confidence threshold is `0.30`. Below it, the engine returns
`actor_id="unknown"` and an empty match list.

### IOC component is conditional

The IOC component contributes **0** unless the engine is constructed with
an OpenSearch store (`os_store`). Production startup wires the
`os_store` shared with the threat-intel feed pipeline, so the IOC
component activates whenever there are collected IOCs in the
`threatintel-iocs` index. In unit tests and local runs without
OpenSearch the score is honest about this — the reasoning list will
contain the line:

```
IOC component unavailable: no os_store wired (TTP/tool/target only)
```

There is **no** synthetic "every observed IOC counts as a match" inflation.

## API

Mounted under `/api/v1/actors` on the `threatintel` service (default
port `8083`).

### `POST /api/v1/actors/attribute`

Body:

```json
{
  "iocs": [
    { "value": "x-agent-malware.exe", "type": "filename" }
  ],
  "mitre_techniques": ["T1566", "T1059", "T1071"],
  "case_metadata": {
    "targets": ["government", "military"],
    "industry": "defense",
    "geography": "US"
  }
}
```

Response (`AttributionResult`):

```json
{
  "actor_id": "APT28",
  "actor_name": "APT28 (Fancy Bear)",
  "confidence_score": 0.4958,
  "matched_indicators": ["T1059", "T1071", "T1566", "x-agent", "government", "military"],
  "reasoning": [
    "Matched 3/4 TTPs: T1059, T1071, T1566",
    "Matched tools: x-agent",
    "Matched target sectors: government, military",
    "IOC component unavailable: no os_store wired (TTP/tool/target only)"
  ],
  "timestamp": "2026-05-09T22:14:44Z"
}
```

If no actor exceeds the confidence threshold:

```json
{
  "actor_id": "unknown",
  "actor_name": "Unknown Actor",
  "confidence_score": 0.0,
  "matched_indicators": [],
  "reasoning": ["No actor exceeded confidence threshold of 0.3"],
  "timestamp": "2026-05-09T22:14:44Z"
}
```

### `GET /api/v1/actors/profiles`

Lists all profiles in the in-memory catalog.

### `GET /api/v1/actors/profiles/{actor_id}`

Returns a single profile, or `404` if the ID is unknown.

## Integration with the investigation agent

`services/agents/app/agents/investigation_agent.py` calls the API once
per investigation, after triage and enrichment have populated
`state.ioc_enrichments` and `state.mitre_mappings`. The result is stored
on `state.threat_intel["attribution"]` and surfaced in the findings
list. Failure is soft — a finding is added and the investigation
continues.

The agent uses `state.raw_alert` for `targets`, `industry`, `geography`,
and `severity`. To enrich attribution, populate those fields on the
incoming alert.

## v0 limits and intended next steps

This is the first cut. Calling these out so reviewers and operators
don't read more into it than is there:

- **Hardcoded catalog.** Three profiles (APT28, APT29, Lazarus) seeded
  from public MITRE ATT&CK Groups data. The next iteration should load
  profiles from STIX/TAXII or a curated YAML/JSON corpus committed to
  the repo.
- **Tool match is substring-based.** Cheap, gets the obvious cases, but
  will false-positive on benign filenames containing common substrings.
  A real implementation should use precise matching against
  malware-family signatures.
- **IOC match is exact-value only.** No fuzzy hashing, no domain
  hierarchy expansion, no IP CIDR matching.
- **No temporal weighting.** Recency of an actor's last-seen activity
  doesn't affect the score yet.
- **Score weights are constants.** They live at the top of
  `attribution.py` and have not been tuned against a labeled corpus.

## Adding a custom actor profile

Edit `services/threatintel/app/actors/attribution.py` and append to
`_seed_actor_catalog()`:

```python
"CUSTOM_ACTOR": ThreatActorProfile(
    id="CUSTOM_ACTOR",
    name="Custom Threat Actor",
    aliases=["CustomAlias"],
    description="Organization-specific threat actor",
    sophistication_level="intermediate",
    primary_motivation="espionage",
    secondary_motivations=["financial gain"],
    ttps=["T1566", "T1071"],
    tools=["custom-malware"],
    targets=["organization-sector"],
    confidence_score=0.75,
),
```

Or, at runtime, call `engine.update_actor_profile(profile)` from a
custom startup hook. A `PUT /profiles/{actor_id}` endpoint is not yet
implemented — file an issue if you need it.

## Tests

`services/threatintel/tests/test_actor_attribution.py` exercises the
engine end to end with no network. Run with:

```bash
cd services/threatintel
poetry install
poetry run pytest tests/test_actor_attribution.py -v
```
