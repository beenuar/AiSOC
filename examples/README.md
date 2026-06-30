# AiSOC examples

Each scenario in this directory is a small, self-contained alert
fixture you can walk through the AiSOC agent funnel two ways:

1. **Real ingest** — `pnpm aisoc:submit examples/alerts/<name>.json`
   posts the events to the running stack (started by `pnpm aisoc:demo`).
   Fusion deduplicates, the four agents reason, and the result lands
   in the [Investigation Rail](../apps/docs/docs/console/investigation-rail.md).

2. **Offline simulator** — `aisoc-sandbox demo --scenario <name>` runs
   the same scenario through a zero-dependency in-memory simulator.
   No Docker, no API key, completes in < 5 s. Install path:
   `pip install -e packages/aisoc-sandbox` from the repo root, or
   (once v8.0 ships) `pip install aisoc-sandbox`.

The five scenarios cover the most common attack patterns in modern
SOC alert queues; collectively they exercise eleven MITRE ATT&CK
techniques across initial access, credential access, lateral
movement, privilege escalation, and exfiltration.

| ID | Title | MITRE | Severity | Walkthrough |
|---|---|---|---|---|
| `lateral-movement` | Impossible-travel Okta sign-in | T1078, T1078.004 | high | [walkthrough](./lateral-movement.md) |
| `aws-credential-exfil` | IAM keys used from new ASN, then `s3:GetObject` flood | T1552, T1567, T1078.004 | critical | [walkthrough](./aws-credential-exfil.md) |
| `phishing-payload` | Click-through to credential-harvest page | T1566, T1566.002 | high | [walkthrough](./phishing-payload.md) |
| `kubernetes-privesc` | Namespace SA bound to `cluster-admin` | T1098, T1078 | critical | [walkthrough](./kubernetes-privesc.md) |
| `github-token-theft` | PAT leaked — six private repos cloned in 11 s | T1078, T1555, T1567 | high | [walkthrough](./github-token-theft.md) |

## Layout

```
examples/
├── README.md                    # this file
├── alerts/
│   ├── lateral-movement.json    # 5x production-faithful OCSF/native-shape
│   ├── aws-credential-exfil.json
│   ├── phishing-payload.json
│   ├── kubernetes-privesc.json
│   └── github-token-theft.json
├── lateral-movement.md          # walkthroughs — what the agent does, step by step
├── aws-credential-exfil.md
├── phishing-payload.md
├── kubernetes-privesc.md
└── github-token-theft.md
```

The bundled offline scenarios live in
[`packages/aisoc-sandbox/src/aisoc_sandbox/scenarios/`](../packages/aisoc-sandbox/src/aisoc_sandbox/scenarios/) — same IDs, simplified shape so the
simulator stays a single small package.

## Contributing a new scenario

Open a [`good first issue`](https://github.com/beenuar/AiSOC/issues?q=is%3Aopen+label%3A%22good+first+issue%22)
or send a PR that adds:

1. `examples/alerts/<id>.json` — production-shape fixture with at
   least one MITRE technique and a clear narrative in the `_description`.
2. `examples/<id>.md` — walkthrough using the existing pages as a template.
3. `packages/aisoc-sandbox/src/aisoc_sandbox/scenarios/<id>.json` —
   simplified sandbox variant so `aisoc-sandbox demo --scenario <id>`
   works.
4. Update the table in `examples/README.md` and (if relevant) the
   tables in `README.md` and `packages/aisoc-sandbox/README.md`.

A maintainer will pair the scenario with at least one detection rule
in [`detections/`](../detections/) so the production funnel can
actually fire on it.
