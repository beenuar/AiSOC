# Event classification catalogue

One file per source. Each maps a vendor's own event type onto a normalized
action, a sensitivity, and an optional ATT&CK hint.

```yaml
source: aws_cloudtrail
event_type_path: eventName          # where the vendor's event type lives
fixture_files:                      # the corpus the gate grows this from
  - services/connectors/tests/test_aws_cloudtrail.py
events:
  CreateAccessKey:
    action: create.access.key
    sensitivity: high
    attack: [T1098.001]
unclassified:
  SomeEventType: why it is deliberately not classified
```

## Why a data file rather than code

The question "how sensitive is this event type" has a different answer per
vendor, per event, and sometimes per customer, and it changes whenever a
vendor adds an event. A regex over event names would be wrong in both
directions and invisible when it was. A reviewed table is wrong in exactly
the places somebody can point at.

It also has to be the *same* table everywhere. Ingest reads it at boot and
stamps the classification onto every event, so the lake, the detection
matcher and triage see one answer rather than three re-derivations.

## Sensitivity

The five-tier ladder the rest of the platform uses — `info`, `low`,
`medium`, `high`, `critical` — and it means **how security-relevant this
event type is**, not how severe this particular occurrence was. A vendor's
own severity on the record still governs promotion; sensitivity is a
property of the *class* of event and is what makes "show me everything above
medium that a non-human actor did" answerable without enumerating verbs.

`critical` is reserved for event types that are an incident on their own
reading — disabling the audit trail, destroying it, granting the top-level
administrative role. Everything an estate does hourly is `info`.

## How this grows

`scripts/check_event_catalog.py` extracts every event type that appears in
the fixtures each catalogue declares, and fails when one is neither
classified nor listed under `unclassified` with a reason. Adding a connector
fixture that carries a new event type therefore fails CI until somebody
decides what it means, which is the point: a catalogue that only grows when
someone remembers is a catalogue that stops growing.

A source whose declared fixtures yield **no** event types also fails. A gate
over an empty corpus is a gate that passes for the wrong reason, and two of
the ten sources here had no vendor-payload fixture at all until this
catalogue was written.

## What is deliberately not here

A sensitivity does not change an event's severity or whether fusion promotes
it. Making `critical` sensitivity force an alert would mean this file could
silently flood a queue, and the promotion contract belongs with the OCSF
class and the vendor's severity where it already is. The classification is
attached to the event for detections, hunts and triage to read.
