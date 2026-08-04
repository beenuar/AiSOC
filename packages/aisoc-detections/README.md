# aisoc-detections — Python detection framework

Write detections as Python, unit-tested against their own fixtures. Complements
the YAML/Sigma corpus in [`detections/`](../../detections/) — use Python when a
detection needs real logic (thresholds, correlation, stateful decisions) that is
awkward in a declarative DSL.

## A detection

A detection is a `.py` module with a `rule(event) -> bool` and metadata:

```python
ID = "py-okta-mfa-fatigue"
TITLE = "Okta MFA fatigue (push bombing)"
SEVERITY = "high"          # info | low | medium | high | critical
MITRE = ["T1621"]
DESCRIPTION = "Many MFA push challenges to one user in a short window."

def rule(event: dict) -> bool:
    return event.get("eventType") == "user.mfa.attempt" and event.get("attempts", 0) >= 5

# Optional: def title(event) -> str, def dedup(event) -> str

TESTS = [
    {"name": "fires on 6 attempts", "event": {"eventType": "user.mfa.attempt", "attempts": 6}, "expect": True},
    {"name": "quiet on 1 attempt",  "event": {"eventType": "user.mfa.attempt", "attempts": 1}, "expect": False},
]
```

Every detection **must** ship at least one positive and one negative `TESTS`
case — the harness fails a blind rule (misses a positive) or a noisy one (fires
on a negative), the same non-circular guarantee the YAML corpus gets.

## Running the fixture gate

```bash
# from packages/aisoc-detections/
python -m aisoc_detections.runner detections    # aka `aisoc-detections`
PYTHONPATH=. python -m pytest tests/
```

CI runs this on every PR ([`.github/workflows/python-detections.yml`](../../.github/workflows/python-detections.yml)).

## Safety

Rules are first-party and reviewed via PR. `evaluate()` is fail-closed: a rule
that raises returns `False` (never fires, never crashes the batch).
