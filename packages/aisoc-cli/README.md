# aisoc-cli

Developer CLI for building, validating, and publishing AiSOC plugins and detection rules.

> **Status — monorepo today, PyPI in v8.0.** The CLI ships from this monorepo and is fully functional today. The PyPI release lands with v8.0. The CLI name (`aisoc`) and command surface stay identical once it ships.

## Installation

```bash
# Today (from this monorepo):
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC && pip install -e packages/aisoc-cli

# v8.0+ (once aisoc-cli lands on PyPI):
pipx install aisoc-cli       # recommended (isolated venv)
# or:
pip install aisoc-cli
```

## Commands

### Plugin Scaffold
```bash
aisoc plugin scaffold my-enricher
aisoc plugin scaffold my-connector --type connector
```

### Plugin Validate
```bash
aisoc plugin validate ./my-enricher
aisoc plugin validate ./my-enricher/plugin.yaml
```

### Plugin Publish
```bash
export AISOC_API_URL=https://api.example.com
export AISOC_API_KEY=sk-...
aisoc plugin publish ./my-enricher
```

### Detection Validate
```bash
aisoc detection validate ./detections/brute-force.yaml
```

### Key Generation
```bash
aisoc keygen              # generates ~/.aisoc/signing.key + signing.pub
```

## Environment Variables

| Variable | Description |
|---|---|
| `AISOC_API_URL` | AiSOC API base URL (default: `http://localhost:8000`) |
| `AISOC_API_KEY` | API key for authentication |
| `AISOC_SIGNING_KEY` | Path to Ed25519 private key (default: `~/.aisoc/signing.key`) |
