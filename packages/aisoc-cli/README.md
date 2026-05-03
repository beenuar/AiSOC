# aisoc-cli

Developer CLI for building, validating, and publishing AiSOC plugins and detection rules.

## Installation

```bash
pip install aisoc-cli
```

Or from source:
```bash
pip install -e packages/aisoc-cli
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
export AISOC_API_URL=https://api.aisoc.dev
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
