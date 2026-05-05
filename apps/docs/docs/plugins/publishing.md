---
sidebar_position: 4
---

# Publishing Plugins

Share your plugin with the AiSOC community via the marketplace.

## Steps

1. **Build and test** your plugin locally.
2. **Sign the plugin** with an Ed25519 key (see [Signing](#signing) below). Production AiSOC deployments default to `PLUGIN_TRUST_MODE=strict` and refuse to load unsigned code.
3. **Publish to PyPI / pkg.go.dev** (or host on GitHub).
4. **Add an entry** to `marketplace/index.json`:

```json
{
  "id": "myorg.virustotal",
  "name": "VirusTotal Enricher",
  "type": "plugin",
  "description": "Enriches IPs, domains and hashes via VirusTotal API.",
  "author": "My Org",
  "version": "1.0.0",
  "tags": ["threat-intel", "enrichment"],
  "url": "https://github.com/myorg/aisoc-virustotal",
  "install": "pip install aisoc-plugin-virustotal",
  "signing_key_id": "myorg-prod"
}
```

5. **Open a PR** — CI validates the JSON schema, verifies your `plugin.sig` against the registered `signing_key_id`, and the marketplace bot posts a preview.
6. **Merge** — your plugin appears on the `/marketplace` page.

## Signing

AiSOC verifies plugins with Ed25519 before executing any code from `plugin.py`. The signing flow is deliberately mechanical so it slots into CI:

### 1. Generate a publisher keypair (once)

```bash
aisoc plugin keygen --out ./keys/myorg
# writes keys/myorg.pem (public, share this) and keys/myorg.key (private, keep secret)
```

The private key never leaves your release pipeline. Store it in your CI secret manager (GitHub Actions encrypted secrets, AWS Secrets Manager, Vault, etc.).

### 2. Sign the plugin directory

```bash
aisoc plugin sign \
  --plugin-dir ./my-enricher \
  --private-key $AISOC_PUBLISHER_KEY \
  --out ./my-enricher/plugin.sig
```

The signer hashes a canonical JSON document containing:

- the manifest (`plugin.yaml` or `aisoc-plugin.json`) with the `signature` and `trust` keys stripped, and
- a sorted `{relative_path: sha256_hex}` map of every `*.py` file in the plugin directory tree.

The resulting Ed25519 signature is written to `plugin.sig` as a hex string. Any change to the manifest or any source file invalidates the signature, so an attacker cannot swap out `plugin.py` after publishing.

### 3. Register your public key with the operator

Operators install your `keys/myorg.pem` into `PLUGIN_TRUSTED_KEYS_DIR` (defaults to `/opt/aisoc/plugin-keys`). Multiple PEM files can live there — every key is tried, and a single match is enough to trust the plugin.

```bash
# operator side
cp myorg.pem /opt/aisoc/plugin-keys/
sudo systemctl restart aisoc-api
```

### 4. Choose a trust mode

The `PLUGIN_TRUST_MODE` setting controls what the loader does on signature failure:

| Mode | Behaviour | When to use |
|---|---|---|
| `strict` (default) | Refuse to load unsigned, invalid, or untrusted-key plugins. | Production. |
| `warn` | Load anyway but tag the plugin record with `signature_status="unsigned"` or `"invalid"` and emit a structured warning log. | Bootstrapping a key-rotation programme, when you need to flush the warnings out of audit logs before flipping back to strict. |
| `disabled` | Skip the signature check entirely. `signature_status="skipped"`. | Throwaway dev sandboxes only. Never production. |

The `signature_status` value is exposed on `GET /api/v1/plugins` so operators can spot unsigned plugins in their marketplace UI.

## Plugin Quality Guidelines

- Include a `README.md` with installation and configuration instructions.
- Write tests with ≥ 80% coverage.
- Follow the AiSOC [Code of Conduct](https://github.com/beenuar/AiSOC/blob/main/CODE_OF_CONDUCT.md).
- Pin dependency versions for reproducibility.
- Never log or store credentials in plain text.
- Ship a signed `plugin.sig`. Unsigned plugins are refused in production.
