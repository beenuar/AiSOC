---
sidebar_position: 4
---

# Publishing Plugins

Share your plugin with the AiSOC community via the marketplace.

## Steps

1. **Build and test** your plugin locally
2. **Publish to PyPI / pkg.go.dev** (or host on GitHub)
3. **Add an entry** to `marketplace/index.json`:

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
  "install": "pip install aisoc-plugin-virustotal"
}
```

4. **Open a PR** — CI validates the JSON schema and the marketplace bot posts a preview
5. **Merge** — your plugin appears on the `/marketplace` page

## Plugin Quality Guidelines

- Include a `README.md` with installation and configuration instructions
- Write tests with ≥ 80% coverage
- Follow the AiSOC [Code of Conduct](https://github.com/beenuar/AiSOC/blob/main/CODE_OF_CONDUCT.md)
- Pin dependency versions for reproducibility
- Never log or store credentials in plain text
