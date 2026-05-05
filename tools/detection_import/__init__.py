"""Detection rule importers.

Pulls detection content from upstream open-source projects (SigmaHQ, MITRE CAR,
Chronicle, Splunk) and converts each rule into AiSOC's native YAML schema with
a populated ``provenance`` block so every rule is traceable to its origin.

See ``tools/detection-import/README.md`` for usage.
"""
