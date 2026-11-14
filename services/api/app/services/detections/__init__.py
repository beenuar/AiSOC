"""Detection rule service modules.

This package collects the in-process services that manage AiSOC's detection
content. Today it owns:

* :mod:`app.services.detections.sigma_import` — bulk import of community
  Sigma rules with OCSF auto-mapping, MITRE ATT&CK extraction, and
  provenance tracking.
* :mod:`app.services.detections.ocsf_mapping` — translation between Sigma
  ``logsource`` blocks and OCSF v1.1 event class metadata.

Runtime evaluation of rules still lives in :mod:`app.services.rule_engine`;
this package handles authoring/import, not execution.
"""

from app.services.detections.sigma_import import (
    SigmaImportError,
    SigmaImportReport,
    SigmaImportResult,
    import_sigma_rules,
)

__all__ = [
    "SigmaImportError",
    "SigmaImportReport",
    "SigmaImportResult",
    "import_sigma_rules",
]
