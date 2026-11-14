"""Reported-phish intake, campaign grouping and the governed purge.

Three modules, split by the question each answers:

* :mod:`app.services.phishing.intake` — what a reported message *is*, and how
  each of the three sources' shapes becomes one.
* :mod:`app.services.phishing.campaigns` — which reports are the same message,
  and who received it.
* :mod:`app.services.phishing.purge` — the governed fan-out across those
  recipients, one dispatch per mailbox.
"""

from __future__ import annotations
