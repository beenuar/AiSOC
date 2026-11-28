# NetAPI list fixtures — provenance and licence

The three `netapi_*.txt` files beside this one are **real excerpts** of the
published NetAPI lists, not synthetic data. They exist so the feed's tests
parse the format the publisher actually serves rather than a format we
imagined, which is the difference between a test that would catch a format
change and one that would not.

## What they are

| Fixture | Source URL | Captured |
| --- | --- | --- |
| `netapi_compromised_ips_sample.txt` | `https://netapi.com/api2/netapi-compromised-ips.txt` | 2026-11-28 |
| `netapi_compromised_domains_short_sample.txt` | `https://netapi.com/api2/netapi-compromised-domains-short.txt` | 2026-11-28 |
| `netapi_compromised_domains_sample.txt` | `https://netapi.com/api2/netapi-compromised-domains.txt` | 2026-11-28 |

Each is the **first 200 lines** of the list as published on that date. The
full lists were 40,078 / 128,570 / 285,028 lines respectively; these are
excerpts kept small deliberately, because the tests need the *format*, not
the corpus, and committing several megabytes of indicators that go stale
within hours would be worse on both counts.

These are a point-in-time snapshot for testing. They are **not** a mirror of
the feed and must not be used as one — the live lists are rebuilt on the
publisher's schedule and anything here is stale by definition.

## Licence and attribution

Published by [NetAPI](https://netapi.com/) under
[Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).

CC BY 4.0 permits redistribution, including in a repository like this one,
provided the source is credited — which is what this file does. If you
redistribute these excerpts further, the same attribution requirement
travels with them.

No modification has been made beyond truncating each list to its first 200
lines.
