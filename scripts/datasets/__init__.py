"""Dataset download helpers (T5.3).

These scripts never redistribute upstream data. They fetch from the
licensed source over HTTPS, verify SHA-256, and unpack into a local
``datasets/`` directory that lives outside version control (see
``.gitignore``). Each script prints the upstream license and citation
before any byte hits disk so a contributor cannot accidentally
publish data they have not read the terms for.
"""
