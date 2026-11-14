"""Extraction layer: pull structured signal out of natural-language reports.

Two responsibilities:

1. **Indicator extraction** — pluck IPs, domains, URLs, hashes, file
   paths, command-line fragments out of free-form prose. We
   deliberately use conservative regexes that prefer false negatives
   over false positives: a missed IOC is better than a regex that
   matches every English word containing ``.``.

2. **MITRE ATT&CK normalization** — recognize technique IDs already
   referenced in the report (``T1003.001``), and map a curated set of
   English aliases (``"credential dumping"``, ``"impacket"``,
   ``"secretsdump"``) onto their canonical IDs. We don't pretend to be
   exhaustive — this maps the high-signal subset that shows up
   repeatedly in real SOC tickets.

3. **Logsource guessing** — best-effort guess of the Sigma logsource
   block (``product``/``service``/``category``) from keywords. The
   generator falls back to a generic ``application`` logsource if we
   can't guess, which keeps the rule parseable.

The whole module is regex/keyword based with no LLM dependency so the
extractor is deterministic, cheap, and reproducible — important
because the rule id is derived from the title and the rule id has to
be stable across re-runs of the same report.
"""

from __future__ import annotations

import re
from typing import Iterable

# --------------------------------------------------------------------------- #
# Indicators
# --------------------------------------------------------------------------- #


# IPv4: four octets, each 0-255. We require word boundaries so we
# don't pick up version numbers like "1.2.3.4-rc.0" embedded in text.
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# URLs: scheme-anchored so we don't accidentally grab any text with a dot.
_URL_RE = re.compile(r"https?://[^\s<>'\"`)]+", re.IGNORECASE)

# Domain: at least two labels, TLD 2+ alpha chars, no leading digits in TLD.
# We refuse anything that's part of a longer dotted token (paths, emails)
# by demanding word boundaries on both sides AND a leading non-dot char.
_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9.\-])"
    r"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,24}"
    r"(?![A-Za-z0-9.\-])",
    re.IGNORECASE,
)

# Hashes: MD5 (32), SHA1 (40), SHA256 (64). Hex chars only, surrounded
# by word boundaries.
_HASH_RE = re.compile(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b", re.IGNORECASE)

# Windows file paths: drive-letter rooted, backslash separated. Also catches
# UNC paths starting with \\server\share. POSIX paths intentionally left
# out — they're too common in unrelated prose ("/var/log was inspected").
_WIN_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\|\\\\)(?:[^\s\"'<>|?*]+\\)*[^\s\"'<>|?*\\]+"
)


def extract_iocs(text: str, *, hints: Iterable[str] = ()) -> tuple[str, ...]:
    """Return a deduplicated tuple of indicators found in ``text``.

    ``hints`` are merged in first so analyst-supplied IOCs are
    preserved verbatim and aren't squashed by the regex normalizer.
    Order within each category is preserved (first occurrence wins);
    the categories themselves are interleaved in this priority order:
    URLs → domains → IPs → hashes → file paths → analyst hints.

    Why interleave? Downstream code uses the FIRST IOC as the seed for
    the rule body if no logsource matches; URLs are the highest-signal
    web indicator, so we want them first.
    """
    out: list[str] = []
    seen: set[str] = set()

    def _add(values: Iterable[str]) -> None:
        for v in values:
            key = v.strip()
            if not key:
                continue
            # Case-insensitive dedupe for domains/URLs but case-sensitive
            # for paths (since case matters on some filesystems).
            norm = key.lower() if any(c.isalpha() for c in key) else key
            if norm in seen:
                continue
            seen.add(norm)
            out.append(key)

    _add(hints)
    _add(_URL_RE.findall(text))
    _add(_DOMAIN_RE.findall(text))
    _add(_IPV4_RE.findall(text))
    _add(_HASH_RE.findall(text))
    _add(_WIN_PATH_RE.findall(text))
    return tuple(out)


def classify_ioc(value: str) -> str:
    """Return the IOC category for ``value``: url/domain/ipv4/hash/path/other."""
    v = value.strip()
    if _URL_RE.fullmatch(v):
        return "url"
    if _IPV4_RE.fullmatch(v):
        return "ipv4"
    if _HASH_RE.fullmatch(v):
        return "hash"
    if _WIN_PATH_RE.fullmatch(v):
        return "path"
    # Domain test goes last because hash hex strings of length 32+ can
    # legitimately contain only [a-f0-9] which won't match the domain
    # regex anyway, but we still want path to win over the broad domain
    # heuristic for ambiguous values.
    if _DOMAIN_RE.fullmatch(v):
        return "domain"
    return "other"


# --------------------------------------------------------------------------- #
# MITRE ATT&CK
# --------------------------------------------------------------------------- #


# Already-formatted technique IDs, optionally with sub-technique.
_MITRE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


# Curated alias → technique ID map. Lowercased keys; matched as
# substring against the lower-cased narrative so multi-word phrases
# work without per-token NLP. We keep this small and high-precision —
# adding too many aliases muddies the rule's MITRE tags.
_MITRE_ALIASES: dict[str, str] = {
    # Credential Access
    "credential dumping": "T1003",
    "lsass dump": "T1003.001",
    "lsass": "T1003.001",
    "ntds.dit": "T1003.003",
    "secretsdump": "T1003",
    "impacket": "T1003",
    "mimikatz": "T1003.001",
    "kerberoasting": "T1558.003",
    "as-rep roast": "T1558.004",
    "golden ticket": "T1558.001",
    # Initial Access / Identity
    "valid accounts": "T1078",
    "compromised account": "T1078",
    "phishing": "T1566",
    "spearphishing": "T1566.001",
    "phishing link": "T1566.002",
    "oauth consent": "T1528",
    "consent phishing": "T1528",
    "device code phishing": "T1566.002",
    "aitm": "T1557",
    "adversary in the middle": "T1557",
    "session cookie theft": "T1539",
    "stolen cookie": "T1539",
    "impossible travel": "T1078.004",
    # Execution / Persistence
    "powershell": "T1059.001",
    "cmd.exe": "T1059.003",
    "windows shell": "T1059.003",
    "bash": "T1059.004",
    "scheduled task": "T1053.005",
    "schtasks": "T1053.005",
    "cron": "T1053.003",
    "service install": "T1543.003",
    "new service": "T1543.003",
    # Privilege Escalation / Defense Evasion
    "uac bypass": "T1548.002",
    "process injection": "T1055",
    "dll injection": "T1055.001",
    "amsi bypass": "T1562.001",
    "disable defender": "T1562.001",
    "clear event log": "T1070.001",
    "wevtutil cl": "T1070.001",
    # Discovery / Lateral Movement
    "net view": "T1018",
    "remote service": "T1021.002",
    "smb admin shares": "T1021.002",
    "psexec": "T1021.002",
    "rdp": "T1021.001",
    "ssh": "T1021.004",
    "wmiexec": "T1021.006",
    # Exfiltration / C2
    "exfiltration over web": "T1567",
    "exfil to cloud": "T1567.002",
    "dropbox upload": "T1567.002",
    "data staging": "T1074",
    "rar archive": "T1560.001",
    "7zip archive": "T1560.001",
    "beacon": "T1071.001",
    "cobalt strike": "T1071.001",
    "dns tunnel": "T1071.004",
    # Cloud-specific
    "aws assumerole": "T1078.004",
    "sts assumerole": "T1078.004",
    "iam policy attachment": "T1098.001",
    "console login": "T1078.004",
    # Identity provider
    "okta super_admin": "T1098.003",
    "azure global admin": "T1098.003",
    "role escalation": "T1098.003",
}


def extract_mitre(text: str, *, hints: Iterable[str] = ()) -> tuple[str, ...]:
    """Return a deduplicated tuple of MITRE technique IDs.

    Hints (analyst-supplied) take precedence and are emitted FIRST in
    the original order, then we add any IDs we found in the prose,
    then any alias-derived IDs. Casing is normalized to upper-case
    (``T1003.001``); the dot in sub-technique IDs is preserved.

    Returned tuple is suitable to drop straight into ``tags:`` after
    prefixing with ``attack.``.
    """
    found: list[str] = []
    seen: set[str] = set()

    def _norm(tid: str) -> str:
        return tid.strip().upper()

    def _add(tid: str) -> None:
        t = _norm(tid)
        if not t.startswith("T"):
            return
        if t in seen:
            return
        seen.add(t)
        found.append(t)

    for h in hints:
        _add(h)

    for m in _MITRE_ID_RE.findall(text):
        _add(m)

    low = text.lower()
    for alias, tid in _MITRE_ALIASES.items():
        if alias in low:
            _add(tid)
    return tuple(found)


# --------------------------------------------------------------------------- #
# Logsource guessing
# --------------------------------------------------------------------------- #


# Keyword → logsource block. Ordered: first match wins. We pick
# specific-before-generic (``okta`` before ``identity``) so the most
# precise logsource is selected.
_LOGSOURCE_KEYWORDS: tuple[tuple[str, dict[str, str]], ...] = (
    # Identity
    ("okta", {"product": "okta", "service": "system"}),
    ("entra", {"product": "azure", "service": "signinlogs"}),
    ("azure ad", {"product": "azure", "service": "signinlogs"}),
    ("active directory", {"product": "windows", "service": "security"}),
    ("workspace", {"product": "google_workspace", "service": "login"}),
    # Cloud
    ("cloudtrail", {"product": "aws", "service": "cloudtrail"}),
    ("aws iam", {"product": "aws", "service": "cloudtrail"}),
    ("s3 bucket", {"product": "aws", "service": "cloudtrail"}),
    ("guardduty", {"product": "aws", "service": "guardduty"}),
    # Endpoint / EDR
    ("crowdstrike", {"product": "crowdstrike", "service": "falcon"}),
    ("sentinelone", {"product": "sentinelone", "service": "agent"}),
    ("defender for endpoint", {"product": "windows", "service": "defender"}),
    ("mde", {"product": "windows", "service": "defender"}),
    ("sysmon", {"product": "windows", "service": "sysmon"}),
    # Network
    ("zeek", {"product": "zeek", "service": "conn"}),
    ("suricata", {"product": "suricata", "service": "alert"}),
    ("firewall", {"category": "firewall"}),
    ("proxy", {"category": "proxy"}),
    # Email / SaaS
    ("m365", {"product": "m365", "service": "audit"}),
    ("microsoft 365", {"product": "m365", "service": "audit"}),
    ("exchange", {"product": "m365", "service": "exchange"}),
    ("slack", {"product": "slack", "service": "audit"}),
    ("github", {"product": "github", "service": "audit"}),
    # Generic categories — last so a more-specific match wins
    ("process creation", {"category": "process_creation"}),
    ("powershell", {"product": "windows", "service": "powershell"}),
    ("registry", {"category": "registry_event"}),
    ("dns", {"category": "dns"}),
)


def guess_logsource(text: str) -> dict[str, str]:
    """Best-effort Sigma ``logsource`` block derived from keywords.

    Returns at minimum ``{'category': 'application'}`` so the generator
    always has something to emit — Sigma rules without a logsource
    block are technically valid but our internal RulePack loader
    expects one.
    """
    low = text.lower()
    for kw, block in _LOGSOURCE_KEYWORDS:
        if kw in low:
            return dict(block)
    return {"category": "application"}


# --------------------------------------------------------------------------- #
# Severity heuristic
# --------------------------------------------------------------------------- #


_SEVERITY_KEYWORDS: tuple[tuple[str, str], ...] = (
    # Critical: outright domain takeover, ransomware, data destruction
    ("ransomware", "critical"),
    ("domain controller", "critical"),
    ("super_admin", "critical"),
    ("global admin", "critical"),
    ("ntds.dit", "critical"),
    ("golden ticket", "critical"),
    # High: high-impact credential / cloud / lateral movement
    ("credential dump", "high"),
    ("lsass", "high"),
    ("kerberoast", "high"),
    ("assumerole", "high"),
    ("privilege escalation", "high"),
    ("data exfil", "high"),
    # Medium: reconnaissance, suspicious login behavior
    ("impossible travel", "medium"),
    ("phishing", "medium"),
    ("reconnaissance", "medium"),
    ("brute force", "medium"),
    # Low default for general application-level events
)


def guess_severity(text: str) -> str:
    """Return one of low/medium/high/critical from keyword voting."""
    low = text.lower()
    for kw, sev in _SEVERITY_KEYWORDS:
        if kw in low:
            return sev
    return "medium"
