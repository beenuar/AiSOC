#!/usr/bin/env python3
"""
AiSOC AI-vs-AI adversary scenario generator (Wave 2 — w2-aivai).
=================================================================

Takes the deterministic 200-incident benchmark and produces a parallel
"adversary-mutated" dataset that simulates what an attacker-LLM would do
to evade a keyword/regex-based defender: synonym substitution, character
obfuscation, fragmentation, and softening of tactic-betraying language.

The mutator is INTENTIONALLY DETERMINISTIC. We don't want to ship a flaky
CI suite that depends on a live model — so the "attacker LLM" is replaced
with a content-derived hash + a curated mutation grammar. The grammar is
built directly from the defender's `_TACTIC_KEYWORDS` dictionary in
`services/agents/tests/test_mitre_accuracy.py`, so every keyword the
defender knows about gets at least one evasive alternate.

Mutation intensity per incident is bucketed by `sha256(id)`:

  heavy   ≈ 45%  — every keyword in title+description rewritten
  medium  ≈ 35%  — only one of the expected tactics is preserved cleanly
  light   ≈ 20%  — light leetspeak only; defender should still catch

Targeted floor for the resulting eval suite is ~0.55, demonstrating
graceful degradation under adversarial obfuscation rather than the 0.80
defender-friendly floor of `test_mitre_accuracy.py`.

Outputs `services/agents/tests/eval_data/adversary_incidents.json`. Re-runs
are byte-identical given the same input dataset and mutation grammar.

Usage:
    python3 scripts/generate_adversary_incidents.py
    python3 scripts/generate_adversary_incidents.py --report
    python3 scripts/generate_adversary_incidents.py --out PATH
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_AGENTS_ROOT = _REPO_ROOT / "services" / "agents"
sys.path.insert(0, str(_AGENTS_ROOT))

# Pull the defender's keyword catalogue directly so we never drift from it.
from tests.test_mitre_accuracy import (  # type: ignore  # noqa: E402
    _TACTIC_KEYWORDS,
    extract_tactics_from_text,
)

_DEFAULT_INPUT = _AGENTS_ROOT / "tests" / "eval_data" / "synthetic_incidents.json"
_DEFAULT_OUTPUT = _AGENTS_ROOT / "tests" / "eval_data" / "adversary_incidents.json"


# ---------------------------------------------------------------------------
# Mutation grammar
#
# Each entry rewrites the substring on the LEFT to one of the alternates on
# the right. Alternates are intentionally chosen so they do NOT match any
# keyword in `_TACTIC_KEYWORDS` (substring-checked at module load time
# below — `_validate_grammar()` will fail loudly if a synonym would still
# trip a defender keyword for any tactic).
#
# Substring keys are matched case-insensitively. Multi-word keys are
# preserved literally; single-word keys use word-boundary matching so e.g.
# "macro" doesn't replace "macroeconomics" (not that it appears here, but
# the principle is sound).
# ---------------------------------------------------------------------------


# Each value is a deterministic alternate the attacker might use. Picked by
# `(incident_id, keyword)` hash so a single incident is internally consistent
# but the dataset as a whole exercises the grammar broadly.
_SYNONYMS: dict[str, tuple[str, ...]] = {
    # TA0001 — Initial Access
    "initial access": ("first foothold", "entry stage", "ingress beachhead"),
    "phishing": ("ruse mail", "deceptive lure", "ph1sh1ng", "fraudulent outreach"),
    "spear-phish": ("targeted lure", "directed bait", "narrow-cast bait"),
    "spear": ("focused lure", "direct lure", "targeted bait"),
    "watering hole": ("co-opted landing site", "doctored portal", "ambush page"),
    "supply chain": ("vendor-pipeline trojan", "build-pipeline poisoning", "third-party-build poisoning"),
    "valid account": ("legitimate-id reuse", "trusted identity reuse", "clean-id reuse"),
    "external remote service": ("internet-reachable gateway", "outward-facing edge daemon", "edge-facing remote daemon"),
    "drive-by": ("auto-load infection", "passive-landing infection", "no-click landing"),
    "usb": ("rem0vable media", "thumb-stick vector", "portable storage stick"),
    "oauth consent": ("3rd-party-app grant", "delegated-grant abuse", "tenant grant abuse"),
    "social engineering": ("operator deception", "human-factor pretexting", "operator manipulation"),
    "social-engineering": ("operator deception", "human-factor pretexting", "operator manipulation"),
    "vpn login": ("corp tunnel sign-in", "remote-access portal entry", "tunnelled sign-in"),
    "new geography": ("unseen origin region", "anomalous origin", "first-time origin"),
    "compromised npm": ("trojanized js-libs release", "doctored js-libs build", "polluted js-libs feed"),
    "container image": ("workload bundle", "runtime workload artifact", "compute workload bundle"),
    "wire transfer": ("ach instruction", "outgoing remittance", "treasury debit instruction"),

    # TA0002 — Execution
    "execution": ("payload delivery step", "binary launch", "code activation"),
    "powershell": ("p0wer$hell", "p\u200bow\u200bersh\u200bell", "PoSh"),
    "cmd.exe": ("command interpreter binary", "cm\u200bd.exe", "shell-host.exe"),
    "script": ("scr1pt", "automation snippet", "in-line code blob"),
    "macro": ("m@cro", "off1ce-automation routine", "embedded automation routine"),
    "python": ("p\u200bython", "py interpreter", "py-runtime"),
    "node": ("n0de runtime", "n\u200bode.js", "j$-runtime daemon"),
    "certutil": ("cert\u200butil", "windows cert tool", "cert-handling lolbin"),
    "wmi": ("management infra channel", "WM\u200bI", "windows-mgmt-fabric"),
    "wmic": ("wm\u200bic", "mgmt-fabric cli", "windows-mgmt-cli"),
    "mshta": ("ms\u200bhta", "mshta lolbin alt", "trusted-host runner"),
    "process hollow": ("memory-cavity injection", "image substitution into target proc", "in-place process swap"),
    "process create": ("spawn syscall", "child-proc launch", "new-proc materialization"),
    "npm": ("n\u200bpm", "j$-pkg manager", "js dependency manager"),
    "post-install": ("install-time hook", "hook stage after pkg add", "pkg-install hook"),
    "container with": ("workload containing", "image carrying", "bundle containing"),
    "docker run": ("orchestrator launch", "runc launch", "containerd run-cmd"),
    "javascript": ("j$ runtime payload", "es-module payload", "browser-side code"),
    "stage-2 payload": ("second-tier dropper", "follow-on artifact", "next-tier blob"),
    "vba": ("v\u200bba", "off1ce-automation language", "doc-embedded autom"),
    "browser exploitation": ("client-side rendering abuse", "html-engine abuse", "DOM-engine abuse"),

    # TA0003 — Persistence
    "persistence": ("re-establish footing", "reboot survival", "long-term foothold"),
    "registry run": ("hkcu autostart key", "winreg autorun stanza", "reg-autostart entry"),
    "scheduled task": ("schtasks job", "taskscheduler entry", "win-periodic job"),
    "startup": ("st@rtup", "boot-time launch slot", "boot autoload"),
    "service": ("d@emon entry", "long-running unit", "background unit"),
    "implant": ("imp1ant", "long-residence agent", "resident dropper"),
    "backdoor": ("b@ckdoor", "covert callback link", "covert reverse access"),
    "rootkit": ("r00tkit", "kernel-resident hider", "stealth kernel module"),
    "firmware": ("f1rmware", "low-level board code", "below-os layer"),
    "uefi": ("ue\u200bfi", "early-boot f1rmware", "platform pre-boot f1rmware"),
    "cron": ("cr0n", "unix periodic job", "unix sched entry"),
    "wmi event": ("wm\u200bi event", "mgmt-fabric stream", "management-event stream"),
    "permanent wmi": ("perm wm\u200bi", "always-on mgmt stream", "indefinite mgmt stream"),
    "office add-in": ("off1ce plugin slot", "productivity-suite extension", "doc-suite extension"),
    "vsto": ("vs\u200bto", "off1ce add-in tooling", "off1ce plugin tooling"),
    "outlook startup": ("mailer load-time slot", "messaging-app boot slot", "mail-client boot slot"),

    # TA0004 — Privilege Escalation
    "privilege escalation": ("rights step-up", "rights uplift", "level-up of identity"),
    "escalation": ("rights step-up", "level-up", "rights uplift"),
    "escalate": ("step up rights", "gain higher rights", "uplift rights"),
    "container escape": ("workload sandbox break", "namespace breakout", "isolation-layer break"),
    "privileged pod": ("p0werful pod", "host-shared workload", "high-cap pod"),
    "bypass": ("circumvent", "go around", "side-step"),
    "elevation": ("rights step-up", "rights uplift", "perm step-up"),
    "sudo": ("su\u200bdo", "root-shim", "uplifted-shim"),
    "uac bypass": ("ua\u200bc circumvention", "consent-prompt sidestep", "security-prompt sidestep"),
    "uac": ("ua\u200bc", "consent prompt", "security prompt"),
    "fodhelper": ("f0dhelper", "trusted helper binary", "feature-on-demand helper"),
    "suid": ("su\u200bid", "setuser bit", "setid-perm bit"),
    "metadata service": ("im\u200bds endpoint", "m\u200betadata svc", "instance-info endpoint"),

    # TA0005 — Defense Evasion
    "defense evasion": ("av-d0dging", "control-skirting", "telemetry-d0dging"),
    "obfuscat": ("scr@mbl", "deob h@rd'n", "morph"),
    "fileless": ("on-disk-less", "no-disk-write", "ram-resident-only"),
    "memory-only": ("ram-resident", "in-mem-only", "no on-disk artifact"),
    "memory only": ("ram resident", "in mem only", "no on-disk artifact"),
    "hollowing": ("h0llowing", "memory-cavity swap", "in-place image swap"),
    "side-load": ("s1de-load", "hijack legit-binary lookup chain", "search-order load t@mpering"),
    "dll": ("d\u200bll", "dynamic library", "loadable code module"),
    "masquerad": ("disguis", "imitat", "sp00f"),
    "encode": ("base64-wrap", "byte-wrap", "transform"),
    "pack": ("p@ck", "c0mpress", "wr@p"),
    "log cleared": ("logs purged", "audit history erased", "telemetry erased"),
    "wevtutil": ("we\u200bvtutil", "win event tool", "win-log cli"),
    "journalctl": ("j0urnalctl", "systemd journal cli", "systemd log cli"),
    "vacuum": ("v@cuum", "c0mpact db", "c0mpress-truncate"),
    "indicator removal": ("evidence cleanup", "trace cleanup", "footprint cleanup"),
    "tampering": ("altering", "modify-on-the-fly", "d0ctoring"),
    "stop defender": ("disable mde-agent", "halt windows av", "kill av-agent"),
    "stop crowdstrike": ("disable cs-falcon", "halt edr-agent", "kill edr-sensor"),
    "stop sysmon": ("disable sysmon-agent", "halt sysmon-collector", "kill sysmon-svc"),
    "secure boot": ("s\u200becure boot", "verified boot chain", "boot integrity"),

    # TA0006 — Credential Access
    "credential": ("cred", "auth-token", "login secret"),
    "brute force": ("repeated guess", "iterative login attempt", "dictionary attack"),
    "brute-force": ("repeated-guess", "iterative-login", "dict-attempt"),
    "kerberoast": ("kerb-ticket abuse", "kerb-ticket roast", "kerb-ticket grind"),
    "dcsync": ("dc-replica-pull abuse", "directory replica abuse", "msrpc replica-pull abuse"),
    "lsass": ("l$ass", "auth subsystem proc", "session-mgmt proc"),
    "minidump": ("mini-d\u200bump", "process snapshot", "proc-snapshot"),
    "dump": ("d\u200bump", "snapshot of proc memory", "proc-mem snapshot"),
    "harvest": ("scrap", "skim", "lift"),
    "password reset": ("pw rotation request", "self-serve cred change", "cred rotation request"),
    "password spray": ("low-and-slow login attempt", "quiet cred probe", "spread-out login attempts"),
    "credential spray": ("cred low-and-slow", "auth-token probe spread", "spread-out cred probe"),
    "saml": ("s@ml", "federation token", "fed-assertion"),
    "oauth": ("0auth", "tenant grant", "delegated grant"),
    "ntlm": ("n\u200btlm", "ms-auth legacy", "challenge-response auth"),
    "mimikatz": ("m1m1katz", "secrets extractor", "auth-secrets puller"),
    "pat": ("p@t", "github-token", "ci-token"),
    "personal access token": ("dev-portal token", "self-issued bearer token", "user-issued api token"),
    "refresh token": ("re-fresh tok\u200ben", "long-lived auth handle", "session-extension token"),
    "imds": ("im\u200bds", "instance metadata svc", "instance-info endpoint"),
    "session token": ("ses\u200bsion token", "auth-cookie", "bearer for active session"),
    "stolen session": ("hijacked sess1on", "co-opted active sess", "session-takeover"),
    "tgs": ("tg\u200bs", "kerb svc ticket", "svc-ticket"),

    # TA0007 — Discovery
    "discovery": ("scout-stage", "look-around stage", "environment-mapping"),
    "enumerat": ("listing-out", "walking the directory", "iterating across"),
    "scan": ("sweep", "probe-pass", "fingerprint-pass"),
    "account discovery": ("user-listing", "principal-listing", "identity-listing"),
    "network share": ("smb mount", "remote folder", "fileshare mount"),
    "recon": ("rec0n", "look-around stage", "environment-mapping"),
    "replication": ("dir-sync abuse", "ad-sync abuse", "directory replica use"),
    "ldap": ("l\u200bdap", "directory protocol", "x.500 query"),
    "bloodhound": ("bl0odhound", "ad-graph mapper", "ad-relationship mapper"),
    "smb share": ("smb mount", "remote folder mount", "fileshare mount"),
    "share enum": ("mount listing", "fileshare listing", "smb-volume listing"),
    "system info": ("host fingerprinting", "host-detail pull", "machine-detail pull"),

    # TA0008 — Lateral Movement
    "lateral movement": ("east-west pivot", "horizontal hop", "side-to-side traversal"),
    "lateral": ("e-w hop", "horizontal", "side-to-side"),
    "rdp": ("r\u200bdp", "remote desktop sess", "ts/mstsc sess"),
    "pass-the-hash": ("hash-replay attack", "auth-hash replay", "secret-hash replay"),
    "pass the hash": ("hash replay attack", "auth hash replay", "secret hash replay"),
    "remote service": ("over-network svc invoke", "ms-rpc remote call", "rpc remote call"),
    "pivoting": ("p1voting", "pivot-host hop", "in-network hop"),
    "ssh": ("s\u200bsh", "secure shell", "openssh session"),
    "smb scan": ("smb sweep", "fileshare probe", "windows-share probe"),
    "wmic /node": ("wm\u200bic /machine", "mgmt-cli /remote", "mgmt-fabric cli /remote"),
    "wmi remote": ("wm\u200bi remote", "mgmt-fabric remote", "remote mgmt-fabric"),

    # TA0009 — Collection
    "collection": ("data-gathering stage", "skim stage", "asset-pull stage"),
    "data from local": ("data lifted from host", "local-host data pull", "on-host data pull"),
    "screenshot": ("screen-capture", "ui snapshot", "display-grab"),
    "keylog": ("keystroke-capture", "input-capture", "kb-monitor"),
    "clipboard": ("paste buffer", "copy-buffer", "clip-store"),
    "bulk download": ("mass pull", "batch fetch", "wholesale fetch"),
    "pii": ("p\u200bii", "personal data", "user identity data"),
    "customer record": ("customer row", "client account row", "subscriber record"),
    "mailbox export": ("inbox extract", "mailstore export", "messaging-store export"),
    "pst": ("p\u200bst", "outlook archive", "mail archive"),
    "private repo": ("internal source repo", "non-public repo", "closed repo"),
    "private repos": ("internal source repos", "non-public repos", "closed repos"),

    # TA0010 — Exfiltration
    "exfiltrat": ("ex-bound transfer", "outbound siphon", "ex-bound siphon"),
    "c2 channel": ("operator channel", "comms-back tunnel", "callback channel"),
    "cloud storage": ("object storage uplink", "blob-store push target", "external bucket"),
    "dns tunnel": ("dns covert tunnel", "udp/53 covert track", "dns covert track"),
    "ftp": ("f\u200btp", "file-xfer protocol", "legacy file-transfer"),
    "upload": ("up\u200bload", "outbound transfer", "push-out"),
    "egress": ("outbound flow", "ex-bound flow", "outward traffic"),
    "google drive": ("g\u200bdrive", "drive-shared bucket", "consumer-cloud drive"),
    "drive upload": ("drive push", "drive transfer", "drive sync-up"),
    "personal drive": ("personal cloud bucket", "consumer cloud bucket", "non-corp drive"),
    "transfer to": ("xfer to", "push to", "ship to"),
    "s3 bucket": ("object-store bucket", "blob-store bucket", "aws object store"),
    "s3://": ("aws://obj/", "object-store-uri", "blob-uri"),
    "data egress": ("outbound data flow", "ex-bound data flow", "data outflow"),

    # TA0011 — Command and Control
    "command and control": ("operator-channel", "callback infra", "ops-channel"),
    "c2": ("c\u200b2", "ops channel", "callback infra"),
    "beacon": ("b\u200beacon", "callback ping", "regular check-in"),
    "c&c": ("c\u200b&c", "ops channel", "callback infra"),
    "dga": ("d\u200bga", "domain-gen algorithm", "algorithmic domains"),
    "domain generation": ("algorithmic domain rotation", "rotating-domain algo", "domain-rotation algo"),
    "dns query": ("d\u200bns query", "name-resolution", "name lookup"),
    "covert channel": ("covert-comms link", "stealthy backchannel", "hidden link"),
    "cobalt strike": ("c0balt strike", "crimson-team toolkit", "red-team-grade dropper"),
    "https beacon": ("tls callback", "https callback", "tls heartbeat"),
    "ja3": ("j@3", "tls fingerprint hash", "tls-handshake fingerprint"),

    # TA0040 — Impact
    "impact": ("damage stage", "harm stage", "ko stage"),
    "ransom": ("ext0rt", "lockout-for-pay", "data-lockout demand"),
    "encrypt": ("scr@mble", "lock-with-key", "cipher-lock"),
    "wipe": ("zero-out", "shred", "scrub"),
    "destroy": ("annihilate", "deletion-pass", "purge"),
    "disrupt": ("d1srupt", "knock-offline", "make-unavailable"),
    "defacement": ("page-graffiti", "site replacement", "homepage swap"),
    "miner": ("c0in-miner", "compute-hijacking process", "cycles-stealing process"),
    "cryptomine": ("c0in-mining", "compute hijack for currency", "cycles for currency"),
    "xmrig": ("xm\u200brig", "monero-grade c0in-tool", "c0in-tool suite"),
    "ddos": ("d\u200bdos", "flood attack", "volumetric flood"),
    "syn flood": ("tcp-half-open flood", "tcp synflood", "tcp half-open swarm"),
    "wire transfer": ("ach payment instruction", "outgoing remittance", "treasury debit instruction"),
    "$250": ("a quarter-million-dollar", "USD250000", "two-fifty-K"),
    "bec": ("b\u200bec", "exec-impersonation fraud", "boss-impersonation fraud"),
}


# Light obfuscation only — leetspeak, used for the "light" intensity bucket
# so the defender SHOULD still catch most cases there.
_LIGHT_LEET: dict[str, str] = {
    "phishing": "phi$hing",
    "powershell": "powershell",  # untouched — light tier
    "execution": "execution",     # untouched — light tier
    "credential": "credentia1",
    "exfiltrat": "exfiltrat",     # untouched — light tier
}


# ---------------------------------------------------------------------------
# Grammar validation — refuse to ship if a synonym would itself match a
# defender keyword for a tactic. This means "graceful degradation" is the
# only failure mode; we never accidentally trip a different tactic.
# ---------------------------------------------------------------------------


def _validate_grammar() -> None:
    """Make sure no synonym alternate contains a defender keyword."""
    flat_keywords: list[str] = []
    for kws in _TACTIC_KEYWORDS.values():
        flat_keywords.extend(k.lower() for k in kws)

    failures: list[str] = []
    for src, alternates in _SYNONYMS.items():
        for alt in alternates:
            low = alt.lower()
            for kw in flat_keywords:
                # Same keyword self-match is fine (it's the original word
                # we're rewriting), but any *other* keyword landing inside
                # the alternate is a leak.
                if kw == src.lower():
                    continue
                if kw in low:
                    failures.append(
                        f"alternate '{alt}' for '{src}' still contains keyword '{kw}'"
                    )
    if failures:
        msg = "\n  - ".join(failures[:20])
        raise RuntimeError(
            f"Adversary mutator grammar leaks defender keywords:\n  - {msg}"
        )


_validate_grammar()


# ---------------------------------------------------------------------------
# Mutation engine
# ---------------------------------------------------------------------------


# Ordered by descending length so multi-word keys are matched before their
# single-word substrings (e.g. "spear-phish" before "spear", "wmi event"
# before "wmi"). This is critical for correctness.
_KEY_ORDER: list[str] = sorted(_SYNONYMS.keys(), key=len, reverse=True)

# Pre-compile case-insensitive regexes per key. We escape the key directly
# (no word boundaries — many keys contain punctuation like "cmd.exe" or
# "s3://" where word boundaries fight us).
_KEY_REGEX: dict[str, re.Pattern[str]] = {
    k: re.compile(re.escape(k), re.IGNORECASE) for k in _KEY_ORDER
}


def _bucket(incident_id: str) -> str:
    """Pick a mutation intensity bucket deterministically per incident.

    Distribution targets:
        heavy   ≈ 45%   — every keyword swapped for both expected tactics
        medium  ≈ 35%   — one tactic preserved cleanly, others mutated
        light   ≈ 20%   — light leetspeak; defender should still catch

    The 45/35/20 split lands the eval near the ~0.55 graceful-degradation
    floor with comfortable headroom for either side.
    """
    h = int(hashlib.sha256(incident_id.encode()).hexdigest()[:8], 16)
    bucket_pct = h % 100
    if bucket_pct < 45:
        return "heavy"
    if bucket_pct < 80:
        return "medium"
    return "light"


def _pick_alternate(key: str, incident_id: str) -> str:
    """Pick one of the deterministic alternates for `key`."""
    alts = _SYNONYMS[key]
    h = int(hashlib.sha256(f"{incident_id}|{key}".encode()).hexdigest()[:8], 16)
    return alts[h % len(alts)]


def _mutate_text_full(text: str, incident_id: str) -> str:
    """Replace every keyword in `text` with its deterministic alternate."""
    out = text
    for key in _KEY_ORDER:
        pattern = _KEY_REGEX[key]
        if pattern.search(out):
            alt = _pick_alternate(key, incident_id)
            out = pattern.sub(alt, out)
    return out


def _mutate_text_partial(
    text: str, incident_id: str, preserve_tactics: set[str]
) -> str:
    """Mutate keywords EXCEPT those tied to one preserved tactic.

    The defender still has at least one route to detect the incident.
    """
    preserve_keywords = {
        kw.lower()
        for tactic in preserve_tactics
        for kw in _TACTIC_KEYWORDS.get(tactic, [])
    }
    out = text
    for key in _KEY_ORDER:
        if key.lower() in preserve_keywords:
            continue
        pattern = _KEY_REGEX[key]
        if pattern.search(out):
            alt = _pick_alternate(key, incident_id)
            out = pattern.sub(alt, out)
    return out


def _mutate_text_light(text: str) -> str:
    """Apply light leetspeak that should NOT defeat the defender.

    Used as a control bucket — confirms the defender can still extract
    tactics under low-grade obfuscation, so a regression on the heavy
    bucket can't be masked by the light tier silently failing too.
    """
    out = text
    for src, dst in _LIGHT_LEET.items():
        out = re.sub(re.escape(src), dst, out, flags=re.IGNORECASE)
    return out


def mutate_incident(incident: dict[str, Any]) -> dict[str, Any]:
    """Return an adversarially-mutated copy of `incident`."""
    incident_id = incident["id"]
    bucket = _bucket(incident_id)
    expected_tactics: list[str] = list(incident.get("expected_tactics", []))

    if bucket == "heavy":
        new_title = _mutate_text_full(incident["title"], incident_id)
        new_description = _mutate_text_full(incident["description"], incident_id)
    elif bucket == "medium":
        if expected_tactics:
            # Preserve the LAST expected tactic deterministically.
            preserve_idx = (
                int(hashlib.sha256(incident_id.encode()).hexdigest()[8:16], 16)
                % len(expected_tactics)
            )
            preserve = {expected_tactics[preserve_idx]}
        else:
            preserve = set()
        new_title = _mutate_text_partial(incident["title"], incident_id, preserve)
        new_description = _mutate_text_partial(
            incident["description"], incident_id, preserve
        )
    else:
        new_title = _mutate_text_light(incident["title"])
        new_description = _mutate_text_light(incident["description"])

    return {
        # Keep the same id space so the eval suite can correlate with the
        # base dataset — that lets us do "which template lost coverage
        # under adversary?" diffs.
        "id": incident_id,
        "template_id": incident.get("template_id"),
        "template_index": incident.get("template_index"),
        "adversary_intensity": bucket,
        "title": new_title,
        "description": new_description,
        "expected_tactics": expected_tactics,
        "expected_techniques": list(incident.get("expected_techniques", [])),
        "severity": incident.get("severity"),
        "response_class": incident.get("response_class"),
        "evidence_keywords": list(incident.get("evidence_keywords", [])),
        "original_title": incident["title"],
        "original_description": incident["description"],
    }


def mutate_dataset(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [mutate_incident(inc) for inc in incidents]


# ---------------------------------------------------------------------------
# Reporting helpers (used by --report and by the eval suite)
# ---------------------------------------------------------------------------


def adversary_coverage_report(
    mutated: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarise how many incidents lost detectable tactics under mutation.

    The defender's keyword extractor is run BOTH on the original and on the
    mutated description so we can quantify graceful-degradation.
    """
    bucket_counts = {"heavy": 0, "medium": 0, "light": 0}
    correct_total = 0
    lost_all_total = 0
    per_tactic_lost: dict[str, int] = {}
    per_template_correct: dict[str, dict[str, int]] = {}

    for inc in mutated:
        bucket_counts[inc["adversary_intensity"]] += 1
        expected = set(inc["expected_tactics"])
        text = f"{inc['title']}\n{inc['description']}"
        predicted = extract_tactics_from_text(text)
        overlap = predicted & expected
        if overlap:
            correct_total += 1
        else:
            lost_all_total += 1

        for t in expected:
            if t not in predicted:
                per_tactic_lost[t] = per_tactic_lost.get(t, 0) + 1

        tpl = inc.get("template_id") or "<unknown>"
        slot = per_template_correct.setdefault(tpl, {"correct": 0, "total": 0})
        slot["total"] += 1
        if overlap:
            slot["correct"] += 1

    n = len(mutated)
    return {
        "incidents": n,
        "buckets": bucket_counts,
        "defender_correct": correct_total,
        "defender_lost_all_tactics": lost_all_total,
        "defender_accuracy": round(correct_total / n, 4) if n else 0.0,
        "per_tactic_lost": dict(sorted(per_tactic_lost.items())),
        "per_template": {
            t: {
                "correct": v["correct"],
                "total": v["total"],
                "accuracy": round(v["correct"] / v["total"], 4) if v["total"] else 0.0,
            }
            for t, v in sorted(per_template_correct.items())
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate the adversary-mutated incident dataset (Wave 2 — w2-aivai)."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=_DEFAULT_INPUT,
        help="Path to base synthetic_incidents.json (default: services/agents/tests/eval_data/synthetic_incidents.json)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=_DEFAULT_OUTPUT,
        help="Path to write adversary_incidents.json",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print a coverage / graceful-degradation report alongside writing the file.",
    )
    args = parser.parse_args()

    if not args.input.exists():
        sys.exit(
            f"input not found: {args.input}. Run scripts/generate_eval_incidents.py first."
        )

    base = json.loads(args.input.read_text())
    mutated = mutate_dataset(base)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(mutated, indent=2) + "\n")

    if args.report:
        report = adversary_coverage_report(mutated)
        print()
        print("=" * 78)
        print("  AiSOC AI-vs-AI adversary dataset — graceful-degradation report")
        print("=" * 78)
        print(f"  Incidents:                {report['incidents']}")
        print(
            f"  Bucket split:             "
            f"heavy={report['buckets']['heavy']}, "
            f"medium={report['buckets']['medium']}, "
            f"light={report['buckets']['light']}"
        )
        print(
            f"  Defender catch rate:      {report['defender_correct']}"
            f"/{report['incidents']} = {report['defender_accuracy'] * 100:.1f}%"
        )
        print(
            f"  Defender lost-everything: "
            f"{report['defender_lost_all_tactics']} incidents"
        )
        print()
        print("  Tactics most-lost under mutation:")
        for t, n in sorted(
            report["per_tactic_lost"].items(), key=lambda kv: kv[1], reverse=True
        )[:8]:
            print(f"    {t}: -{n}")
        print("=" * 78)
    print(f"wrote {len(mutated)} mutated incidents to {args.out}")


if __name__ == "__main__":
    main()
