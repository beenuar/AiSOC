#!/usr/bin/env python3
"""Rules that still cannot fire after depth plan 3.3, and exactly why.

3.3 asked for three enrichment inputs and said of one of them: *"build them
where cheap, otherwise quarantine with a reason."* That instruction is the
shape of this file, applied to all three families.

What was built
--------------
* **Identity privilege** (`services/fusion/app/services/tenant_overlay.py`),
  from `identity_nodes.privilege_tier`. Closed 18 rules.
* **First-seen** (`services/fusion/app/services/first_seen.py`), per tenant in
  Redis. Closed 2 rules.
* **A gate-drift fix.** Five rules were never unreachable: the reachability
  gate's operator list had not been given `neq` when the matcher was, so
  `approver_role_neq` was read as a field name instead of as `approver_role`
  with `!=`.

What is left, and why each one is a refusal rather than a fix
-------------------------------------------------------------
Eighteen rules. Every one needs something that belongs to a different piece
of work, named per entry. They keep their id and their YAML and stop being
counted as executable, which they never were.

The line this file holds, and the reason it matters more than the count: a
plausible substitute is worse than an absence. `domain_age_days` wants a
domain's registration age from a registry. The first-seen store could answer
"the first time this deployment saw it" and the number would look right in a
diff — and the rule would then fire on every domain a quiet tenant had not
happened to see, which is most of the internet. Refusing is the correct
engineering answer, not the lazy one.
"""

from __future__ import annotations

from dataclasses import dataclass

# `KINDS` belongs here: `check_enrichment_decisions.py` reads it as
# `module.KINDS` after loading this file by path, which no static
# analysis can follow — CodeQL reported it as an unused global. Naming
# it as an export is both true and the thing that makes the use visible.
__all__ = ["DECISIONS", "KINDS", "NEEDS_CONNECTOR_FIELD", "NEEDS_EXTERNAL_SOURCE", "NEEDS_INVENTORY", "Refusal"]

#: The field exists at the vendor and no connector surfaces it. Closing these
#: is the activity projection of depth plan 2.2.
NEEDS_CONNECTOR_FIELD = "needs-connector-field"

#: The answer lives outside any telemetry: a registry, a directory snapshot,
#: a vendor configuration API. Depth plan 2.5 for posture, elsewhere for the
#: rest.
NEEDS_EXTERNAL_SOURCE = "needs-external-source"

#: The answer needs an inventory this platform does not hold — which machine
#: accounts are domain controllers, which OAuth scopes are privileged.
NEEDS_INVENTORY = "needs-inventory"

KINDS = frozenset({NEEDS_CONNECTOR_FIELD, NEEDS_EXTERNAL_SOURCE, NEEDS_INVENTORY})


@dataclass(frozen=True)
class Refusal:
    kind: str
    reason: str


DECISIONS: dict[str, Refusal] = {
    # ── comparisons whose operands nothing emits ────────────────────────
    "application/api-permission-bypass-idor": Refusal(
        NEEDS_CONNECTOR_FIELD,
        "compares the object's owning tenant with the caller's, and no application "
        "source in this tree surfaces either. The engine can compare two fields of "
        "one event; it cannot compare two fields that are not there.",
    ),
    "endpoint/linux-bashrc-modified-by-other-user": Refusal(
        NEEDS_CONNECTOR_FIELD,
        "compares the acting uid with the file owner's uid. The acting uid is "
        "emitted and the owner's is not, so the comparison resolves to nothing. "
        "An EDR file-write event carries the owner; surfacing it is connector work.",
    ),
    "endpoint/linux-zshrc-modified-by-other-user": Refusal(
        NEEDS_CONNECTOR_FIELD,
        "compares the acting uid with the file owner's uid, and no source emits the owner. Same gap as the bashrc rule beside it.",
    ),
    "endpoint/macos-keychain-db-read-by-other-uid": Refusal(
        NEEDS_CONNECTOR_FIELD,
        "compares the reading uid with the keychain owner's uid, and no source emits the owner.",
    ),
    "identity/ident-pim-activation-self-approval": Refusal(
        NEEDS_CONNECTOR_FIELD,
        "compares the approver with the requester. The requester is emitted as "
        "`actor`; no identity source in this tree emits the approver, so a "
        "self-approval cannot be distinguished from an approval.",
    ),
    "identity/ident-ntlm-relay-indicator": Refusal(
        NEEDS_CONNECTOR_FIELD,
        "compares the workstation named in the logon with the address it came from. "
        "Windows 4624 carries both as `WorkstationName` and `IpAddress`; neither is "
        "lifted as a top-level field, so neither side of the comparison resolves.",
    ),
    "identity/ident-pass-the-ticket-anomalous-tgt-source": Refusal(
        NEEDS_CONNECTOR_FIELD,
        "compares the address a Kerberos ticket was issued to with the address using "
        "it. That needs two events joined on the ticket, which is a correlation, and "
        "neither address is emitted today.",
    ),
    # ── ages of a thing, which a first-seen store must not guess ────────
    "application/app-npm-package-publish-new-account": Refusal(
        NEEDS_EXTERNAL_SOURCE,
        "wants the publisher account's age at the registry. The first-seen store "
        "knows when this deployment first saw the account, which is a different "
        "number: substituting it would fire on every publisher a quiet tenant has "
        "not seen before.",
    ),
    "cloud/aws-iam-key-rotation-skipped": Refusal(
        NEEDS_EXTERNAL_SOURCE,
        "wants an access key's creation date. CloudTrail reports key *use* and not "
        "key age; the date is in the IAM credential report, which arrives with the "
        "AWS posture snapshot (depth plan 2.5).",
    ),
    "cloud/aws-cloudfront-origin-changed": Refusal(
        NEEDS_EXTERNAL_SOURCE,
        "wants a distribution's creation date, which is configuration state rather "
        "than an event, and arrives with the AWS posture snapshot (depth plan 2.5).",
    ),
    "identity/ident-fido2-key-added-then-removed-old": Refusal(
        NEEDS_EXTERNAL_SOURCE,
        "wants the enrolment age of the factor being removed. The IdP holds it on the factor record; no audit event carries it.",
    ),
    "network/newly-registered-domain-traffic": Refusal(
        NEEDS_EXTERNAL_SOURCE,
        "wants a domain's registration age, which comes from RDAP or WHOIS. Nothing "
        "in this tree queries either, and answering it from when this deployment "
        "first saw the domain would fire on most of the internet.",
    ),
    "network/net-dns-newly-registered-domain": Refusal(
        NEEDS_EXTERNAL_SOURCE,
        "wants a domain's registration age from RDAP or WHOIS, which nothing here queries. Same gap as the proxy-side rule beside it.",
    ),
    # ── privilege questions with no subject on the event ────────────────
    "endpoint/win-dcsync-via-replication": Refusal(
        NEEDS_INVENTORY,
        "asks whether the replicating account is a domain controller. That needs a "
        "directory inventory of DC machine accounts; `identity_nodes` carries a "
        "privilege tier per principal and no such flag.",
    ),
    "identity/ident-session-timeout-extended-priv": Refusal(
        NEEDS_INVENTORY,
        "asks whether a policy's scope is privileged. The scope is emitted; what is "
        "missing is a list of which scopes are privileged, which no source provides "
        "and no tenant configures today.",
    ),
    "identity/ident-app-impersonation-priv": Refusal(
        NEEDS_CONNECTOR_FIELD,
        "asks whether the impersonated user is privileged. The privilege lookup now "
        "exists; the impersonated user is not emitted by any source, so there is no "
        "subject to look up.",
    ),
    "identity/ident-ad-gpo-modified-priv": Refusal(
        NEEDS_INVENTORY,
        "asks whether a modified GPO is linked to a privileged scope. Neither the GPO link nor a list of privileged scopes exists here.",
    ),
    # ── other ───────────────────────────────────────────────────────────
    "identity/ident-svc-account-interactive-login": Refusal(
        NEEDS_CONNECTOR_FIELD,
        "asks whether a logon was interactive. Windows 4624 answers it in "
        "`LogonType` (2, 10 and 11 are interactive) and no source lifts that field, "
        "so the boolean has nothing to derive from.",
    ),
}
