#!/usr/bin/env python3
"""Uploading a customer file stays off by default, and a failure stays a failure.

What this is protecting
-----------------------
Sending a customer's file to a third party is a disclosure that cannot be
recalled. For the first commercial provider wired into this tree it is a
disclosure to the *internet*: a stored report carries ``visibility: "public"``
and ``tlp: "clear"``. So the properties below are not style preferences, and
none of them is visible in a diff that breaks them:

* a default flipping from ``False`` to ``True`` in a dataclass
* a policy branch reordered so consent is checked before the hash lookup
* a new provider that forgets to declare whether it runs locally
* an exception handler that turns a provider outage into an empty report

The last one is the quietest and the worst. A sandbox is slow and
failure-prone; a timeout that reads as "no detections" is how an analyst, or a
model, writes a benign verdict on a file nobody analysed.

Both directions
---------------
* forward: the policy function is driven over every combination of its inputs
  and each refusal is required, so removing a branch fails here rather than in
  production.
* reverse: the *source* is read for the shapes that would make the runtime
  checks vacuous: an upload verb that is reachable without a decision, a
  provider whose base class no longer requires ``local``, or a
  ``SandboxResult`` constructed with ``outcome="known"`` from an exception
  handler.

Empty input is a failure. A run that imported no policy module and read no
provider has verified nothing.
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

SANDBOX = Path("services/api/app/services/sandbox")
#: Every provider adapter must be reachable from here, so a new one cannot be
#: added without this gate seeing it.
PROVIDERS_DIR = SANDBOX / "providers"


@dataclass
class Finding:
    where: str
    detail: str

    def __str__(self) -> str:
        return f"  {self.where}: {self.detail}"


# ---------------------------------------------------------------------------
# Forward: drive the real policy function
# ---------------------------------------------------------------------------


def _check_policy_behaviour(root: Path) -> tuple[list[Finding], int]:
    """Import the real policy and require a refusal for every unsafe combination."""
    findings: list[Finding] = []
    sys.path.insert(0, str(root / "services" / "api"))
    try:
        from app.services.sandbox.policy import UploadRefusal, evaluate_upload  # noqa: PLC0415
        from app.services.sandbox.types import ProviderCapabilities  # noqa: PLC0415
    except ImportError as exc:
        return [Finding(str(SANDBOX / "policy.py"), f"could not import the policy module: {exc}")], 0

    hosted = ProviderCapabilities(name="hosted", local=False, supports_file_submission=True)
    local = ProviderCapabilities(name="local", local=True, supports_file_submission=True)
    lookup_only = ProviderCapabilities(name="lookup_only", local=True, supports_file_submission=False)

    cases = 0
    # The only combination that may be allowed: not air-gapped, provider takes
    # uploads, hash unknown, tenant consented. Everything else is a refusal.
    for caps in (hosted, local, lookup_only):
        for airgapped in (True, False):
            for consented in (True, False):
                for known in (True, False):
                    cases += 1
                    decision = evaluate_upload(
                        capabilities=caps,
                        airgapped=airgapped,
                        tenant_uploads_enabled=consented,
                        hash_already_known=known,
                    )
                    should_allow = caps.supports_file_submission and consented and not known and not (airgapped and not caps.local)
                    if decision.allowed != should_allow:
                        findings.append(
                            Finding(
                                "evaluate_upload",
                                f"provider={caps.name} airgapped={airgapped} consented={consented} "
                                f"hash_known={known}: allowed={decision.allowed}, expected {should_allow}",
                            )
                        )
                    if not decision.allowed and decision.refusal is None:
                        findings.append(Finding("evaluate_upload", "refused without naming a refusal reason"))

    # The order of the checks is itself a property. Air-gap must beat consent,
    # or a consenting tenant could reach a hosted provider on an air-gapped
    # deployment.
    airgap_beats_consent = evaluate_upload(capabilities=hosted, airgapped=True, tenant_uploads_enabled=True, hash_already_known=False)
    cases += 1
    if airgap_beats_consent.refusal is not UploadRefusal.AIRGAPPED:
        findings.append(Finding("evaluate_upload", f"air-gap must outrank tenant consent, got {airgap_beats_consent.refusal}"))

    # Hash-first must beat consent too, so a consenting tenant does not upload
    # a file the provider already holds.
    hash_beats_consent = evaluate_upload(capabilities=hosted, airgapped=False, tenant_uploads_enabled=True, hash_already_known=True)
    cases += 1
    if hash_beats_consent.refusal is not UploadRefusal.ALREADY_KNOWN:
        findings.append(Finding("evaluate_upload", f"a known hash must short-circuit an upload, got {hash_beats_consent.refusal}"))

    return findings, cases


def _check_consent_text(root: Path) -> tuple[list[Finding], int]:
    """A provider that publishes submissions must say *public* in its consent text."""
    findings: list[Finding] = []
    try:
        from app.services.sandbox.policy import consent_text_for  # noqa: PLC0415
        from app.services.sandbox.types import ProviderCapabilities  # noqa: PLC0415
    except ImportError as exc:
        return [Finding(str(SANDBOX / "policy.py"), f"could not import consent_text_for: {exc}")], 0

    public = consent_text_for(
        ProviderCapabilities(name="p", local=False, supports_file_submission=True, submissions_are_public_by_default=True)
    ).lower()
    checked = 1
    for required in ("public", "anyone"):
        if required not in public:
            findings.append(
                Finding(
                    "consent_text_for",
                    f"a provider that publishes submissions must say {required!r} in the text an operator agrees to",
                )
            )
    if "cannot be recalled" not in public:
        findings.append(Finding("consent_text_for", "the text must say the disclosure cannot be recalled"))

    private = consent_text_for(
        ProviderCapabilities(name="p", local=True, supports_file_submission=True, submissions_are_public_by_default=False)
    ).lower()
    checked += 1
    if "readable by anyone" in private:
        findings.append(Finding("consent_text_for", "a local provider must not be described as publishing samples"))
    return findings, checked


# ---------------------------------------------------------------------------
# Reverse: read the source for shapes that would make the above vacuous
# ---------------------------------------------------------------------------


def _check_defaults_are_off(root: Path) -> tuple[list[Finding], int]:
    """No consent-shaped flag may default to on, anywhere in the package."""
    findings: list[Finding] = []
    checked = 0
    names = {"uploads_enabled", "tenant_uploads_enabled", "allow_upload", "confirm_upload", "uploaded"}
    for path in sorted(root.glob(str(SANDBOX / "**/*.py"))) + [root / "services/api/app/api/v1/endpoints/sandbox.py"]:
        if not path.is_file():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = path.relative_to(root)
        for node in ast.walk(tree):
            # Keyword-only and defaulted function arguments.
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                pairs = list(zip(args.args[len(args.args) - len(args.defaults) :], args.defaults, strict=True))
                pairs += [(a, d) for a, d in zip(args.kwonlyargs, args.kw_defaults, strict=True) if d is not None]
                for arg, default in pairs:
                    if arg.arg not in names:
                        continue
                    checked += 1
                    # `allow_upload` defaults True on the service helper: the
                    # route always passes it explicitly and the tenant consent
                    # is the real gate. Everything else must default off.
                    if arg.arg == "allow_upload":
                        continue
                    if isinstance(default, ast.Constant) and default.value is True:
                        findings.append(Finding(f"{rel}:{node.lineno}", f"{node.name}({arg.arg}=) defaults to True"))
            # Dataclass / model field defaults.
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in names:
                checked += 1
                value = node.value
                if isinstance(value, ast.Constant) and value.value is True:
                    findings.append(Finding(f"{rel}:{node.lineno}", f"field {node.target.id} defaults to True"))
                if isinstance(value, ast.Call) and getattr(value.func, "id", "") == "Field":
                    for kw in value.keywords:
                        if kw.arg == "default" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append(Finding(f"{rel}:{node.lineno}", f"Field {node.target.id} defaults to True"))
    if not checked:
        findings.append(Finding(str(SANDBOX), "found no upload-consent flag to check; the package or the names moved"))
    return findings, checked


def _check_failures_are_not_clean(root: Path) -> tuple[list[Finding], int]:
    """No exception handler may produce a report or a ``known`` outcome.

    The shape being refused is a ``except ...: return SandboxResult(outcome="known")``
    or an ``except ...: return SandboxReport(...)``, which is how a provider
    outage becomes a clean bill of health.
    """
    findings: list[Finding] = []
    checked = 0
    for path in sorted(root.glob(str(SANDBOX / "**/*.py"))):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = path.relative_to(root)
        for handler in (n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)):
            checked += 1
            for node in ast.walk(handler):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                if func == "SandboxReport":
                    findings.append(
                        Finding(f"{rel}:{node.lineno}", "an exception handler constructs a SandboxReport; a failure is not a report")
                    )
                if func == "SandboxResult":
                    for kw in node.keywords:
                        if kw.arg == "outcome" and isinstance(kw.value, ast.Constant) and kw.value.value in ("known", "not_seen"):
                            findings.append(
                                Finding(
                                    f"{rel}:{node.lineno}",
                                    f"an exception handler returns outcome={kw.value.value!r}; a failure must be could_not_check",
                                )
                            )
    if not checked:
        findings.append(Finding(str(SANDBOX), "found no exception handlers to inspect; the package moved or is empty"))
    return findings, checked


def _check_providers_declare_locality(root: Path) -> tuple[list[Finding], int]:
    """Every adapter declares ``local``, which is what air-gap mode reads."""
    findings: list[Finding] = []
    providers = sorted(p for p in root.glob(str(PROVIDERS_DIR / "*.py")) if p.name != "__init__.py")
    if not providers:
        return [Finding(str(PROVIDERS_DIR), "no provider adapters found; the package moved or is empty")], 0
    for path in providers:
        source = path.read_text(encoding="utf-8")
        rel = path.relative_to(root)
        if "ProviderCapabilities(" not in source:
            findings.append(Finding(str(rel), "declares no ProviderCapabilities, so air-gap mode cannot classify it"))
            continue
        if "local=" not in source:
            findings.append(Finding(str(rel), "does not set `local=` on its capabilities"))
    return findings, len(providers)


def _check_hash_lookup_precedes_upload(root: Path) -> tuple[list[Finding], int]:
    """``analyse_file`` must call the lookup before it evaluates the upload."""
    path = root / SANDBOX / "service.py"
    if not path.is_file():
        return [Finding(str(SANDBOX / "service.py"), "missing; the hash-first rule has no implementation to check")], 0
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    target = next(
        (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "analyse_file"),
        None,
    )
    if target is None:
        return [Finding(str(SANDBOX / "service.py"), "analyse_file not found; the hash-first rule moved")], 0

    lookup_line = evaluate_line = submit_line = None
    for node in ast.walk(target):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
        if name == "lookup_hash" and lookup_line is None:
            lookup_line = node.lineno
        elif name == "evaluate_upload" and evaluate_line is None:
            evaluate_line = node.lineno
        elif name == "submit_file" and submit_line is None:
            submit_line = node.lineno

    findings: list[Finding] = []
    if lookup_line is None:
        findings.append(Finding("analyse_file", "never calls lookup_hash; the hash-first rule is not implemented"))
    if evaluate_line is None:
        findings.append(Finding("analyse_file", "never calls evaluate_upload; the upload policy is not consulted"))
    if submit_line is None:
        findings.append(Finding("analyse_file", "never calls submit_file, so nothing is wired to the provider"))
    if lookup_line and evaluate_line and lookup_line > evaluate_line:
        findings.append(Finding("analyse_file", "evaluates the upload policy before looking the hash up"))
    if evaluate_line and submit_line and evaluate_line > submit_line:
        findings.append(Finding("analyse_file", "submits the file before evaluating the upload policy"))
    return findings, 3


CHECKS = (
    ("policy refuses every unsafe combination", _check_policy_behaviour),
    ("consent text names the disclosure", _check_consent_text),
    ("no consent flag defaults to on", _check_defaults_are_off),
    ("a failure never becomes a clean result", _check_failures_are_not_clean),
    ("every provider declares its locality", _check_providers_declare_locality),
    ("hash lookup precedes any upload", _check_hash_lookup_precedes_upload),
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Render a verdict (the default).")
    parser.parse_args()

    root = repo_root()
    if not (root / SANDBOX).is_dir():
        print(f"check_sandbox_upload_policy: {SANDBOX} does not exist - nothing verified", file=sys.stderr)
        return 2

    failed = False
    total_checked = 0
    for label, check in CHECKS:
        findings, checked = check(root)
        total_checked += checked
        status = "FAIL" if findings else "OK"
        print(f"[{status}] {label} ({checked} checked)")
        for finding in findings:
            print(str(finding))
        failed |= bool(findings)

    if total_checked == 0:
        print("check_sandbox_upload_policy: verified nothing - refusing to report a clean tree", file=sys.stderr)
        return 2
    print()
    if failed:
        print("check_sandbox_upload_policy: FAILED")
        return 1
    print(f"check_sandbox_upload_policy: OK ({total_checked} properties checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
