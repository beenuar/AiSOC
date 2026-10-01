#!/usr/bin/env python3
"""Every console call to an AiSOC API carries a credential.

Why this exists
---------------
The console reached 61 API call sites across 21 files through bare
``fetch(url)`` and through single-argument SWR fetchers that take no options
at all, so the request went out with no ``Authorization`` header. Those calls
worked, which is the whole problem: the API resolved a credential-free request
to a demo administrator whenever it ran in a development-class environment,
and that is how the quick start and the documented single-host deployment ran.
Closing the anonymous path turns every one of them into a 401, so the console
had to move onto the credentialed client in the same change.

Nothing would have caught the drift. ``check_ledger_replay_contract`` holds
one client object against one router and says nothing about headers;
``check_route_auth`` and ``check_route_authz`` look at the server. The console
side had no gate at all, and a header is exactly the kind of thing a new
component omits by copying the component beside it.

What counts as a credential
---------------------------
An ``Authorization`` header, and nothing else. Two near-misses deserve
naming because both were present in the tree and neither authenticates:

``X-Tenant-Id``
    A caller-supplied tenant claim. Five call sites in ``api.ts`` sent it and
    no token, which reads like an identity and is not one.

``credentials: 'include'``
    Sends cookies. The API verifies a bearer token; the SSO cookie it sets is
    read by nothing. A cookie-only call is anonymous to this backend.

Scope
-----
Browser code under ``apps/web/src``. Server components are in scope and
allowlisted individually rather than exempted as a class: a server render has
no session to borrow, so a call made there is either genuinely public or a
call that cannot succeed, and both deserve a written reason.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import tempfile
from dataclasses import dataclass

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

#: Where the console lives, relative to the repository root.
CONSOLE_ROOT = "apps/web/src"

#: Path fragments that mark a URL as an AiSOC API call. `/api/v1` covers the
#: core API and every service the Next rewrites proxy; `/v1/inbox` is the
#: ingest webhook, which authenticates by token in the path.
API_MARKERS = ("/api/v1/", "/v1/inbox/")

#: Suffixes whose calls are not shipped to a browser.
EXEMPT_SUFFIXES = (".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx", ".stories.tsx")

#: What counts as a credential at a call site, matched case-insensitively.
#:
#: Either the header spelled out, or a call to the one helper that attaches
#: it. Recognising the helper matters: hiding the header behind a local
#: `const headers = {...}` a few lines up is how the preferences call ended up
#: with a token and no tenant header, and the fix for that shape is to route
#: it through the helper rather than to make the gate chase variables. So the
#: rule a reviewer can state is "show the credential, or call the thing whose
#: job is attaching it, on the same expression as the fetch".
CREDENTIAL_MARKERS = ("authorization", "apiheaders(")

#: Fetchers that attach a credential themselves, so a bare reference to one as
#: an SWR fetcher is fine. Keep in step with `apps/web/src/lib/api.ts`.
AUTHED_FETCHERS = frozenset({"authedFetcher", "apiRequest", "apiFetch", "request"})

#: Single-argument fetchers that cannot attach a credential, by construction:
#: SWR calls them as `f(key)` and they take no options. A bare reference to
#: one against an API key is a finding even though no `fetch(` is in sight.
#: Both named here were retired; the names stay so that re-introducing the
#: shape is a failure rather than a silent regression.
UNAUTHED_FETCHERS = frozenset({"jsonFetcher", "safeFetcher"})


#: Calls that legitimately carry no credential, keyed by (path, url fragment)
#: with the reason. This may only shrink: `--check` reports an entry whose
#: call has gone, so a fixed site cannot leave its excuse behind.
ALLOWED_UNCREDENTIALED: dict[tuple[str, str], str] = {
    (
        "lib/replay.ts",
        "/api/v1/r/",
    ): (
        "The public replay permalink. Unauthenticated by design: /r/<slug> is "
        "the surface a reader opens from a blog post, and the redaction pass in "
        "services/api/app/services/replay_redaction.py is what makes it safe to serve."
    ),
}


@dataclass(frozen=True)
class Finding:
    """One console call that reaches an API without a credential."""

    rel_path: str
    line: int
    url: str
    kind: str
    detail: str

    def render(self) -> str:
        return f"{self.rel_path}:{self.line}  [{self.kind}] {self.url}\n      {self.detail}"


@dataclass(frozen=True)
class Report:
    findings: list[Finding]
    files_scanned: int
    calls_scanned: int
    stale_allowlist: list[str]


def _sources(root: pathlib.Path) -> list[pathlib.Path]:
    console = root / CONSOLE_ROOT
    if not console.is_dir():
        return []
    return sorted(p for p in console.rglob("*.ts*") if p.suffix in (".ts", ".tsx") and not p.name.endswith(EXEMPT_SUFFIXES))


def _call_arguments(text: str, open_paren: int) -> tuple[str, int] | None:
    """The text between the parentheses of a call, and the index after it.

    Written by hand rather than with a regex because the first argument is
    usually a template literal, and `${...}` puts braces and quotes inside a
    string that a naive matcher would treat as structure. Tracks quote state
    and template-substitution depth so `fetch(`${A}/api/v1/x`, { ... })` is
    read as two arguments rather than five.
    """
    if open_paren >= len(text) or text[open_paren] != "(":
        return None
    depth = 0
    index = open_paren
    quote: str | None = None
    # One entry per `${` we are inside, so a nested template closes correctly.
    substitutions: list[int] = []
    while index < len(text):
        char = text[index]
        if quote is not None:
            if char == "\\":
                index += 2
                continue
            if quote == "`" and char == "$" and text[index : index + 2] == "${":
                substitutions.append(depth)
                quote = None
                depth += 1
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "'\"`":
            quote = char
            index += 1
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if substitutions and depth == substitutions[-1]:
                substitutions.pop()
                quote = "`"
                index += 1
                continue
            if depth == 0:
                return text[open_paren + 1 : index], index + 1
        index += 1
    return None


def _split_top_level(argument_text: str) -> list[str]:
    """Split a call's arguments on commas that are not nested or quoted."""
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    substitutions: list[int] = []
    start = 0
    index = 0
    while index < len(argument_text):
        char = argument_text[index]
        if quote is not None:
            if char == "\\":
                index += 2
                continue
            if quote == "`" and argument_text[index : index + 2] == "${":
                substitutions.append(depth)
                quote = None
                depth += 1
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "'\"`":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if substitutions and depth == substitutions[-1]:
                substitutions.pop()
                quote = "`"
        elif char == "," and depth == 0:
            parts.append(argument_text[start:index])
            start = index + 1
        index += 1
    parts.append(argument_text[start:])
    return [part.strip() for part in parts]


def _api_path_in(text: str) -> str | None:
    """The API path a URL expression names, if it names one."""
    for marker in API_MARKERS:
        if marker in text:
            # Report from the marker so the finding reads as a route rather
            # than as whatever base-URL expression happens to precede it.
            tail = text[text.index(marker) :]
            for terminator in ("`", "'", '"', "?"):
                if terminator in tail:
                    tail = tail[: tail.index(terminator)]
            return tail.strip()
    return None


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _skip_generic(text: str, index: int) -> int:
    """Past a `<...>` type argument list, if one starts at `index`.

    `useSWR<Role[]>('/api/v1/rbac/roles', fetcher)` is a call, and a matcher
    that only skips whitespace between the name and `(` does not see it. Both
    SWR sites in the settings console carried a generic, so the rule that was
    meant to catch an unauthenticated fetcher matched nothing at all.

    Only a balanced `<...>` immediately followed by `(` counts, so a genuine
    comparison such as `a < b && c > (d)` is left alone.
    """
    if index >= len(text) or text[index] != "<":
        return index
    depth = 0
    cursor = index
    while cursor < len(text):
        char = text[cursor]
        if char == "<":
            depth += 1
        elif char == ">":
            depth -= 1
            if depth == 0:
                after = cursor + 1
                while after < len(text) and text[after] in " \t\n":
                    after += 1
                return after if after < len(text) and text[after] == "(" else index
        elif char in ";{}\n" and depth:
            return index
        cursor += 1
    return index


def _find_call_sites(source: str, callee: str) -> list[tuple[int, str, list[str]]]:
    """Every `callee(...)` in `source`, as (offset, raw arguments, split)."""
    sites: list[tuple[int, str, list[str]]] = []
    needle = callee
    cursor = 0
    while True:
        found = source.find(needle, cursor)
        if found < 0:
            return sites
        cursor = found + len(needle)
        # Reject `myFetch(` and `.fetch(` style matches: only a call whose
        # name starts at a word boundary is this callee.
        before = source[found - 1] if found else " "
        if before.isalnum() or before in "_$.":
            continue
        after = found + len(needle)
        while after < len(source) and source[after] in " \t\n":
            after += 1
        after = _skip_generic(source, after)
        parsed = _call_arguments(source, after)
        if parsed is None:
            continue
        raw, _ = parsed
        sites.append((found, raw, _split_top_level(raw)))


def _carries_credential(options_text: str) -> bool:
    lowered = options_text.lower()
    return any(marker in lowered for marker in CREDENTIAL_MARKERS)


def _definition_of(source: str, name: str) -> str | None:
    """The text of a `const name = ...` or `function name(...)` in this file.

    SWR takes a fetcher by name, so judging the call means reading what the
    name is bound to. Three bindings occur in this console and they answer
    differently: an alias of an imported fetcher, an inline arrow that calls
    `fetch(url)` on the SWR key, and a name imported from another module.
    Only the first two can be decided here.
    """
    for opener in (f"const {name} = ", f"let {name} = ", f"function {name}("):
        found = source.find(opener)
        if found < 0:
            continue
        start = found + len(opener)
        depth = 0
        cursor = start
        while cursor < len(source):
            char = source[cursor]
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
                if depth < 0:
                    break
            elif char == ";" and depth == 0:
                break
            elif char == "\n" and depth == 0 and _statement_ends_at(source, start, cursor):
                break
            cursor += 1
        return source[start:cursor]
    return None


#: Tokens that mean a statement continues on the next line, so a newline at
#: brace depth zero is not the end of the definition. Both fetchers on the
#: honeytokens and purple-team pages are written as
#: `const fetcher = (url: string) =>\n  fetch(url).then(...)`, and stopping at
#: the first newline read the definition as the bare signature `(url: string)
#: =>`. That has no `fetch(` in it, so the gate concluded "imported from
#: elsewhere, judged where defined" and skipped nine real findings while
#: printing a clean line for them.
_CONTINUES = ("=>", "=", "&&", "||", "?", ":", ",", "+", "(", "[", "{", ".", "await", "return")


def _statement_ends_at(source: str, start: int, cursor: int) -> bool:
    text = source[start:cursor].rstrip()
    if not text:
        return False
    return not any(text.endswith(token) for token in _CONTINUES)


def _fetcher_is_credentialed(source: str, fetcher: str) -> bool | None:
    """Whether a named SWR fetcher attaches a credential. None means unknown."""
    if fetcher in AUTHED_FETCHERS:
        return True
    if fetcher in UNAUTHED_FETCHERS:
        return False
    definition = _definition_of(source, fetcher)
    if definition is None:
        # Imported from another module; judged where it is defined.
        return None
    stripped = definition.strip().rstrip(";")
    if stripped in AUTHED_FETCHERS:
        return True
    if stripped in UNAUTHED_FETCHERS:
        return False
    if _carries_credential(definition):
        return True
    if "fetch(" in definition:
        # An inline fetcher that calls fetch() on the SWR key with no header.
        # The fetch() scanner cannot see this one: its URL is the parameter,
        # so there is no API path at the call site to match on.
        return False
    return None


def _allowlist_reason(rel_path: str, url: str) -> str | None:
    for (path, fragment), reason in ALLOWED_UNCREDENTIALED.items():
        if path == rel_path and fragment in url:
            return reason
    return None


def inspect(root: pathlib.Path) -> Report:
    findings: list[Finding] = []
    calls = 0
    files = _sources(root)
    used_allowlist: set[tuple[str, str]] = set()

    for path in files:
        rel = path.relative_to(root / CONSOLE_ROOT).as_posix()
        source = path.read_text(encoding="utf-8", errors="replace")

        for offset, _raw, parts in _find_call_sites(source, "fetch"):
            url = _api_path_in(parts[0] if parts else "")
            if url is None:
                continue
            calls += 1
            options = ",".join(parts[1:])
            if _carries_credential(options):
                continue
            reason = _allowlist_reason(rel, url)
            if reason is not None:
                for key in ALLOWED_UNCREDENTIALED:
                    if key[0] == rel and key[1] in url:
                        used_allowlist.add(key)
                continue
            findings.append(
                Finding(
                    rel,
                    _line_of(source, offset),
                    url,
                    "bare-fetch",
                    "fetch() with no Authorization header. Use apiRequest() from @/lib/api.",
                )
            )

        for offset, _raw, parts in _find_call_sites(source, "useSWR"):
            if len(parts) < 2:
                continue
            url = _api_path_in(parts[0])
            if url is None:
                # The key may be a local binding rather than a literal.
                # `const dashKey = `/api/v1/compliance/${f}`;` followed by
                # `useSWR(dashKey, fetcher)` is an API call with a fetcher
                # that sends no credential, and reading only the call site
                # sees a bare identifier with no path in it. That is how
                # `FrameworkView.tsx` kept an uncredentialed compliance call
                # through the sweep that was meant to find exactly this.
                swr_key = parts[0].strip()
                if swr_key.isidentifier():
                    binding = _definition_of(source, swr_key)
                    if binding is not None:
                        url = _api_path_in(binding)
            if url is None:
                continue
            calls += 1
            fetcher = parts[1].strip()
            if "=>" in fetcher or fetcher.startswith("function"):
                # An inline arrow is judged on what it does, not its name.
                if _carries_credential(fetcher) or "fetch(" not in fetcher:
                    continue
            elif fetcher.isidentifier():
                credentialed = _fetcher_is_credentialed(source, fetcher)
                if credentialed is not False:
                    continue
            else:
                continue
            reason = _allowlist_reason(rel, url)
            if reason is not None:
                continue
            findings.append(
                Finding(
                    rel,
                    _line_of(source, offset),
                    url,
                    "swr-fetcher",
                    f"useSWR keyed on an API path with `{fetcher}`, which sends no credential. Use authedFetcher from @/lib/api.",
                )
            )

    stale = [f"{path} :: {fragment}" for (path, fragment) in ALLOWED_UNCREDENTIALED if (path, fragment) not in used_allowlist]
    return Report(findings, len(files), calls, stale)


def _verdict(report: Report) -> int:
    if report.files_scanned == 0:
        print(
            f"check_console_auth_headers: no console sources under {CONSOLE_ROOT} — refusing to report a tree with nothing in it as clean",
            file=sys.stderr,
        )
        return 2
    if report.calls_scanned == 0:
        print(
            "check_console_auth_headers: scanned "
            f"{report.files_scanned} file(s) and found no API call at all. "
            "Either the console stopped calling the API or the matcher broke; "
            "both need a human.",
            file=sys.stderr,
        )
        return 2

    if report.stale_allowlist:
        print("check_console_auth_headers: allowlist entries whose call is gone:", file=sys.stderr)
        for entry in report.stale_allowlist:
            print(f"  {entry}", file=sys.stderr)
        print("Remove them; the allowlist may only shrink.", file=sys.stderr)
        return 1

    if report.findings:
        print(
            f"check_console_auth_headers: {len(report.findings)} console call(s) reach an API with no credential:",
            file=sys.stderr,
        )
        for finding in report.findings:
            print(f"  {finding.render()}", file=sys.stderr)
        return 1

    print(
        f"check_console_auth_headers: OK — {report.calls_scanned} API call(s) across "
        f"{report.files_scanned} console file(s) all carry a credential "
        f"({len(ALLOWED_UNCREDENTIALED)} allowlisted as public)."
    )
    return 0


# ── Self-test ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Case:
    """One self-test case: source, and the finding kind that must account for it.

    `expect` names the kind rather than asking "did anything fire", so a bare
    fetch cannot pass on the strength of the SWR rule catching the same line.
    `expect=None` means the case must produce nothing.
    """

    description: str
    source: str
    expect: str | None
    suffix: str = ".tsx"
    name: str = "View"


def self_test_cases() -> tuple[Case, ...]:
    return (
        Case(
            "a bare fetch to an API path, the shape that shipped",
            "export async function go() {\n  await fetch('/api/v1/rbac/roles/abc', { method: 'DELETE' });\n}\n",
            "bare-fetch",
        ),
        Case(
            "a template-literal URL behind a base variable",
            "const API = process.env.NEXT_PUBLIC_HONEYTOKENS_URL ?? '';\n"
            "export async function go() {\n"
            "  await fetch(`${API}/api/v1/honeytokens/x/revoke`, { method: 'PATCH' });\n}\n",
            "bare-fetch",
        ),
        Case(
            "X-Tenant-Id alone, which reads like an identity and is not one",
            "export async function go() {\n"
            "  await fetch('/api/v1/cases/1/investigations/2/report.pdf', {\n"
            "    headers: { 'X-Tenant-Id': t },\n  });\n}\n",
            "bare-fetch",
        ),
        Case(
            "credentials: 'include', which sends cookies the API never reads",
            "export async function go() {\n  await fetch('/api/v1/compliance/soc2/export', { credentials: 'include' });\n}\n",
            "bare-fetch",
        ),
        Case(
            "a local alias of an unauthenticated fetcher used by SWR",
            "import { jsonFetcher } from '@/lib/failure';\n"
            "const fetcher = jsonFetcher;\n"
            "export function V() {\n"
            "  const { data } = useSWR('/api/v1/rbac/roles', fetcher);\n"
            "  return <b>{data}</b>;\n}\n",
            "swr-fetcher",
            name="Aliased",
        ),
        Case(
            "the same alias behind a generic, which hid both real SWR sites",
            "import { jsonFetcher } from '@/lib/failure';\n"
            "const fetcher = jsonFetcher;\n"
            "export function V() {\n"
            "  const { data } = useSWR<Role[]>('/api/v1/rbac/roles', fetcher, { x: 1 });\n"
            "  return <b>{data}</b>;\n}\n",
            "swr-fetcher",
            name="Generic",
        ),
        Case(
            "an inline fetcher whose URL is the SWR key, invisible to fetch() scanning",
            "const fetcher = async (url: string) => {\n"
            "  const r = await fetch(url);\n  return r.json();\n};\n"
            "export function V() {\n"
            "  const { data } = useSWR<Row[]>('/api/v1/sla/config', fetcher);\n"
            "  return <b>{data}</b>;\n}\n",
            "swr-fetcher",
            name="Inline",
        ),
        # ── and the directions it must not fire in ──────────────────────────
        Case(
            "a credentialed fetch",
            "export async function go() {\n"
            "  await fetch('/api/v1/playbooks/1/run', {\n"
            "    method: 'POST',\n    headers: { Authorization: `Bearer ${t}` },\n  });\n}\n",
            None,
        ),
        Case(
            "the authenticated client, which attaches the header itself",
            "import { apiRequest, authedFetcher } from '@/lib/api';\n"
            "export function V() {\n"
            "  const { data } = useSWR('/api/v1/rbac/roles', authedFetcher);\n"
            "  void apiRequest('/api/v1/playbooks', { method: 'POST' });\n"
            "  return <b>{data}</b>;\n}\n",
            None,
        ),
        Case(
            "a multi-line arrow fetcher, truncated at the newline by a first pass",
            "const fetcher = (url: string) =>\n"
            "  fetch(url).then((r) => {\n"
            "    if (!r.ok) throw new Error(`HTTP ${r.status}`)\n"
            "    return r.json()\n"
            "  })\n"
            "export function V() {\n"
            "  const { data } = useSWR<Row[]>(t ? `${API}/api/v1/purple-team/coverage?x=1` : null, fetcher)\n"
            "  return <b>{data}</b>;\n}\n",
            "swr-fetcher",
            name="MultiLine",
        ),
        Case(
            "the header helper, which is the credentialed path",
            "import { apiHeaders } from '@/lib/api';\n"
            "export async function go() {\n"
            "  await fetch('/api/v1/auth/me/preferences', {\n"
            "    method: 'PATCH',\n    headers: apiHeaders(),\n  });\n}\n",
            None,
        ),
        Case(
            "a fetch to something that is not an AiSOC API",
            "export async function go() {\n  await fetch('https://cdn.example.com/logo.svg');\n}\n",
            None,
        ),
        Case(
            "a template literal whose substitution contains braces and a quote",
            "export async function go() {\n"
            "  await fetch(`/api/v1/x/${encodeURIComponent(o['k'])}`, {\n"
            "    headers: { Authorization: `Bearer ${t}` },\n  });\n}\n",
            None,
        ),
    )


def _case_results(tmp: pathlib.Path) -> list[tuple[str, bool]]:
    results: list[tuple[str, bool]] = []
    for index, case in enumerate(self_test_cases()):
        tree = tmp / f"case{index}"
        console = tree / CONSOLE_ROOT
        console.mkdir(parents=True)
        (console / f"{case.name}{case.suffix}").write_text(case.source, encoding="utf-8")
        report = inspect(tree)
        kinds = {finding.kind for finding in report.findings}
        if case.expect is None:
            passed = not report.findings
            detail = f"expected nothing, got {sorted(kinds)}" if not passed else ""
        else:
            passed = case.expect in kinds
            detail = f"expected {case.expect}, got {sorted(kinds)}" if not passed else ""
        results.append((f"{case.description}{f' — {detail}' if detail else ''}", passed))
    return results


def _corpus_result(root: pathlib.Path) -> tuple[str, bool]:
    """A console whose calls all vanished must fail, not pass."""
    report = inspect(root)
    return (
        f"counts what it scanned ({report.calls_scanned} API calls in {report.files_scanned} files)",
        report.calls_scanned > 0 and report.files_scanned > 0,
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="aisoc-console-auth-") as tmp:
        extra = _case_results(pathlib.Path(tmp))
    extra.append(_corpus_result(repo_root()))
    return self_test_main(pathlib.Path(__file__).name, ["--check"], extra)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="render a verdict (default)")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", dest="self_test")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return _verdict(inspect(repo_root()))


if __name__ == "__main__":
    raise SystemExit(main())
