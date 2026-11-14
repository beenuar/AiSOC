"""Prompt-injection patterns, generated from the agents-service guard.

DO NOT EDIT. Regenerate with:

    python scripts/sync_vendored_ai_instruction_rules.py

Source of truth: ``services/agents/app/prompting/envelope.py::_RULES``. The
API service cannot import it — separate deployable, separate build context —
so the pattern table is generated here and
``scripts/sync_vendored_ai_instruction_rules.py --check`` fails when the two
drift.

Used by ``app/services/ai_repo_scan.py`` to flag an agent-instruction file,
a skill or an MCP configuration whose text tries to steer an agent. That is
a *capture-time signal on a file*, feeding the exposure score in
``app/services/ai_inventory.py::score_risk``. It is not an authorization
control: the authorization property at triage time is claim-support, proved
by the adversarial suite in ``services/agents/tests/adversarial/``.
"""

from __future__ import annotations

import re
import unicodedata

#: ``(kind, severity, compiled pattern)``, generated from the guard.
#:
#: ``fmt: off`` and ``noqa: E501`` are not style laziness. A detection
#: pattern is a single indivisible token: the formatter cannot wrap one
#: without changing the string, and a wrapped pattern that still compiled
#: would be a *different* pattern. Leaving the block alone is what lets the
#: generator produce a file that is byte-identical on every run, which is
#: the property ``--check`` rests on.
# fmt: off
RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ('ignore_previous', 'high', re.compile('\\b(?:ignore|disregard|forget|override)\\b[\\s\\S]{0,80}\\b(?:previous|prior|above|earlier|all|the)\\b[\\s\\S]{0,80}\\b(?:instructions?|prompt|rules?|system|context)\\b', 2)),  # noqa: E501
    ('reveal_prompt', 'high', re.compile('\\b(?:reveal|print|show|exfiltrate|leak|repeat|dump)\\b[^\\n]{0,40}\\b(?:system prompt|developer prompt|hidden instructions?|your instructions?|api[_ ]?key|secret|credentials?)\\b', 2)),  # noqa: E501
    ('possessive_prompt_reference', 'high', re.compile('\\byour\\s+(?:system\\s+(?:prompt|message|instructions?)|(?:initial|original|hidden|prior|preceding)\\s+(?:instructions?|prompt|rules?)|prompt\\s+(?:text|contents?)|configuration\\s+(?:prompt|instructions?))\\b', 2)),  # noqa: E501
    ('asserted_verdict', 'high', re.compile('(?:\\b(?:analyst\\s+note|soc\\s+(?:lead|manager|analyst)|tier\\s*[123]|reviewed\\s+by|triaged\\s+by|approved\\s+by|signed\\s+off|previously\\s+(?:triaged|reviewed|assessed|investigated)|assessment\\s+was\\s+superseded|per\\s+the\\s+(?:analyst|soc)|no\\s+further\\s+action|safe\\s+to\\s+close|can\\s+be\\s+closed|close\\s+this\\s+(?:alert|case|incident)|suppress\\s+this\\s+(?:alert|detection))\\b[\\s\\S]{0,160}\\b(?:false[\\s-]?positive|benign|not\\s+malicious|no\\s+threat|authoriz(?:ed|ation)\\s+activity|expected\\s+behaviou?r|known[\\s-]good)\\b(?![\\s\\S]{0,40}\\b(?:in\\s+error|reopen(?:ing|ed)?|incorrectl?y?|mistakenl?y?|was\\s+wrong|disagree|overturn|escalat)))|(?:\\b(?:false[\\s-]?positive|benign|not\\s+malicious|no\\s+threat|authoriz(?:ed|ation)\\s+activity|expected\\s+behaviou?r|known[\\s-]good)\\b(?![\\s\\S]{0,40}\\b(?:in\\s+error|reopen(?:ing|ed)?|incorrectl?y?|mistakenl?y?|was\\s+wrong|disagree|overturn|escalat))[\\s\\S]{0,160}\\b(?:analyst\\s+note|soc\\s+(?:lead|manager|analyst)|tier\\s*[123]|reviewed\\s+by|triaged\\s+by|approved\\s+by|signed\\s+off|previously\\s+(?:triaged|reviewed|assessed|investigated)|assessment\\s+was\\s+superseded|per\\s+the\\s+(?:analyst|soc)|no\\s+further\\s+action|safe\\s+to\\s+close|can\\s+be\\s+closed|close\\s+this\\s+(?:alert|case|incident)|suppress\\s+this\\s+(?:alert|detection))\\b)', 2)),  # noqa: E501
    ('jailbreak_persona', 'high', re.compile('\\byou are\\s+(?:now\\s+)?(?:in\\s+)?(?:a\\s+|an\\s+|the\\s+)?(?:dan|developer\\s+mode|jailbroken|unrestricted|no-?op)\\b', 2)),  # noqa: E501
    ('imperative_to_assistant', 'high', re.compile('\\b(?:as (?:an? )?(?:ai|assistant|agent|model)|dear (?:ai|assistant|agent))\\b[^\\n]{0,60}\\b(?:must|should|now|instead|please)\\b', 2)),  # noqa: E501
    ('injected_containment', 'high', re.compile('\\b(?:isolate|quarantine|contain|disable|suspend|deactivate|block|revoke|terminate|kill|release|unisolate|remediate)\\b[^\\n]{0,60}\\b(?:host|machine|endpoint|account|user|domain admin|administrator|ip|address|session|process|immediately|at the perimeter|isolation|containment|quarantine)\\b', 2)),  # noqa: E501
    ('named_containment_target', 'high', re.compile('\\b(?:isolate|quarantine|contain|unisolate|uncontain|disable|deactivate|revoke|release|remediate|reimage|wipe)[-_:=\\s]{1,3}(?:(?:the|this|that|host|machine|endpoint|account|user|device|node|server|asset|vm)[-_:=\\s]{1,3})?(?:(?:\\d{1,3}\\.){3}\\d{1,3}(?:/\\d{1,2})?|(?:svc|srv|sa|adm|admin|sys|app|db)[-_][A-Za-z0-9][\\w-]{0,30}|[A-Z][A-Z0-9]{0,15}(?:-[A-Z0-9]{1,15}){1,4}|[a-z]{1,16}(?:-[a-z]{0,15}\\d[a-z0-9]{0,15}){1,4})\\b')),  # noqa: E501
    ('fake_remediation_directive', 'high', re.compile('\\b(?:recommended|required|approved|authorised|authorized|per)\\s+(?:remediation|response|playbook|action|procedure|policy)\\b|\\bremediation[_ ]?script\\s*:', 2)),  # noqa: E501
    ('claimed_triage_authority', 'high', re.compile('\\b(?:soc|security|ir|incident\\s+response|review\\s+board|change\\s+board|cab)[-_\\s]{1,3}(?:team[-_\\s]{1,3}|review\\s+board[-_\\s]{1,3})?(?:pre[-_\\s]?)?(?:approved|authorised|authorized|cleared|exempt|whitelisted|signed[-_\\s]?off)\\b|\\b(?:pre[-_\\s]?)?(?:approved|authorised|authorized|cleared|signed\\s+off)\\s+(?:by|per|via)\\s+(?:the\\s+)?(?:soc|security|ir\\b|incident\\s+response|change\\s+board|review\\s+board)', 2)),  # noqa: E501
    ('triage_control_assignment', 'high', re.compile('\\b(?:set|mark|change|update|override|force|apply|treat|classify|reclassify|record|flag|close)\\b[\\s:=\\-_]{0,3}(?:\\w+[\\s:=\\-_]{1,3}){0,2}\\b(?:disposition|verdict|triage|classification|reason[_ ]?code|finding)\\b[\\s:=\\-_\\"\']{1,4}(?:\\w+[\\s:=\\-_]{1,3}){0,1}(?:benign|false[_ -]?positive|closed?|suppress(?:ed)?|informational|ignored?|resolved?|expected|superseded|no[_ -]?action)\\b', 2)),  # noqa: E501
    ('product_control_namespace', 'high', re.compile('\\baisoc[-_\\s]?(?:triage|note|disposition|verdict|control|directive|instruction|agent|analyst)\\b|\\baisoc\\s*[:=]', 2)),  # noqa: E501
    ('enumerate_secrets', 'high', re.compile('\\b(?:list|enumerate|output|include|report|show)\\b[^\\n]{0,60}\\b(?:every|all|each)?\\s*(?:credential|api[_ ]?key|secret|token|password|other (?:customers?|tenants?)|another tenant)\\b', 2)),  # noqa: E501
    ('tenant_override', 'high', re.compile('\\btenant[_ ]?id\\s*[:=]\\s*[\\"\\\']?[0-9a-f]{8}-[0-9a-f]{4}', 2)),  # noqa: E501
    ('memory_poisoning', 'high', re.compile('\\b(?:remember|note|record|store)\\b[^\\n]{0,40}\\b(?:for (?:all )?future|permanently|always|going forward|from now on)\\b|\\breason[_ ]?code\\s*=|\\bpermanent\\s*=\\s*true\\b', 2)),  # noqa: E501
    ('exfil_destination', 'high', re.compile('(?:https?://)?[\\w.-]{4,80}/\\S{0,10}\\?\\S{0,40}(?:prompt|secret|token|key|credential|context|system)', 2)),  # noqa: E501
    ('addressed_to_assistant', 'high', re.compile('\\b(?:note|message|instruction|reminder)\\s+(?:for|to)\\s+(?:the\\s+)?(?:security\\s+)?(?:analyst\\s+)?(?:ai|assistant|agent|model|llm)\\b|\\bhas been (?:reviewed and )?approved by\\b[^\\n]{0,40}\\b(?:soc|security|manager|analyst)\\b', 2)),  # noqa: E501
    ('role_reassignment', 'high', re.compile('\\byou are (?:now |no longer )|\\bnot a (?:security )?(?:analyst|soc|investigator)\\b|\\bstop (?:acting|behaving) as\\b', 2)),  # noqa: E501
    ('role_marker', 'medium', re.compile('<\\|(?:im_start|im_end|system|user|assistant)\\|>|\\[/?INST\\]|<\\s*/?\\s*system\\s*>', 2)),  # noqa: E501
    ('fence_break', 'medium', re.compile('<<<\\s*(?:END|AISOC)[^>]*>>>', 2)),  # noqa: E501
    ('markdown_system', 'medium', re.compile('^#{1,3}\\s*(?:system|instructions?)\\b', 10)),  # noqa: E501
    ('suppress_investigation', 'medium', re.compile("\\b(?:do not|don't|no need to|skip)\\b[^\\n]{0,40}\\b(?:call|use|run|query|investigate|check)\\b[^\\n]{0,30}\\b(?:tools?|further|additional|more)\\b|\\bevidence\\s+(?:below\\s+)?is\\s+(?:complete|authoritative|sufficient)\\b|\\bno\\s+further\\s+(?:enrichment|pivots?|lookups?|queries|enrichments)\\b", 2)),  # noqa: E501
    ('investigation_amplification', 'medium', re.compile('\\b(?:run|query|hunt|scan|search|sweep|enumerate|call|check)\\b[^\\n]{0,40}\\b(?:every|each)\\s+(?:hosts?|ips?|endpoints?|assets?|users?|devices?|accounts?|machines?|tenants?)\\b', 2)),  # noqa: E501
    ('structured_role_claim', 'medium', re.compile('["\\\']?role["\\\']?\\s*[:=]\\s*["\\\']?(?:system|assistant|developer)["\\\']?|^\\s*(?:system|assistant|developer)\\s*:', 10)),  # noqa: E501
    ('claimed_boundary', 'medium', re.compile('(?:-{2,}|={2,}|\\*{2,})\\s*END\\s+(?:UNTRUSTED|EVIDENCE|DATA|INPUT)|</\\s*evidence\\s*>', 2)),  # noqa: E501
)
# fmt: on


def scan_instruction_text(text: str) -> tuple[str, ...]:
    """Names of the patterns `text` matched, sorted, never the matched text.

    Returning names and not spans is deliberate. The caller stores the
    result on an asset record that a console renders, and a stored copy of
    the matching payload would put the attacker's text in a second place.

    The text is NFKC-normalised first, for the reason the guard documents:
    a homoglyph spelling of an instruction renders identically and would
    otherwise pass a literal match.
    """
    if not text:
        return ()
    normalised = unicodedata.normalize("NFKC", text)
    return tuple(sorted({kind for kind, _severity, pattern in RULES if pattern.search(normalised)}))


def severity_of(kind: str) -> str | None:
    """The guard's own severity for one pattern name."""
    for name, severity, _pattern in RULES:
        if name == kind:
            return severity
    return None
