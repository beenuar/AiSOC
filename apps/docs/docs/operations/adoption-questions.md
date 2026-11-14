---
sidebar_position: 3
title: Adoption consultation questions
description: A structured question set to run with a security leader before deploying AiSOC — coverage, agent autonomy, compliance, ITSM, SLOs, and success metrics.
---

# Adoption consultation questions

This page is the question set we walk through with a security leader (CISO, head of SecOps, IR lead) before deploying AiSOC. It exists because most failed SOC-tooling rollouts fail not on capability but on **boundary** — the tool was given too much or too little autonomy, was wired to the wrong source of truth, or was measured against a goal it could not move.

The structure below is meant to be taken **in order**. Each section depends on answers from the section above it. Skipping ahead — particularly to "agent autonomy" before answering "what does success look like" — is the most common way these conversations go sideways.

Use this as a working doc. Capture the answers in your own copy of the file (or in a Notion / Confluence equivalent), commit it next to the deployment plan, and revisit it at the end of every quarter.

---

## 1. Outcomes & success criteria

Establish the goal _before_ talking about tools.

1. **What is the single number that is unacceptable today?**
   (Mean time to triage? P1 backlog? Analyst hours per week on false positives? Time to contain a confirmed identity compromise?)
2. **In 90 days, what change in that number is the bar for "AiSOC is working"?**
   Concrete numbers only — "fewer false positives" is not an answer.
3. **Who reviews that number with you, and how often?**
   (Board, CIO, weekly ops review, monthly business review.)
4. **What change in that number would cause you to expand AiSOC?** **What change would cause you to roll it back?**
5. **Are there qualitative outcomes the number does not capture?**
   (Analyst retention, on-call burden, audit findings, cyber-insurance posture.)
6. **Which two adjacent teams stand to benefit if this works?**
   (IT ops, fraud, GRC, SRE — these are the natural expansion vectors and worth scoping early.)

---

## 2. Threat model & coverage requirements

Before integrations, agree on what AiSOC must detect and respond to.

1. **What are your top three threat scenarios?**
   Phrase each as a story: who, doing what, against which asset, and what would tip you off. Avoid generic categories like "ransomware."
2. **What detection coverage do you have today for those three?**
   (Detection rules in your SIEM? EDR queries? Manual hunting? Nothing?)
3. **For each scenario, where does the relevant signal _originate_?**
   Identity provider audit, EDR, cloud control plane, email security, network logs, SaaS audit. This is the connector shopping list.
4. **What signal do you _not_ collect today that you would need to catch these scenarios reliably?**
5. **What attacker behavior would you accept missing entirely** in the first 6 months in exchange for shipping the rest faster?
6. **Do you have a hunt or red-team program?** If so, is its output already structured (test cases, MITRE technique IDs, scenario YAML), or is it free-text reports that we would need to convert?
7. **Do you maintain a "crown jewel" or asset criticality list?** Where does it live, and who owns it?

---

## 3. Data sources & connector inventory

Map the existing surface area to the [connector catalog](/docs/connectors/api-coverage).

1. **Identity provider(s).** Entra ID, Okta, Google Workspace, Auth0 — which? Is SSO mandatory? Is MFA enforced for everyone?
2. **EDR.** Which vendor? What licensing tier? Do you have isolation API access enabled? Who owns the API credentials today?
3. **SIEM(s).** Are you on Sentinel, Splunk, Elastic, Sumo, Chronicle, Datadog, Sumo, Trellix, or none? If multiple, which is canonical and which are read-only second copies? Are you paying licensing on data you do not query?
4. **Cloud platforms.** AWS, GCP, Azure — which accounts are in scope? Do you already have CloudTrail / Cloud Audit / Activity Logs centralized? Where?
5. **SaaS surfaces.** M365 audit? Google Workspace audit? GitHub audit? Slack audit? Salesforce login history? Which of these does compliance require you to retain, and for how long?
6. **Network.** Cisco Umbrella / Zscaler / Tailscale / firewall syslog — which are present, and is there a centralized aggregator?
7. **Vulnerability + posture.** Tenable, Wiz, Lacework — what runs today, and where do its findings flow?
8. **For each integration above, who owns the credential rotation policy?** Who would be paged if AiSOC's poll started failing?
9. **Are any sources only available behind your corporate VPN / on-prem network?** This determines whether the air-gap deployment shape is needed.

---

## 4. Case lifecycle & ITSM source of truth

This is where rollouts most often break — see [ITSM as a projection of AiSOC](/docs/architecture/itsm-as-source-of-truth) for the architectural answer.

1. **Where does an incident "live" today?**
   (Jira project, ServiceNow Security Incident Response, a Confluence runbook, a Slack channel, an email thread.)
2. **Which of those would you give up?**
   The honest answer is rarely "all of them." Get the realistic one.
3. **Who owns the lifecycle transitions today?**
   Detection author? Tier-1 analyst? Manager? An automated rule? Two of these?
4. **What status vocabulary do you use, and is it stable?**
   (`triage / open / in progress / contained / resolved / closed`, or some variant — does it match across teams or does each team have its own?)
5. **Do you currently push security incidents back into IT change-management?**
   If yes — under what conditions, and who approves?
6. **Are there incident types you would _not_ want mirrored to ITSM?**
   (Insider risk, executive impersonation attempts, ongoing red-team exercises, anything HR-adjacent.)
7. **Do you need approval workflows in the ticket itself**, or are approvals out of band (chat, email)?
8. **Who reviews closed cases?** Is that a real ritual or theoretical?

---

## 5. Agent autonomy & response boundaries

The hardest conversation. Refusing it explicitly is a red flag.

1. **What actions is AiSOC _allowed_ to take without human approval, ever?**
   (Enrich a domain. Pull a process tree. Query the SIEM. Read mailbox audit.)
2. **What actions require explicit human approval before AiSOC takes them?**
   (Isolate a host. Disable a user account. Quarantine a file. Block a hash globally. Revoke a token.)
3. **For the approval-required actions, who can approve, on which channel, and what is the timeout?**
   (ChatOps verification model — see the action contracts.)
4. **What actions are _never_ allowed regardless of approval?**
   (Touch executive identity, isolate a domain controller, kill a process on the CEO's laptop, anything in a regulated environment without change-management.)
5. **What blast-radius limits do you want enforced?**
   (Max N hosts isolated per hour. Max M users disabled per day. Stop and require human re-confirmation if exceeded.)
6. **Who is on the approval rotation, and what is the fallback when they are unreachable?**
7. **Is there a "panic stop" you want — a single switch that puts the agent into pure-advisory mode?**
8. **Are you comfortable with the agent _proposing_ a multi-step plan and a human approving the whole plan once,** or do you want each step approved individually?

---

## 6. Compliance, data residency, audit

1. **Which regulatory regimes apply?**
   (SOC 2, ISO 27001, PCI DSS, HIPAA, GDPR, FedRAMP, regional regulators.)
2. **Where must the data physically reside?**
   (Single region, multi-region, on-prem only, EU only.)
3. **What is your data retention requirement** for raw logs, normalized events, and case records? Do they differ?
4. **Who is your DPO / privacy contact?** Have they reviewed how AiSOC handles PII (usernames, IPs, email addresses, device names)?
5. **What is your encryption standard for data at rest and for credentials?**
   (AiSOC uses Fernet AES-128-CBC + HMAC-SHA256 by default; if you require AES-256 or KMS-backed keys, we need to know now.)
6. **Do you require an immutable audit trail of every action AiSOC takes?**
   (We provide one — make sure it is reviewed.)
7. **Is air-gapped deployment a hard requirement** for any of your environments? If yes, see [air-gap operations](/docs/operations/airgap).
8. **Are you subject to AI-specific regulation** (EU AI Act, sectoral AI guidance) that constrains which model providers are usable?

---

## 7. Identity, access, and tenancy

1. **How will analysts log in to AiSOC?**
   (SSO via your IdP — which?) Will MFA be enforced at the IdP, the app, or both?
2. **What is the role model in AiSOC?**
   (Read-only, triage, responder, admin, super-admin — how does that map to your existing security team structure?)
3. **Do you need SCIM provisioning?**
4. **Is multi-tenancy needed within your org?**
   (Per-business-unit isolation, MSSP serving multiple customers, regulated subsidiary.)
5. **Who owns the "break-glass" admin account, where is its credential stored, and what triggers using it?**
6. **Is there a separation-of-duties requirement** between who configures detection rules and who can approve containment?

---

## 8. Operations, SLOs, and on-call

1. **What is your in-hours and out-of-hours coverage today?**
2. **What latency do you need from event ingest to detection?**
   (Seconds, minutes, hours.)
3. **What latency do you need from detection to a triaged case?**
4. **What is your acceptable false-positive rate** on the top 10 detection rules? How is that measured?
5. **How do you want to be alerted when AiSOC itself is degraded?**
   (Connector failing, ingest backlog, agent unable to call its tools.)
6. **Who owns the on-call rotation for AiSOC the platform** (separate from the SOC analyst rotation)?
7. **What is your release tolerance?**
   (Auto-update is fine. Bi-weekly windows. Quarterly with internal validation.)
8. **Do you require a staging environment** that mirrors prod? At what fidelity?

---

## 9. Reporting & stakeholder communication

1. **What does the weekly report to leadership need to contain?**
2. **What does the quarterly report to the board need to contain?**
3. **Are there external reporting obligations** — to insurers, customers, regulators — that AiSOC outputs need to feed?
4. **Do you need an exec dashboard** distinct from the analyst console?
5. **What language do you use for severity, externally?**
   (Critical / high / medium / low? P1-P4? Numbered SEV?) AiSOC needs to map to it.

---

## 10. Failure modes & exit

The honest question that almost no procurement conversation asks.

1. **Under what conditions would you decommission AiSOC?**
   Be specific.
2. **What data would you need to take with you?**
   (Cases, evidence, audit trail, detection rules.)
3. **Who is the off-boarding executive sponsor** if the project lead leaves?
4. **What does success look like _without_ AiSOC** — i.e. if it works so well it makes itself less needed?

---

## How to use this list in practice

1. Walk it top to bottom in a 90-minute working session with the security leader and the SOC lead present. Skip nothing in §1 and §10.
2. Fill the gaps with their team async. Most of §3 (data sources) and §6 (compliance) can be answered on paper.
3. Write the answers down, in this same file, in the deployment repo. The answers _are_ the deployment plan.
4. Revisit at quarter end. The answers in §1, §4, and §5 will move; the questions stay the same.

If a question on this page does not apply to you, write down _why_ it does not, in the doc, before moving on. The act of writing the "why not" is what catches the wrong assumption six months later.
