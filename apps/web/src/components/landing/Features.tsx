'use client';

import { motion } from 'framer-motion';

const FEATURES = [
  {
    title: 'Streaming correlation',
    description:
      'Events flow through Kafka into rule- and ML-based detectors. Risk-Based Alerting accumulates time-decayed risk points per entity and promotes them at a tunable threshold — hitting ≥ 50:1 alert-to-incident reduction, CI-gated.',
    icon: (
      <path d="M4 4h16v4H4zM4 10h10v4H4zM4 16h16v4H4z" />
    ),
  },
  {
    title: 'Tiered retention pipeline',
    description:
      'Declarative pre-ingest filter rules drop noisy events at the connector edge before they hit Kafka — cutting indexing cost without losing forensic depth. Every drop is counted per-connector and surfaced in the health summary.',
    icon: (
      <path d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
    ),
  },
  {
    title: 'Three-tier agent memory',
    description:
      'Session (in-process LRU), working (Redis, 24 h TTL), and institutional (PostgreSQL + pgvector, permanent). Agents carry context across tool calls, cases, and sessions; institutional knowledge survives restarts.',
    icon: (
      <path d="M12 2a5 5 0 015 5v1h1a3 3 0 010 6h-1v1a5 5 0 01-10 0v-1H6a3 3 0 010-6h1V7a5 5 0 015-5z" />
    ),
  },
  {
    title: 'Autonomy guardrails',
    description:
      'Per-action confidence thresholds (e.g. block_ip ≥ 0.90, close_alert ≥ 0.60) gate every autonomous decision. Tenant admins tune thresholds via API; all guardrail decisions are logged with rationale.',
    icon: (
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    ),
  },
  {
    title: 'NL detection authoring',
    description:
      'Describe a threat in plain English; the API translates it to Sigma YAML, KQL, SPL, and ES|QL simultaneously. Closed-loop: FP verdicts trigger automatic DAC proposals with CI regression gates.',
    icon: (
      <path d="M8 9l-5 3 5 3M16 9l5 3-5 3M14 5l-4 14" />
    ),
  },
  {
    title: 'Natural-language query',
    description:
      'Ask security questions in plain English — the API translates them to ES|QL, SPL, and KQL, executes against Elasticsearch-backed tenants live, and returns structured results with column metadata.',
    icon: (
      <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
    ),
  },
  {
    title: 'Hypothesis-driven hunting',
    description:
      'Hunt YAML corpus (DNS tunnelling, IAM anomalies, LOLBin abuse, OAuth mass-consent, after-hours service accounts) loaded from hunts/ and executed on a schedule against the federated query layer.',
    icon: (
      <path d="M10 21l-7-7 7-7M21 10H3" />
    ),
  },
  {
    title: 'Cross-platform rule translation',
    description:
      'Federated query layer translates a single ES|QL hunt into SPL (Splunk) and KQL (Sentinel) at execution time. Connectors for Splunk, Sentinel, and Elastic each hold a dedicated dialect translator.',
    icon: (
      <path d="M4 6h16v4H4zM4 14h10v4H4zM18 14h2v4h-2z" />
    ),
  },
  {
    title: 'MITRE ATT&CK coverage',
    description:
      'Detection rules, alerts, and the live heatmap reference ATT&CK techniques. Coverage gaps appear alongside live activity. The public eval harness gates MITRE accuracy on every PR.',
    icon: (
      <path d="M3 3h7v7H3zm11 0h7v4h-7zm0 6h7v12h-7zm-11 4h7v8H3z" />
    ),
  },
  {
    title: 'Identity-centric investigation',
    description:
      'Attack graph links users, devices, and service accounts. Pivot from alert to identity, trace lateral movement, and reconstruct blast radius across a Neo4j graph updated in real time.',
    icon: (
      <path d="M5 5a3 3 0 116 0 3 3 0 01-6 0zm8 14a3 3 0 116 0 3 3 0 01-6 0zM7.5 8l5 8" />
    ),
  },
  {
    title: 'Attack-path investigation agent',
    description:
      'A dedicated LangGraph agent reconstructs lateral movement and blast radius from the live graph, summarises high-risk pivots, and proposes contained response actions (host isolation, account disable) gated by autonomy guardrails.',
    icon: (
      <path d="M13 10V3L4 14h7v7l9-11h-7z" />
    ),
  },
  {
    title: 'SOC metrics dashboard',
    description:
      'Live MTTD, MTTR, False Positive Rate, and alert/case volumes (rolling 7 d) with an ATT&CK technique heatmap. Analyst-override feedback updates FPR automatically; corrections flow into institutional memory.',
    icon: (
      <path d="M2 20h20M6 20V10M12 20V4M18 20v-8" />
    ),
  },
  {
    title: 'Pluggable connectors',
    description:
      'Click-and-connect catalog (Defender XDR, Azure, GCP, M365, GitHub, CrowdStrike, Splunk, Sentinel, Okta, and more). Secrets encrypted with CredentialVault (Fernet AES-128-CBC + HMAC-SHA256).',
    icon: (
      <path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18" />
    ),
  },
  {
    title: 'Schema-drift sentinel',
    description:
      'Every poll fingerprints the upstream payload shape and diffs it against the last known-good schema. New, removed, or renamed fields surface in the connector card and aggregate health tile before they silently break detections.',
    icon: (
      <path d="M12 9v2m0 4h.01M5 19h14a2 2 0 001.74-2.99l-7-12a2 2 0 00-3.48 0l-7 12A2 2 0 005 19z" />
    ),
  },
  {
    title: 'Compliance & governance',
    description:
      'Evidence dashboards with controls mapped to SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, and DORA — to help your team gather audit evidence, not a claim that AiSOC itself holds any of these certifications. Backed by multi-tenant RLS, granular RBAC, immutable audit logs, and an MSSP parent-tenant console for cross-tenant management.',
    icon: (
      <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    ),
  },
];

export function Features() {
  return (
    <section id="features" className="relative py-24 md:py-32">
      <div className="mx-auto max-w-7xl px-6">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
          className="mx-auto max-w-2xl text-center"
        >
          <span className="text-xs font-semibold uppercase tracking-wider text-velvet-emerald-mint">
            Platform
          </span>
          <h2 className="font-velvet-display font-normal mt-3 text-4xl tracking-tight text-velvet-content-primary md:text-5xl">
            What is in the box
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            Ingest, detection, analysis and response are separate services that can be inspected,
            extended and run in your own environment.
          </p>
        </motion.div>

        <div className="mt-16 grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((feature, i) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-80px' }}
              transition={{ duration: 0.4, delay: i * 0.04 }}
              className="group relative overflow-hidden rounded-2xl border border-velvet-content-primary/5 bg-velvet-surface-raised/50 p-6 transition hover:border-velvet-content-primary/15 hover:bg-velvet-surface-raised"
            >
              <div className="relative">
                <div className="inline-flex h-11 w-11 items-center justify-center rounded-lg border border-velvet-content-primary/10 bg-white/[0.04] text-velvet-emerald-mint">
                  <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    className="h-5 w-5"
                  >
                    {feature.icon}
                  </svg>
                </div>
                <h3 className="font-velvet-display font-normal mt-5 text-lg text-velvet-content-primary">{feature.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-gray-400">{feature.description}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
