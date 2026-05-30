import type { Metadata } from 'next';
import Link from 'next/link';
import { LandingNav } from '@/components/landing/LandingNav';
import { Footer } from '@/components/landing/Footer';

/**
 * `/sovereign` — deployment-flexibility one-pager (T6.3).
 *
 * Surfaces the answer to the procurement question that comes up before any
 * technical evaluation: "where can it run, on what LLM, in which country, and
 * against which compliance regime?". Everything on the page maps to an asset
 * already shipping in the repo:
 *
 *   - Air-gapped overlay  → `docker-compose.airgap.yml` + the Ollama sidecar.
 *   - On-prem / Helm      → `infra/helm/aisoc/`.
 *   - Public cloud / BYOC → `infra/terraform/{aws,gcp,byoc}/`.
 *   - BYO LLM endpoint    → `AISOC_LLM_*` env vars + tenant LLM credential vault.
 *
 * The page is intentionally text-and-grid heavy — buyers in regulated sectors
 * scan for keywords (air-gap, EU, GDPR, Helm, Terraform) before reading.
 */

export const metadata: Metadata = {
  title: 'Sovereign + air-gap deployment — AiSOC',
  description:
    'AiSOC runs anywhere: air-gapped, on-prem, hybrid, public cloud, or managed SaaS — with cloud LLM APIs, a local Ollama sidecar, or a bring-your-own LLM endpoint. EU, US, India, or custom data residency.',
  alternates: { canonical: '/sovereign' },
  openGraph: {
    title: 'AiSOC runs where you do — sovereign by default',
    description:
      'Air-gapped, on-prem, hybrid, public cloud, managed SaaS · cloud LLM, local Ollama, or BYO endpoint · EU / US / India / custom residency.',
    type: 'article',
  },
};

type DeploymentMode = {
  name: string;
  llm: string;
  residency: string;
  compliance: string;
  artefact: string;
  artefactHref?: string;
};

const DEPLOYMENT_MODES: DeploymentMode[] = [
  {
    name: 'Air-gapped',
    llm: 'Local Ollama sidecar',
    residency: 'Operator-defined',
    compliance: 'SOC 2 · ISO 27001 · GDPR · DPDP',
    artefact: 'docker-compose.airgap.yml',
    artefactHref:
      'https://github.com/beenuar/AiSOC/blob/main/docker-compose.airgap.yml',
  },
  {
    name: 'On-prem',
    llm: 'Local Ollama or BYO endpoint',
    residency: 'Operator-defined',
    compliance: 'SOC 2 · ISO 27001 · GDPR · DPDP',
    artefact: 'Helm chart (infra/helm/aisoc)',
    artefactHref:
      'https://github.com/beenuar/AiSOC/blob/main/infra/helm/aisoc/Chart.yaml',
  },
  {
    name: 'Hybrid',
    llm: 'Cloud APIs · Ollama · BYO',
    residency: 'EU · US · India · Custom',
    compliance: 'SOC 2 · ISO 27001 · GDPR · DPDP',
    artefact: 'Terraform (infra/terraform/byoc)',
    artefactHref:
      'https://github.com/beenuar/AiSOC/tree/main/infra/terraform/byoc',
  },
  {
    name: 'Public cloud',
    llm: 'Cloud APIs · BYO endpoint',
    residency: 'EU · US · India · Custom',
    compliance: 'SOC 2 · ISO 27001 · GDPR · DPDP',
    artefact: 'Terraform (infra/terraform/{aws,gcp})',
    artefactHref:
      'https://github.com/beenuar/AiSOC/tree/main/infra/terraform',
  },
  {
    name: 'Managed SaaS (waitlist)',
    llm: 'Cloud APIs (default) · BYO',
    residency: 'EU · US · India',
    compliance: 'SOC 2 · GDPR (target)',
    artefact: 'tryaisoc.com',
    artefactHref: 'mailto:hello@tryaisoc.com?subject=AiSOC%20managed%20waitlist',
  },
];

const PILLARS = [
  {
    label: 'Air-gap by config flag',
    body: 'Set AISOC_AIRGAPPED=true and the platform refuses to make outbound calls — no LLM provider, no threat-intel feed, no telemetry. The Ollama overlay ships a pinned local model so the demo seed runs end-to-end with zero external calls.',
    cite: 'docker-compose.airgap.yml',
  },
  {
    label: 'BYO LLM endpoint',
    body: 'Per-tenant LLM credentials live in the encrypted vault (Fernet AES-128-CBC + HMAC-SHA256). Point a tenant at OpenAI, Anthropic, an Azure deployment, a Bedrock model, or a private LiteLLM gateway — the agent loop is identical.',
    cite: 'BYOK + tenant LLM credential vault',
  },
  {
    label: 'Helm + Terraform first-class',
    body: 'A single Helm release deploys every service into your cluster; Terraform modules cover AWS EKS, GCP Cloud Run, and a generic BYOC blueprint. Bring your own VPC, KMS, and IAM — the modules consume them rather than reinventing them.',
    cite: 'infra/helm/aisoc · infra/terraform/{aws,gcp,byoc}',
  },
  {
    label: 'Data residency by VPC',
    body: 'Because the entire stack runs in your account, residency is decided by which region you provision into. Pin to eu-west-1, ap-south-1, us-east-2, or any other region your provider exposes — including sovereign-cloud regions.',
    cite: 'Operator-controlled provisioning',
  },
];

const CLOUDS = ['AWS', 'Azure', 'GCP', 'OCI', 'DigitalOcean', 'Hetzner'];
const REGIONS = ['US', 'EU', 'India', 'Singapore', 'Custom'];

const COMPLIANCE_BADGES = [
  { label: 'SOC 2', tone: 'border-emerald-500/30 text-emerald-200' },
  { label: 'ISO 27001', tone: 'border-cyan-500/30 text-cyan-200' },
  { label: 'GDPR', tone: 'border-brand-500/30 text-brand-200' },
  { label: 'DPDP (India)', tone: 'border-amber-500/30 text-amber-200' },
];

export default function SovereignPage() {
  return (
    <main
      data-theme="dark"
      className="relative min-h-screen overflow-x-hidden bg-surface-base text-fg-primary"
    >
      <LandingNav />

      {/* Hero */}
      <section className="px-6 pt-32 pb-16">
        <div className="mx-auto max-w-4xl">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300">
              Sovereign by default
            </span>
            <span className="text-xs text-gray-500">
              Air-gap · BYO LLM · BYO cloud
            </span>
          </div>
          <h1 className="text-4xl font-bold tracking-tight text-white md:text-5xl">
            AiSOC runs where you do.
            <br />
            <span className="text-brand-300">Sovereign by default.</span>
          </h1>
          <p className="mt-5 max-w-2xl text-lg leading-relaxed text-gray-400">
            Deploy the same MIT-licensed agent loop into an air-gapped network,
            an on-prem Kubernetes cluster, your VPC on any major cloud, or a
            sovereign-cloud region. Pick the LLM trust boundary that fits your
            policy — including a fully local one — and pin data residency to a
            specific region.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <a
              href="mailto:hello@tryaisoc.com?subject=AiSOC%20sovereign%20deployment"
              className="inline-flex items-center gap-2 rounded-md bg-brand-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-brand-400"
            >
              Talk to us about sovereign deployment
              <svg
                viewBox="0 0 20 20"
                className="h-3.5 w-3.5"
                fill="currentColor"
                aria-hidden="true"
              >
                <path d="M7.05 4.05a1 1 0 011.41 0l5 5a1 1 0 010 1.41l-5 5a1 1 0 11-1.41-1.41L11.09 10 7.05 5.46a1 1 0 010-1.41z" />
              </svg>
            </a>
            <a
              href="https://github.com/beenuar/AiSOC/blob/main/docker-compose.airgap.yml"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-gray-300 transition hover:border-white/20 hover:bg-white/[0.06] hover:text-white"
            >
              See the air-gap overlay
            </a>
          </div>
        </div>
      </section>

      {/* Pillars */}
      <section className="px-6 pb-16">
        <div className="mx-auto max-w-5xl">
          <h2 className="text-2xl font-semibold tracking-tight text-white">
            Four control points, in your hands
          </h2>
          <div className="mt-8 grid gap-4 md:grid-cols-2">
            {PILLARS.map((p) => (
              <div
                key={p.label}
                className="rounded-2xl border border-white/10 bg-white/[0.02] p-6"
              >
                <div className="text-xs font-semibold uppercase tracking-wider text-brand-300">
                  {p.label}
                </div>
                <p className="mt-3 text-sm leading-relaxed text-gray-300">
                  {p.body}
                </p>
                <p className="mt-4 inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/[0.03] px-2.5 py-1 font-mono text-[11px] text-gray-300">
                  {p.cite}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Deployment matrix */}
      <section className="px-6 pb-16">
        <div className="mx-auto max-w-6xl">
          <h2 className="text-2xl font-semibold tracking-tight text-white">
            Deployment matrix
          </h2>
          <p className="mt-3 max-w-3xl text-sm text-gray-400">
            One platform, five deployment modes. Every row maps to a shipping
            artefact in the repo — no special edition, no enterprise binary,
            no closed components.
          </p>

          <div className="mt-8 overflow-x-auto rounded-2xl border border-white/10 bg-white/[0.02]">
            <table className="w-full min-w-[760px] border-collapse text-sm">
              <thead>
                <tr className="text-left text-[11px] font-semibold uppercase tracking-wider text-gray-500">
                  <th className="px-5 py-4">Mode</th>
                  <th className="px-5 py-4">LLM trust boundary</th>
                  <th className="px-5 py-4">Data residency</th>
                  <th className="px-5 py-4">Compliance posture</th>
                  <th className="px-5 py-4">Shipping artefact</th>
                </tr>
              </thead>
              <tbody>
                {DEPLOYMENT_MODES.map((row, i) => (
                  <tr
                    key={row.name}
                    className={
                      i % 2 === 0
                        ? 'border-t border-white/5'
                        : 'border-t border-white/5 bg-white/[0.015]'
                    }
                  >
                    <td className="px-5 py-4 font-semibold text-white">
                      {row.name}
                    </td>
                    <td className="px-5 py-4 text-gray-300">{row.llm}</td>
                    <td className="px-5 py-4 text-gray-300">
                      {row.residency}
                    </td>
                    <td className="px-5 py-4 text-gray-300">
                      {row.compliance}
                    </td>
                    <td className="px-5 py-4">
                      {row.artefactHref ? (
                        <a
                          href={row.artefactHref}
                          target={
                            row.artefactHref.startsWith('http')
                              ? '_blank'
                              : undefined
                          }
                          rel={
                            row.artefactHref.startsWith('http')
                              ? 'noreferrer'
                              : undefined
                          }
                          className="font-mono text-xs text-brand-300 underline decoration-brand-500/40 underline-offset-2 hover:text-brand-200"
                        >
                          {row.artefact}
                        </a>
                      ) : (
                        <span className="font-mono text-xs text-gray-300">
                          {row.artefact}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-gray-500">
            <span>Compliance frameworks supported across the matrix:</span>
            {COMPLIANCE_BADGES.map((b) => (
              <span
                key={b.label}
                className={`inline-flex items-center rounded-full border bg-white/[0.02] px-2.5 py-1 font-medium ${b.tone}`}
              >
                {b.label}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* Country / cloud combo grid */}
      <section className="px-6 pb-16">
        <div className="mx-auto max-w-6xl">
          <h2 className="text-2xl font-semibold tracking-tight text-white">
            Any cloud × any region
          </h2>
          <p className="mt-3 max-w-3xl text-sm text-gray-400">
            Because deployment is operator-controlled (Helm or Terraform into
            your account), the supported cloud / region pairs are the ones
            your provider supports — including sovereign-cloud regions.
          </p>

          <div className="mt-8 overflow-x-auto rounded-2xl border border-white/10 bg-white/[0.02]">
            <table className="w-full min-w-[640px] border-collapse text-sm">
              <thead>
                <tr className="text-left text-[11px] font-semibold uppercase tracking-wider text-gray-500">
                  <th className="px-5 py-4">Cloud</th>
                  {REGIONS.map((r) => (
                    <th key={r} className="px-5 py-4 text-center">
                      {r}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {CLOUDS.map((cloud, i) => (
                  <tr
                    key={cloud}
                    className={
                      i % 2 === 0
                        ? 'border-t border-white/5'
                        : 'border-t border-white/5 bg-white/[0.015]'
                    }
                  >
                    <td className="px-5 py-4 font-semibold text-white">
                      {cloud}
                    </td>
                    {REGIONS.map((r) => (
                      <td key={r} className="px-5 py-4 text-center">
                        <span
                          className="inline-flex h-6 w-6 items-center justify-center rounded-full border border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                          aria-label={`${cloud} ${r} supported`}
                        >
                          <svg
                            viewBox="0 0 20 20"
                            className="h-3 w-3"
                            fill="currentColor"
                            aria-hidden="true"
                          >
                            <path d="M16.7 5.3a1 1 0 010 1.4l-7 7a1 1 0 01-1.4 0l-3.5-3.5a1 1 0 011.4-1.4L9 11.6l6.3-6.3a1 1 0 011.4 0z" />
                          </svg>
                        </span>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-xs text-gray-500">
            “Custom” covers sovereign-cloud regions (e.g. AWS GovCloud, Azure
            Germany, OVH, Scaleway, IBM Cloud) and on-prem Kubernetes clusters
            reachable from your operator network.
          </p>
        </div>
      </section>

      {/* What ships in the repo */}
      <section className="px-6 pb-16">
        <div className="mx-auto max-w-5xl">
          <h2 className="text-2xl font-semibold tracking-tight text-white">
            What ships in the repo
          </h2>
          <div className="mt-8 grid gap-4 md:grid-cols-3">
            <RepoArtefact
              label="Air-gap overlay"
              path="docker-compose.airgap.yml"
              href="https://github.com/beenuar/AiSOC/blob/main/docker-compose.airgap.yml"
              body="Compose overlay that adds an Ollama sidecar with a pinned model and flips AISOC_AIRGAPPED=true on every service that calls an LLM."
            />
            <RepoArtefact
              label="Helm chart"
              path="infra/helm/aisoc/"
              href="https://github.com/beenuar/AiSOC/tree/main/infra/helm/aisoc"
              body="Single Helm release for every backend service, the web console, and the realtime gateway. Production-shaped values for resource limits, secrets, and ingress."
            />
            <RepoArtefact
              label="Terraform modules"
              path="infra/terraform/"
              href="https://github.com/beenuar/AiSOC/tree/main/infra/terraform"
              body="AWS EKS, GCP Cloud Run, and a BYOC blueprint that consumes your VPC, KMS, and IAM rather than reinventing them."
            />
            <RepoArtefact
              label="Credential vault"
              path="services/api/app/services/credentials.py"
              href="https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/credentials.py"
              body="Fernet AES-128-CBC + HMAC-SHA256. Per-tenant LLM credentials, connector secrets, and webhook tokens never leave the vault in plaintext."
            />
            <RepoArtefact
              label="Investigation ledger"
              path="services/agents/app/ledger/"
              href="https://github.com/beenuar/AiSOC/tree/main/services/agents/app/ledger"
              body="Every prompt, tool call, evidence row, and decision the agent makes — durable and replayable. The auditor reads the events directly, not a vendor summary."
            />
            <RepoArtefact
              label="Public eval harness"
              path="services/agents/tests/eval_data/"
              href="/benchmark"
              body="200-incident substrate suite + 1,000-alert noisy stream. Reproducible locally, gated in CI on every PR. The benchmark page documents what each metric measures."
            />
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="px-6 pb-24">
        <div className="mx-auto max-w-4xl rounded-2xl border border-brand-500/20 bg-brand-500/[0.04] p-8 text-center md:p-10">
          <h2 className="text-2xl font-semibold tracking-tight text-white">
            Talk to us about sovereign deployment
          </h2>
          <p className="mx-auto mt-3 max-w-2xl text-sm leading-relaxed text-gray-300">
            Tell us the cloud, region, LLM trust boundary, and compliance
            regime you need to land. We&apos;ll point you at the right Helm
            values, Terraform module, or air-gap overlay — and stay on the
            line for the first deployment.
          </p>
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <a
              href="mailto:hello@tryaisoc.com?subject=AiSOC%20sovereign%20deployment"
              className="inline-flex items-center gap-2 rounded-md bg-brand-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-brand-400"
            >
              Email hello@tryaisoc.com
            </a>
            <Link
              href="/customers"
              className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-gray-300 transition hover:border-white/20 hover:bg-white/[0.06] hover:text-white"
            >
              See who runs it in production
            </Link>
            <a
              href="https://github.com/beenuar/AiSOC"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-gray-300 transition hover:border-white/20 hover:bg-white/[0.06] hover:text-white"
            >
              Browse the repo
            </a>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}

function RepoArtefact({
  label,
  path,
  href,
  body,
}: {
  label: string;
  path: string;
  href: string;
  body: string;
}) {
  const external = href.startsWith('http');
  const inner = (
    <div className="group h-full rounded-2xl border border-white/10 bg-white/[0.02] p-6 transition hover:border-white/20 hover:bg-white/[0.04]">
      <div className="text-xs font-semibold uppercase tracking-wider text-emerald-300">
        {label}
      </div>
      <code className="mt-2 block break-all font-mono text-[11px] text-gray-400">
        {path}
      </code>
      <p className="mt-3 text-sm leading-relaxed text-gray-300">{body}</p>
      <span className="mt-4 inline-flex items-center gap-1 text-xs font-medium text-gray-400 group-hover:text-white">
        Open
        <svg
          viewBox="0 0 20 20"
          className="h-3 w-3"
          fill="currentColor"
          aria-hidden="true"
        >
          <path d="M5.22 14.78a.75.75 0 001.06 0l7.22-7.22v3.69a.75.75 0 001.5 0v-5.5a.75.75 0 00-.75-.75h-5.5a.75.75 0 000 1.5h3.69L5.22 13.72a.75.75 0 000 1.06z" />
        </svg>
      </span>
    </div>
  );
  return external ? (
    <a href={href} target="_blank" rel="noreferrer">
      {inner}
    </a>
  ) : (
    <Link href={href}>{inner}</Link>
  );
}
