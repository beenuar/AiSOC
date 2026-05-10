'use client';

/**
 * Settings.
 *
 * Tabbed workspace surfacing every preference an analyst or admin needs:
 *   - Profile        Identity + display preferences for the current operator.
 *   - Workspace      Tenant / org-level metadata.
 *   - Integrations   Connectors managed via the connectorsApi.
 *   - API keys       Programmatic access (demo).
 *   - Notifications  Alerting preferences (localStorage).
 *   - Appearance     Theme, density, motion (localStorage).
 *   - Audit log      Recent settings/security events (demo).
 *   - About          Build, license, support links.
 *
 * Designed to keep working when the backend hasn't been deployed: everything
 * has a graceful demo fallback so the page always feels alive.
 */

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { motion, AnimatePresence } from 'framer-motion';
import { format, formatDistanceToNow } from 'date-fns';
import toast from 'react-hot-toast';
import {
  ApiError,
  connectorsApi,
  deploymentApi,
  type AirgapStatus,
  type Connector,
  type ConnectorStatus,
  type LlmCredentialUpsert,
  type LlmCredentialView,
  type LlmProvider,
  type LlmStatus,
  type LlmWritableProvider,
} from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorState } from '@/components/ui/ErrorState';
import { EmptyState } from '@/components/ui/EmptyState';
import { AutonomyPolicyPanel } from '@/components/settings/AutonomyPolicy';
import { useTheme, type ThemePreference } from '@/components/theme/ThemeProvider';

// ─── Types ────────────────────────────────────────────────────────────────────

type TabId =
  | 'profile'
  | 'workspace'
  | 'integrations'
  | 'autonomy'
  | 'api-keys'
  | 'notifications'
  | 'appearance'
  | 'deployment'
  | 'audit'
  | 'about';

interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  createdAt: string;
  lastUsedAt?: string;
}

interface AuditEntry {
  id: string;
  actor: string;
  action: string;
  target: string;
  at: string;
}

interface Preferences {
  theme: 'system' | 'dark' | 'light';
  density: 'comfortable' | 'compact';
  motion: 'full' | 'reduced';
  alertSoundsEnabled: boolean;
  emailDigestFrequency: 'realtime' | 'hourly' | 'daily' | 'off';
  defaultTimeRange: '15m' | '1h' | '24h' | '7d';
  desktopNotifications: boolean;
  copilotAutoOpen: boolean;
}

const DEFAULT_PREFS: Preferences = {
  theme: 'dark',
  density: 'comfortable',
  motion: 'full',
  alertSoundsEnabled: true,
  emailDigestFrequency: 'hourly',
  defaultTimeRange: '24h',
  desktopNotifications: true,
  copilotAutoOpen: false,
};

const STORAGE_KEY = 'aisoc:settings:preferences';
const PROFILE_KEY = 'aisoc:settings:profile';

interface ProfileData {
  displayName: string;
  email: string;
  title: string;
  timezone: string;
}

const DEFAULT_PROFILE: ProfileData = {
  displayName: 'Sasha Lin',
  email: 'sasha.lin@example.com',
  title: 'Senior SOC Analyst',
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
};

// ─── Demo fallbacks ───────────────────────────────────────────────────────────

// Deterministic base — no Date.now() to avoid SSR hydration mismatches.
const MOCK_BASE = new Date('2026-05-06T12:00:00Z').getTime();
const ago = (mins: number) => new Date(MOCK_BASE - mins * 60 * 1000).toISOString();

const DEMO_CONNECTORS: Connector[] = [
  {
    id: 'c-okta',
    name: 'Okta — Identity Logs',
    type: 'okta',
    status: 'active',
    enabled: true,
    description: 'System log + risk events from the Okta admin tenant.',
    lastSync: ago(2),
    alertsIngested: 1842,
    alertCount: 1842,
    createdAt: ago(60 * 24 * 14),
  },
  {
    id: 'c-aws',
    name: 'AWS GuardDuty — prod-us-east-1',
    type: 'aws_guardduty',
    status: 'active',
    enabled: true,
    description: 'High/medium severity findings, replicated every 60s.',
    lastSync: ago(1),
    alertsIngested: 421,
    alertCount: 421,
    createdAt: ago(60 * 24 * 30),
  },
  {
    id: 'c-crowd',
    name: 'CrowdStrike Falcon EDR',
    type: 'crowdstrike',
    status: 'error',
    enabled: true,
    description: 'Streaming detections failed — auth token expired.',
    lastSync: ago(45),
    alertsIngested: 8754,
    alertCount: 8754,
    errorMessage: '401 Unauthorized — refresh OAuth credential.',
    createdAt: ago(60 * 24 * 60),
  },
  {
    id: 'c-zsc',
    name: 'Zscaler — DNS / URL Logs',
    type: 'zscaler',
    status: 'configuring',
    enabled: false,
    description: 'Awaiting NSS feed approval from network team.',
    createdAt: ago(60 * 6),
  },
  {
    id: 'c-mde',
    name: 'Microsoft Defender for Endpoint',
    type: 'mde',
    status: 'inactive',
    enabled: false,
    description: 'Disabled — replaced by CrowdStrike.',
    lastSync: ago(60 * 24 * 21),
    alertsIngested: 1244,
    alertCount: 1244,
    createdAt: ago(60 * 24 * 90),
  },
];

const DEMO_API_KEYS: ApiKey[] = [
  {
    id: 'key-1',
    name: 'CI / Detection-as-Code Pipeline',
    prefix: 'aisoc_live_xLm9…',
    scopes: ['detection:read', 'detection:write', 'cases:read'],
    createdAt: ago(60 * 24 * 90),
    lastUsedAt: ago(20),
  },
  {
    id: 'key-2',
    name: 'Splunk forwarder',
    prefix: 'aisoc_live_aQ02…',
    scopes: ['ingest:write'],
    createdAt: ago(60 * 24 * 240),
    lastUsedAt: ago(2),
  },
  {
    id: 'key-3',
    name: 'PagerDuty webhook',
    prefix: 'aisoc_live_TT74…',
    scopes: ['cases:write', 'cases:read'],
    createdAt: ago(60 * 24 * 30),
  },
];

const DEMO_AUDIT: AuditEntry[] = [
  {
    id: 'a-1',
    actor: 'sasha.lin@example.com',
    action: 'enabled',
    target: 'Detection rule “Impossible Travel — Same User”',
    at: ago(12),
  },
  {
    id: 'a-2',
    actor: 'admin@example.com',
    action: 'rotated',
    target: 'API key “CI / Detection-as-Code Pipeline”',
    at: ago(60 * 6),
  },
  {
    id: 'a-3',
    actor: 'system',
    action: 'failed-sync',
    target: 'Connector “CrowdStrike Falcon EDR”',
    at: ago(45),
  },
  {
    id: 'a-4',
    actor: 'sasha.lin@example.com',
    action: 'invited',
    target: 'avi.sharma@example.com (analyst)',
    at: ago(60 * 24 * 1),
  },
  {
    id: 'a-5',
    actor: 'admin@example.com',
    action: 'changed',
    target: 'Workspace timezone to America/Los_Angeles',
    at: ago(60 * 24 * 5),
  },
];

const STATUS_PILL: Record<ConnectorStatus, string> = {
  active: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/40',
  inactive: 'bg-gray-500/10 text-gray-400 ring-gray-500/30',
  error: 'bg-red-500/10 text-red-300 ring-red-500/40',
  configuring: 'bg-amber-500/10 text-amber-300 ring-amber-500/40',
};

const STATUS_LABEL: Record<ConnectorStatus, string> = {
  active: 'Active',
  inactive: 'Disabled',
  error: 'Error',
  configuring: 'Configuring',
};

// ─── Persistence helpers ──────────────────────────────────────────────────────

function loadPreferences(): Preferences {
  if (typeof window === 'undefined') return DEFAULT_PREFS;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_PREFS;
    return { ...DEFAULT_PREFS, ...(JSON.parse(raw) as Partial<Preferences>) };
  } catch {
    return DEFAULT_PREFS;
  }
}

function savePreferences(prefs: Preferences) {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    /* ignore */
  }
}

function loadProfile(): ProfileData {
  if (typeof window === 'undefined') return DEFAULT_PROFILE;
  try {
    const raw = window.localStorage.getItem(PROFILE_KEY);
    if (!raw) return DEFAULT_PROFILE;
    return { ...DEFAULT_PROFILE, ...(JSON.parse(raw) as Partial<ProfileData>) };
  } catch {
    return DEFAULT_PROFILE;
  }
}

function saveProfile(profile: ProfileData) {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
  } catch {
    /* ignore */
  }
}

// ─── Tabs ─────────────────────────────────────────────────────────────────────

const TABS: { id: TabId; label: string; description: string }[] = [
  {
    id: 'profile',
    label: 'Profile',
    description: 'Identity and personal display preferences.',
  },
  {
    id: 'workspace',
    label: 'Workspace',
    description: 'Tenant, branding, locale.',
  },
  {
    id: 'integrations',
    label: 'Integrations',
    description: 'Connected log sources, EDRs, identity providers.',
  },
  {
    id: 'autonomy',
    label: 'Autonomy guardrails',
    description: 'Per-action confidence thresholds for agent actions.',
  },
  {
    id: 'api-keys',
    label: 'API keys',
    description: 'Programmatic access for pipelines and integrations.',
  },
  {
    id: 'notifications',
    label: 'Notifications',
    description: 'How and when AiSOC should ping you.',
  },
  {
    id: 'appearance',
    label: 'Appearance',
    description: 'Theme, density, animations.',
  },
  {
    id: 'deployment',
    label: 'Deployment & AI',
    description:
      'Live air-gap policy and LLM provider snapshot for this AiSOC pod.',
  },
  {
    id: 'audit',
    label: 'Audit log',
    description: 'Recent administrative events.',
  },
  {
    id: 'about',
    label: 'About',
    description: 'Version, license, links.',
  },
];

// ─── Component ────────────────────────────────────────────────────────────────

export function SettingsView() {
  const [tab, setTab] = useState<TabId>('profile');

  return (
    <div className="space-y-5">
      <header className="flex flex-col gap-2">
        <h1 className="text-2xl font-semibold text-gray-100">Settings</h1>
        <p className="max-w-2xl text-sm text-gray-500">
          Configure your account, the workspace, and the integrations that feed
          the SOC. Most preferences sync across devices; appearance and
          notification preferences live on this device only.
        </p>
      </header>

      <div className="flex flex-col gap-5 lg:flex-row lg:items-start">
        {/* ── Sidebar ── */}
        <nav
          aria-label="Settings sections"
          className="lg:sticky lg:top-4 lg:w-64 lg:shrink-0"
        >
          <ul className="space-y-1 rounded-xl border border-gray-800 bg-gray-900/40 p-2">
            {TABS.map((t) => {
              const active = tab === t.id;
              return (
                <li key={t.id}>
                  <button
                    type="button"
                    onClick={() => setTab(t.id)}
                    className={clsx(
                      'flex w-full flex-col items-start gap-0.5 rounded-lg px-3 py-2.5 text-left text-sm transition-colors',
                      active
                        ? 'bg-gray-800/80 text-gray-50 ring-1 ring-blue-500/40'
                        : 'text-gray-300 hover:bg-gray-800/50 hover:text-gray-100',
                    )}
                  >
                    <span className="font-medium">{t.label}</span>
                    <span className="text-xs text-gray-500">
                      {t.description}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* ── Panel ── */}
        <div className="flex-1 min-w-0">
          <AnimatePresence mode="wait">
            <motion.div
              key={tab}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.18 }}
              className="rounded-xl border border-gray-800 bg-gray-900/40"
            >
              {tab === 'profile' && <ProfilePanel />}
              {tab === 'workspace' && <WorkspacePanel />}
              {tab === 'integrations' && <IntegrationsPanel />}
              {tab === 'autonomy' && <AutonomyPolicyPanel />}
              {tab === 'api-keys' && <ApiKeysPanel />}
              {tab === 'notifications' && <NotificationsPanel />}
              {tab === 'appearance' && <AppearancePanel />}
              {tab === 'deployment' && <DeploymentAIPanel />}
              {tab === 'audit' && <AuditPanel />}
              {tab === 'about' && <AboutPanel />}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}

// ─── Shared panel chrome ──────────────────────────────────────────────────────

function PanelHeader({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-3 border-b border-gray-800 px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h2 className="text-lg font-semibold text-gray-100">{title}</h2>
        <p className="mt-1 max-w-xl text-sm text-gray-500">{description}</p>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-sm font-medium text-gray-300">{label}</span>
      {children}
      {hint ? <span className="text-xs text-gray-500">{hint}</span> : null}
    </label>
  );
}

function inputClass() {
  return clsx(
    'w-full rounded-lg border border-gray-700 bg-gray-950/60 px-3 py-2 text-sm text-gray-100',
    'placeholder:text-gray-600 focus:border-blue-500/60 focus:outline-none focus:ring-1 focus:ring-blue-500/40',
  );
}

function Toggle({
  checked,
  onChange,
  label,
  description,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  description?: string;
}) {
  return (
    <div className="flex items-start justify-between gap-4 rounded-lg border border-gray-800 bg-gray-950/40 p-4">
      <div className="min-w-0">
        <p className="text-sm font-medium text-gray-200">{label}</p>
        {description ? (
          <p className="mt-1 text-xs text-gray-500">{description}</p>
        ) : null}
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => onChange(!checked)}
        className={clsx(
          'relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500/50',
          checked ? 'bg-blue-500/80' : 'bg-gray-700',
        )}
      >
        <span
          className={clsx(
            'inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform',
            checked ? 'translate-x-5' : 'translate-x-0.5',
          )}
        />
      </button>
    </div>
  );
}

// ─── Panel: Profile ───────────────────────────────────────────────────────────

function ProfilePanel() {
  const [profile, setProfile] = useState<ProfileData>(DEFAULT_PROFILE);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    setProfile(loadProfile());
  }, []);

  const update = <K extends keyof ProfileData>(key: K, value: ProfileData[K]) => {
    setProfile((p) => ({ ...p, [key]: value }));
    setDirty(true);
  };

  const onSave = () => {
    saveProfile(profile);
    setDirty(false);
    toast.success('Profile updated');
  };

  const initials = profile.displayName
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]?.toUpperCase() ?? '')
    .join('');

  return (
    <div>
      <PanelHeader
        title="Profile"
        description="Your identity inside this workspace. Used in cases, audit, and assignments."
        action={
          <button
            type="button"
            disabled={!dirty}
            onClick={onSave}
            className={clsx(
              'rounded-lg px-4 py-2 text-sm font-medium transition-colors',
              dirty
                ? 'bg-blue-600 text-white hover:bg-blue-500'
                : 'cursor-not-allowed bg-gray-800 text-gray-500',
            )}
          >
            Save changes
          </button>
        }
      />
      <div className="space-y-5 px-6 py-5">
        <div className="flex items-center gap-4">
          <div
            aria-hidden
            className="flex h-16 w-16 items-center justify-center rounded-full bg-blue-600 text-xl font-semibold text-white ring-2 ring-gray-800"
          >
            {initials || '?'}
          </div>
          <div className="min-w-0">
            <p className="truncate text-base font-semibold text-gray-100">
              {profile.displayName || 'Unnamed user'}
            </p>
            <p className="truncate text-sm text-gray-400">{profile.email}</p>
            <p className="mt-1 text-xs text-gray-500">
              Avatar generated from initials.{' '}
              <span className="inline-flex items-center gap-1">
                Custom avatars
                <span className="text-[10px] font-medium rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30 px-1.5 py-0.5">
                  Planned for v1.1
                </span>
              </span>
            </p>
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Display name">
            <input
              className={inputClass()}
              value={profile.displayName}
              onChange={(e) => update('displayName', e.target.value)}
              placeholder="e.g. Avi Sharma"
            />
          </Field>
          <Field label="Email" hint="Used for notifications and login.">
            <input
              type="email"
              className={inputClass()}
              value={profile.email}
              onChange={(e) => update('email', e.target.value)}
              placeholder="you@org.com"
            />
          </Field>
          <Field label="Job title">
            <input
              className={inputClass()}
              value={profile.title}
              onChange={(e) => update('title', e.target.value)}
              placeholder="e.g. SOC Analyst"
            />
          </Field>
          <Field label="Timezone" hint="Used to localize timestamps.">
            <input
              className={inputClass()}
              value={profile.timezone}
              onChange={(e) => update('timezone', e.target.value)}
              placeholder="e.g. America/Los_Angeles"
            />
          </Field>
        </div>

        <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-4 text-xs text-gray-500">
          Profile preferences are persisted to your user account and sync
          across devices when you sign in.
        </div>
      </div>
    </div>
  );
}

// ─── Panel: Workspace ─────────────────────────────────────────────────────────

function WorkspacePanel() {
  return (
    <div>
      <PanelHeader
        title="Workspace"
        description="Tenant identity and locale settings. Available to workspace administrators."
      />
      <div className="grid gap-5 px-6 py-5 sm:grid-cols-2">
        <InfoTile label="Workspace name" value="AiSOC Demo" />
        <InfoTile label="Tenant ID" value="tenant_demo_01H0XE4T2WJ9N6" mono />
        <InfoTile label="Plan" value="Open-source (MIT)" />
        <InfoTile label="Region" value="us-east-1 / Multi-AZ" />
        <InfoTile label="Created" value={format(Date.now() - 1000 * 60 * 60 * 24 * 96, 'PPP')} />
        <InfoTile
          label="Default locale"
          value={`${Intl.DateTimeFormat().resolvedOptions().locale} • 24h`}
        />
      </div>
      <div className="border-t border-gray-800 px-6 py-5">
        <h3 className="text-sm font-semibold text-gray-200">Members</h3>
        <p className="mt-1 text-xs text-gray-500">
          5 active operators in this workspace (demo data).
        </p>
        <ul className="mt-3 divide-y divide-gray-800 rounded-lg border border-gray-800 bg-gray-950/40">
          {[
            { name: 'Sasha Lin', email: 'sasha.lin@example.com', role: 'Admin' },
            { name: 'Avi Sharma', email: 'avi.sharma@example.com', role: 'Analyst' },
            { name: 'Diego Vega', email: 'diego.vega@example.com', role: 'Analyst' },
            { name: 'Mia Ocampo', email: 'mia.ocampo@example.com', role: 'Hunter' },
            { name: 'CI Service', email: 'ci@example.com', role: 'Service' },
          ].map((m) => (
            <li
              key={m.email}
              className="flex items-center justify-between px-4 py-3 text-sm"
            >
              <div className="min-w-0">
                <p className="truncate text-gray-100">{m.name}</p>
                <p className="truncate text-xs text-gray-500">{m.email}</p>
              </div>
              <span className="rounded-full bg-gray-800 px-2.5 py-1 text-xs text-gray-300 ring-1 ring-gray-700">
                {m.role}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function InfoTile({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
      <p className="text-xs uppercase tracking-wide text-gray-500">{label}</p>
      <p
        className={clsx(
          'mt-1.5 text-sm text-gray-100',
          mono && 'font-mono text-xs',
        )}
      >
        {value}
      </p>
    </div>
  );
}

// ─── Panel: Integrations ──────────────────────────────────────────────────────

function IntegrationsPanel() {
  const { data, error, isLoading, mutate } = useSWR(
    'settings:connectors',
    () => connectorsApi.list(),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  const useFallback = !!error;
  const connectors = data?.connectors ?? (useFallback ? DEMO_CONNECTORS : []);

  const counts = useMemo(() => {
    const c = { active: 0, error: 0, inactive: 0, configuring: 0 };
    for (const x of connectors) {
      c[x.status] = (c[x.status] ?? 0) + 1;
    }
    return c;
  }, [connectors]);

  const onTest = async (connector: Connector) => {
    if (useFallback) {
      toast.success(`Test sent to ${connector.name}`);
      return;
    }
    try {
      const result = await connectorsApi.test(connector.id);
      toast.success(
        `${connector.name}: ${result.success ? 'OK' : 'Failed'} • ${result.latencyMs}ms`,
      );
    } catch {
      toast.error('Test request failed');
    }
  };

  const onToggle = async (connector: Connector) => {
    const next = !(connector.enabled ?? connector.status === 'active');
    mutate(
      (curr) =>
        curr
          ? {
              ...curr,
              connectors: curr.connectors.map((c) =>
                c.id === connector.id ? { ...c, enabled: next } : c,
              ),
            }
          : curr,
      { revalidate: false },
    );
    try {
      if (!useFallback) {
        await connectorsApi.update(connector.id, { is_enabled: next });
      }
      toast.success(next ? 'Connector enabled' : 'Connector disabled');
      mutate();
    } catch {
      toast.error('Could not update connector');
      mutate();
    }
  };

  return (
    <div>
      <PanelHeader
        title="Integrations"
        description="Manage the connectors that stream telemetry into AiSOC."
        action={
          <Link
            href="/connectors/new"
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500"
          >
            + Add connector
          </Link>
        }
      />
      <div className="px-6 py-5 space-y-5">
        {/* Stat row */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <StatTile label="Active" value={counts.active} tone="emerald" />
          <StatTile label="Errors" value={counts.error} tone="red" />
          <StatTile label="Configuring" value={counts.configuring} tone="amber" />
          <StatTile label="Disabled" value={counts.inactive} tone="gray" />
        </div>

        {/* List */}
        {isLoading && !data ? (
          <div className="space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-20 w-full rounded-lg" />
            ))}
          </div>
        ) : error && !useFallback ? (
          <ErrorState
            title="Could not load integrations"
            error={error}
            onRetry={() => mutate()}
          />
        ) : connectors.length === 0 ? (
          <EmptyState
            title="No connectors yet"
            description="Add your first integration to start streaming events into AiSOC."
            action={
              <Link
                href="/connectors/new"
                className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500"
              >
                Add connector
              </Link>
            }
          />
        ) : (
          <ul className="space-y-2">
            {connectors.map((c) => (
              <li
                key={c.id}
                className="rounded-lg border border-gray-800 bg-gray-950/40 p-4 transition-colors hover:border-gray-700"
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <h3 className="truncate text-sm font-semibold text-gray-100">
                        {c.name}
                      </h3>
                      <span
                        className={clsx(
                          'rounded-full px-2 py-0.5 text-xs ring-1 ring-inset',
                          STATUS_PILL[c.status],
                        )}
                      >
                        {STATUS_LABEL[c.status]}
                      </span>
                    </div>
                    {c.description ? (
                      <p className="mt-1 text-xs text-gray-500">{c.description}</p>
                    ) : null}
                    <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-gray-500">
                      <span>
                        <span className="text-gray-400">Type:</span>{' '}
                        <span className="font-mono">{c.type}</span>
                      </span>
                      {c.lastSync ? (
                        <span suppressHydrationWarning>
                          Last sync{' '}
                          {formatDistanceToNow(new Date(c.lastSync), {
                            addSuffix: true,
                          })}
                        </span>
                      ) : null}
                      {typeof c.alertsIngested === 'number' ||
                      typeof c.alertCount === 'number' ? (
                        <span>
                          {(c.alertsIngested ?? c.alertCount ?? 0).toLocaleString()}{' '}
                          events
                        </span>
                      ) : null}
                    </div>
                    {c.errorMessage ? (
                      <p className="mt-2 rounded border border-red-500/30 bg-red-500/5 px-2 py-1 text-xs text-red-300">
                        {c.errorMessage}
                      </p>
                    ) : null}
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <button
                      type="button"
                      onClick={() => onTest(c)}
                      className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs text-gray-200 hover:bg-gray-800"
                    >
                      Test
                    </button>
                    <button
                      type="button"
                      onClick={() => onToggle(c)}
                      className={clsx(
                        'rounded-lg px-3 py-1.5 text-xs font-medium',
                        c.enabled ?? c.status === 'active'
                          ? 'bg-amber-500/10 text-amber-300 ring-1 ring-amber-500/30 hover:bg-amber-500/20'
                          : 'bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-500/30 hover:bg-emerald-500/20',
                      )}
                    >
                      {c.enabled ?? c.status === 'active' ? 'Disable' : 'Enable'}
                    </button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function StatTile({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: 'emerald' | 'red' | 'amber' | 'gray';
}) {
  const tones: Record<string, string> = {
    emerald: 'text-emerald-300',
    red: 'text-red-300',
    amber: 'text-amber-300',
    gray: 'text-gray-300',
  };
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
      <p className="text-xs uppercase tracking-wide text-gray-500">{label}</p>
      <p className={clsx('mt-1 text-2xl font-semibold tabular-nums', tones[tone])}>
        {value}
      </p>
    </div>
  );
}

// ─── Panel: API keys ──────────────────────────────────────────────────────────

function ApiKeysPanel() {
  const [keys, setKeys] = useState<ApiKey[]>(DEMO_API_KEYS);
  const [draftName, setDraftName] = useState('');
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);

  const create = () => {
    if (!draftName.trim()) {
      toast.error('Give the key a name');
      return;
    }
    const idBytes = crypto.getRandomValues(new Uint8Array(6));
    const id = `key-${Array.from(idBytes).map(b => b.toString(16).padStart(2, '0')).join('')}`;
    const secretBytes = crypto.getRandomValues(new Uint8Array(16));
    const secretBody = Array.from(secretBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const secret = `aisoc_live_${secretBody}`;
    const key: ApiKey = {
      id,
      name: draftName.trim(),
      prefix: `${secret.slice(0, 16)}…`,
      scopes: ['cases:read', 'detection:read'],
      createdAt: new Date().toISOString(),
    };
    setKeys((curr) => [key, ...curr]);
    setCreatedSecret(secret);
    setDraftName('');
    toast.success('API key created');
  };

  const revoke = (id: string) => {
    setKeys((curr) => curr.filter((k) => k.id !== id));
    toast.success('Key revoked');
  };

  const copy = (value: string) => {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(value).catch(() => undefined);
      toast.success('Copied to clipboard');
    }
  };

  return (
    <div>
      <PanelHeader
        title="API keys"
        description="Long-lived tokens used by pipelines, forwarders, and webhooks."
      />
      <div className="space-y-5 px-6 py-5">
        {/* Create */}
        <div className="flex flex-col gap-3 rounded-lg border border-gray-800 bg-gray-950/40 p-4 sm:flex-row sm:items-end">
          <Field label="Name">
            <input
              className={inputClass()}
              value={draftName}
              onChange={(e) => setDraftName(e.target.value)}
              placeholder="e.g. Detection-as-Code pipeline"
            />
          </Field>
          <button
            type="button"
            onClick={create}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500"
          >
            Generate key
          </button>
        </div>

        {/* New key reveal */}
        <AnimatePresence>
          {createdSecret ? (
            <motion.div
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-4"
            >
              <p className="text-sm font-medium text-amber-200">
                Save this key now — it will not be shown again.
              </p>
              <div className="mt-3 flex items-center gap-2">
                <code className="block flex-1 truncate rounded bg-gray-950 px-3 py-2 font-mono text-sm text-amber-100 ring-1 ring-amber-500/30">
                  {createdSecret}
                </code>
                <button
                  type="button"
                  onClick={() => copy(createdSecret)}
                  className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 hover:bg-gray-800"
                >
                  Copy
                </button>
                <button
                  type="button"
                  onClick={() => setCreatedSecret(null)}
                  className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 hover:bg-gray-800"
                >
                  Dismiss
                </button>
              </div>
            </motion.div>
          ) : null}
        </AnimatePresence>

        {/* List */}
        {keys.length === 0 ? (
          <EmptyState
            title="No API keys yet"
            description="Create your first key above to authenticate pipelines."
          />
        ) : (
          <div className="overflow-hidden rounded-lg border border-gray-800">
            <table className="w-full text-sm">
              <thead className="bg-gray-900/60 text-xs uppercase tracking-wide text-gray-500">
                <tr>
                  <th className="px-4 py-2 text-left">Name</th>
                  <th className="px-4 py-2 text-left">Prefix</th>
                  <th className="px-4 py-2 text-left">Scopes</th>
                  <th className="px-4 py-2 text-left">Created</th>
                  <th className="px-4 py-2 text-left">Last used</th>
                  <th className="px-4 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 bg-gray-950/40">
                {keys.map((k) => (
                  <tr key={k.id}>
                    <td className="px-4 py-3 font-medium text-gray-100">{k.name}</td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-400">
                      {k.prefix}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {k.scopes.map((s) => (
                          <span
                            key={s}
                            className="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-[11px] text-gray-300 ring-1 ring-gray-700"
                          >
                            {s}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400" suppressHydrationWarning>
                      {format(new Date(k.createdAt), 'PPP')}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400" suppressHydrationWarning>
                      {k.lastUsedAt
                        ? formatDistanceToNow(new Date(k.lastUsedAt), {
                            addSuffix: true,
                          })
                        : '—'}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => revoke(k.id)}
                        className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-300 hover:bg-red-500/20"
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Panel: Notifications ─────────────────────────────────────────────────────

function NotificationsPanel() {
  const [prefs, setPrefs] = useState<Preferences>(DEFAULT_PREFS);

  useEffect(() => {
    setPrefs(loadPreferences());
  }, []);

  const update = <K extends keyof Preferences>(key: K, value: Preferences[K]) => {
    setPrefs((p) => {
      const next = { ...p, [key]: value };
      savePreferences(next);
      return next;
    });
    toast.success('Saved');
  };

  return (
    <div>
      <PanelHeader
        title="Notifications"
        description="How AiSOC pings you when things happen."
      />
      <div className="space-y-3 px-6 py-5">
        <Toggle
          label="Desktop notifications"
          description="Native browser notifications for new critical alerts."
          checked={prefs.desktopNotifications}
          onChange={(v) => update('desktopNotifications', v)}
        />
        <Toggle
          label="Alert sounds"
          description="Play a short tone when a critical alert arrives."
          checked={prefs.alertSoundsEnabled}
          onChange={(v) => update('alertSoundsEnabled', v)}
        />
        <Toggle
          label="Auto-open Copilot for high-severity alerts"
          description="Surfaces an investigation suggestion as soon as a critical alert lands."
          checked={prefs.copilotAutoOpen}
          onChange={(v) => update('copilotAutoOpen', v)}
        />

        <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
          <Field
            label="Email digest frequency"
            hint="Roll-up email summarizing alerts and case activity."
          >
            <select
              className={inputClass()}
              value={prefs.emailDigestFrequency}
              onChange={(e) =>
                update(
                  'emailDigestFrequency',
                  e.target.value as Preferences['emailDigestFrequency'],
                )
              }
            >
              <option value="realtime">Real-time</option>
              <option value="hourly">Hourly</option>
              <option value="daily">Daily</option>
              <option value="off">Off</option>
            </select>
          </Field>
        </div>

        <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
          <Field
            label="Default time range"
            hint="Used by Hunt, Dashboard, and Cases when you first arrive."
          >
            <select
              className={inputClass()}
              value={prefs.defaultTimeRange}
              onChange={(e) =>
                update(
                  'defaultTimeRange',
                  e.target.value as Preferences['defaultTimeRange'],
                )
              }
            >
              <option value="15m">Last 15 minutes</option>
              <option value="1h">Last hour</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
            </select>
          </Field>
        </div>
      </div>
    </div>
  );
}

// ─── Panel: Appearance ────────────────────────────────────────────────────────

function AppearancePanel() {
  const [prefs, setPrefs] = useState<Preferences>(DEFAULT_PREFS);
  const { preference: themePreference, setPreference: setThemePreference } =
    useTheme();

  useEffect(() => {
    setPrefs(loadPreferences());
  }, []);

  const update = <K extends keyof Preferences>(key: K, value: Preferences[K]) => {
    setPrefs((p) => {
      const next = { ...p, [key]: value };
      savePreferences(next);
      return next;
    });
  };

  // Theme is owned by the global ThemeProvider (it sets `data-theme` on
  // <html>, primes the FOUC script, and persists to its own storage key).
  // We mirror it into the legacy `prefs.theme` slot so settings exports stay
  // accurate, but `useTheme()` is the source of truth for what the operator
  // sees on screen.
  const onThemeSelect = (next: ThemePreference) => {
    setThemePreference(next);
    update('theme', next);
  };

  return (
    <div>
      <PanelHeader
        title="Appearance"
        description="Tune how AiSOC looks and animates on this device."
      />
      <div className="space-y-5 px-6 py-5">
        {/* Theme */}
        <div>
          <p className="text-sm font-medium text-gray-300">Theme</p>
          <p className="mt-1 text-xs text-gray-500">
            Pick the palette this browser uses. Synced to your user profile.
          </p>
          <div className="mt-3 grid grid-cols-3 gap-3">
            {(['system', 'dark', 'light'] as const satisfies readonly ThemePreference[]).map((t) => {
              const active = themePreference === t;
              return (
                <button
                  key={t}
                  type="button"
                  onClick={() => onThemeSelect(t)}
                  aria-pressed={active}
                  className={clsx(
                    'rounded-xl border p-3 text-left transition-colors',
                    active
                      ? 'border-blue-500/60 bg-blue-500/10'
                      : 'border-gray-800 bg-gray-950/40 hover:border-gray-700',
                  )}
                >
                  <span className="block text-sm font-medium capitalize text-gray-100">
                    {t}
                  </span>
                  <span className="mt-1 block text-xs text-gray-500">
                    {t === 'system'
                      ? 'Match OS preference'
                      : t === 'dark'
                      ? 'Operations-room dark'
                      : 'High-contrast light'}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Density */}
        <div>
          <p className="text-sm font-medium text-gray-300">Density</p>
          <div className="mt-3 grid grid-cols-2 gap-3">
            {(['comfortable', 'compact'] as const).map((d) => {
              const active = prefs.density === d;
              return (
                <button
                  key={d}
                  type="button"
                  onClick={() => update('density', d)}
                  className={clsx(
                    'rounded-xl border p-3 text-left transition-colors',
                    active
                      ? 'border-blue-500/60 bg-blue-500/10'
                      : 'border-gray-800 bg-gray-950/40 hover:border-gray-700',
                  )}
                >
                  <span className="block text-sm font-medium capitalize text-gray-100">
                    {d}
                  </span>
                  <span className="mt-1 block text-xs text-gray-500">
                    {d === 'comfortable'
                      ? 'Default — relaxed spacing'
                      : 'Tighter rows for high-density workloads'}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Motion */}
        <Toggle
          label="Reduce motion"
          description="Disable non-essential animations. Recommended if you have motion sensitivity."
          checked={prefs.motion === 'reduced'}
          onChange={(v) => update('motion', v ? 'reduced' : 'full')}
        />
      </div>
    </div>
  );
}

// ─── Panel: Deployment & AI ───────────────────────────────────────────────────
//
// Operator visibility + per-tenant BYOK control for three questions that are
// always asked during security review:
//
//   1. "Is air-gap actually engaged on this pod?"            → /api/v1/airgap/status
//   2. "Where will my AI calls actually go?"                 → /api/v1/llm/status
//   3. "Can this tenant point AI at its own LLM (BYOK)?"     → /api/v1/llm/credentials
//
// (1) and (2) are server-rendered snapshots that mirror the same code paths the
// runtime uses to gate egress (``app.core.airgap.is_host_allowed_for_airgap``)
// and to pick the LLM transport (``services/agents/app/api/explain.py``). That
// is deliberate: the indicator the operator sees here CANNOT drift from runtime
// behaviour — there is no second source of truth.
//
// (3) is a write surface, scoped to the current tenant and protected by the
// ``settings:write`` permission. API keys are never echoed back; the backend
// only ever returns ``has_api_key`` so the UI can show "set / not set". Mutations
// are encrypted with ``CredentialVault`` server-side and audit-logged.

const PROVIDER_LABEL: Record<LlmProvider, string> = {
  openai: 'OpenAI',
  anthropic: 'Anthropic',
  'azure-openai': 'Azure OpenAI',
  'local-ollama': 'Local Ollama',
  'local-vllm': 'Local vLLM',
  'local-litellm': 'Local LiteLLM',
  custom: 'Custom endpoint',
  none: 'Not configured',
};

function DeploymentAIPanel() {
  const airgap = useSWR(
    'settings:airgap-status',
    () => deploymentApi.getAirgapStatus(),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );
  const llm = useSWR(
    'settings:llm-status',
    () => deploymentApi.getLlmStatus(),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );
  const credential = useSWR(
    'settings:llm-credential',
    () => deploymentApi.getLlmCredential(),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  const isLoading = airgap.isLoading || llm.isLoading;
  const error = airgap.error ?? llm.error;
  const onRetry = () => {
    airgap.mutate();
    llm.mutate();
    credential.mutate();
  };

  return (
    <div>
      <PanelHeader
        title="Deployment & AI"
        description="Air-gap policy, LLM provider snapshot, and per-tenant BYOK overrides for this AiSOC pod."
      />
      <div className="space-y-5 px-6 py-5">
        {isLoading && !airgap.data && !llm.data ? (
          <div className="space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-24 w-full rounded-lg" />
            ))}
          </div>
        ) : error ? (
          <ErrorState
            title="Could not load deployment status"
            error={error}
            onRetry={onRetry}
          />
        ) : (
          <>
            {airgap.data ? <AirgapCard status={airgap.data} /> : null}
            {llm.data ? (
              <LlmCard llm={llm.data} airgap={airgap.data ?? null} />
            ) : null}
            <BYOKCard
              credential={credential.data ?? null}
              isLoading={credential.isLoading}
              error={credential.error}
              onChanged={() => {
                credential.mutate();
                // Resolved LLM status changes whenever a tenant override moves,
                // so refresh the read-only snapshot too.
                llm.mutate();
              }}
            />
            <p className="text-xs text-gray-500">
              The air-gap policy and provider snapshot above are sampled live
              from this pod and mirror the egress gate exactly. To change them
              cluster-wide, update environment variables and redeploy. See{' '}
              <a
                href="https://beenuar.github.io/AiSOC/docs/operations/airgap/"
                target="_blank"
                rel="noreferrer"
                className="text-blue-400 hover:text-blue-300 hover:underline"
              >
                Air-gapped deployments
              </a>
              .
            </p>
          </>
        )}
      </div>
    </div>
  );
}

function AirgapCard({ status }: { status: AirgapStatus }) {
  return (
    <section
      className="rounded-xl border border-gray-800 bg-gray-950/40 p-5"
      aria-label="Air-gap policy"
    >
      <header className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-gray-100">Air-gap policy</h3>
          <p className="mt-1 text-xs text-gray-500">
            Enforced by the egress gate before any outbound HTTP request.
          </p>
        </div>
        <StatusPill
          tone={status.enabled ? 'emerald' : 'gray'}
          label={status.enabled ? 'Enabled' : 'Disabled'}
        />
      </header>

      <dl className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <KeyValue label="Policy">{status.policy}</KeyValue>
        <KeyValue label="Operator allowlist">
          {status.allowlist.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {status.allowlist.map((host) => (
                <code
                  key={host}
                  className="rounded bg-gray-900 px-1.5 py-0.5 font-mono text-[11px] text-gray-200"
                >
                  {host}
                </code>
              ))}
            </div>
          ) : (
            <span className="text-gray-500">— none configured —</span>
          )}
        </KeyValue>
        <KeyValue label="Always-allowed private suffixes">
          <div className="flex flex-wrap gap-1.5">
            {status.implicit_private_suffixes.map((suffix) => (
              <code
                key={suffix}
                className="rounded bg-gray-900 px-1.5 py-0.5 font-mono text-[11px] text-gray-400"
              >
                {suffix}
              </code>
            ))}
          </div>
        </KeyValue>
      </dl>
    </section>
  );
}

function LlmCard({
  llm,
  airgap,
}: {
  llm: LlmStatus;
  airgap: AirgapStatus | null;
}) {
  const providerLabel = PROVIDER_LABEL[llm.provider] ?? llm.provider;
  const isFallback = llm.effective_path === 'fallback';
  const blockedByAirgap = llm.airgap_enabled && !llm.airgap_compliant;

  return (
    <section
      className="rounded-xl border border-gray-800 bg-gray-950/40 p-5"
      aria-label="LLM provider"
    >
      <header className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-gray-100">LLM provider</h3>
          <p className="mt-1 text-xs text-gray-500">
            Where Explain, triage, and other AI features will call out to.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {llm.is_local ? (
            <StatusPill tone="emerald" label="Local" />
          ) : llm.provider === 'none' ? (
            <StatusPill tone="gray" label="Unconfigured" />
          ) : (
            <StatusPill tone="amber" label="Cloud" />
          )}
          {isFallback ? (
            <StatusPill tone="amber" label="Fallback path" />
          ) : (
            <StatusPill tone="emerald" label="Live" />
          )}
        </div>
      </header>

      {blockedByAirgap ? (
        <div
          role="alert"
          className="mt-4 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-200"
        >
          <p className="font-semibold text-red-100">
            Air-gap policy is blocking this LLM host.
          </p>
          <p className="mt-1">
            <code className="font-mono">{llm.host || '—'}</code> is not in the
            operator allowlist. Live AI calls will refuse and Explain will fall
            back to the deterministic OCSF/MITRE summary. Add the host to{' '}
            <code className="font-mono">AISOC_AIRGAP_ALLOWLIST</code> or switch
            to a private LLM endpoint.
          </p>
        </div>
      ) : isFallback && llm.provider !== 'none' ? (
        <div
          role="alert"
          className="mt-4 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200"
        >
          <p className="font-semibold text-amber-100">
            Falling back to deterministic summaries.
          </p>
          <p className="mt-1">{llm.policy_note}</p>
        </div>
      ) : null}

      <dl className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <KeyValue label="Provider">{providerLabel}</KeyValue>
        <KeyValue label="Model">
          {llm.model ? (
            <code className="font-mono text-xs text-gray-100">{llm.model}</code>
          ) : (
            <span className="text-gray-500">—</span>
          )}
        </KeyValue>
        <KeyValue label="Base URL">
          {llm.base_url ? (
            <code className="break-all font-mono text-xs text-gray-200">
              {llm.base_url}
            </code>
          ) : (
            <span className="text-gray-500">—</span>
          )}
        </KeyValue>
        <KeyValue label="Host">
          {llm.host ? (
            <code className="font-mono text-xs text-gray-200">{llm.host}</code>
          ) : (
            <span className="text-gray-500">—</span>
          )}
        </KeyValue>
        <KeyValue label="API key">
          <span
            className={clsx(
              'inline-flex items-center gap-1.5 text-xs',
              llm.key_set ? 'text-emerald-300' : 'text-gray-400',
            )}
          >
            <span
              aria-hidden
              className={clsx(
                'inline-block h-1.5 w-1.5 rounded-full',
                llm.key_set ? 'bg-emerald-400' : 'bg-gray-600',
              )}
            />
            {llm.key_set ? 'Set' : 'Not set'}
          </span>
        </KeyValue>
        <KeyValue label="Air-gap compliant">
          <span
            className={clsx(
              'inline-flex items-center gap-1.5 text-xs',
              llm.airgap_compliant ? 'text-emerald-300' : 'text-red-300',
            )}
          >
            <span
              aria-hidden
              className={clsx(
                'inline-block h-1.5 w-1.5 rounded-full',
                llm.airgap_compliant ? 'bg-emerald-400' : 'bg-red-400',
              )}
            />
            {airgap && !airgap.enabled
              ? 'N/A — air-gap off'
              : llm.airgap_compliant
              ? 'Yes'
              : 'No'}
          </span>
        </KeyValue>
      </dl>

      {!blockedByAirgap && !isFallback && llm.policy_note ? (
        <p className="mt-4 text-xs text-gray-500">{llm.policy_note}</p>
      ) : null}
    </section>
  );
}

// ─── BYOK helpers ─────────────────────────────────────────────────────────────

const WRITABLE_PROVIDERS: readonly LlmWritableProvider[] = [
  'openai',
  'anthropic',
  'azure-openai',
  'local-ollama',
  'local-vllm',
  'local-litellm',
  'custom',
] as const;

const PROVIDERS_REQUIRING_BASE_URL: ReadonlySet<LlmWritableProvider> = new Set([
  'local-ollama',
  'local-vllm',
  'local-litellm',
  'custom',
]);

const PROVIDERS_REQUIRING_API_KEY: ReadonlySet<LlmWritableProvider> = new Set([
  'openai',
  'anthropic',
  'azure-openai',
]);

function providerHintFor(p: LlmWritableProvider): {
  baseUrlPlaceholder: string;
  baseUrlHint: string;
} {
  switch (p) {
    case 'local-ollama':
      return {
        baseUrlPlaceholder: 'http://ollama.example.local:11434',
        baseUrlHint: 'Point at your Ollama server (default port 11434).',
      };
    case 'local-vllm':
      return {
        baseUrlPlaceholder: 'http://vllm.example.local:8000/v1',
        baseUrlHint: 'OpenAI-compatible vLLM endpoint, typically /v1.',
      };
    case 'local-litellm':
      return {
        baseUrlPlaceholder: 'http://litellm.example.local:4000',
        baseUrlHint: 'LiteLLM proxy URL.',
      };
    case 'custom':
      return {
        baseUrlPlaceholder: 'https://internal-llm.example.com/v1',
        baseUrlHint: 'OpenAI-compatible HTTP(S) endpoint.',
      };
    case 'azure-openai':
      return {
        baseUrlPlaceholder: 'https://my-resource.openai.azure.com',
        baseUrlHint: 'Optional override for your Azure OpenAI resource.',
      };
    default:
      return {
        baseUrlPlaceholder: '',
        baseUrlHint: '',
      };
  }
}

function extractApiDetail(err: unknown, fallback = 'Something went wrong.'): string {
  if (err instanceof ApiError) {
    if (err.body) {
      try {
        const parsed = JSON.parse(err.body);
        if (parsed && typeof parsed.detail === 'string') return parsed.detail;
      } catch {
        // body wasn't JSON — fall through
      }
    }
    return err.message || fallback;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}

// ─── Card: BYOK (write surface) ──────────────────────────────────────────────

function BYOKCard({
  credential,
  isLoading,
  error,
  onChanged,
}: {
  credential: LlmCredentialView | null;
  isLoading: boolean;
  error: unknown;
  onChanged: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const [provider, setProvider] = useState<LlmWritableProvider>('openai');
  const [baseUrl, setBaseUrl] = useState('');
  const [model, setModel] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [formError, setFormError] = useState<string | null>(null);

  // Reset form whenever we enter edit mode (or the underlying credential
  // moves while editing). Never preload the API key — it lives only in
  // the vault on the server.
  useEffect(() => {
    if (!editing) {
      setFormError(null);
      setApiKey('');
      return;
    }
    if (credential) {
      setProvider(credential.provider);
      setBaseUrl(credential.base_url ?? '');
      setModel(credential.model ?? '');
      setEnabled(credential.enabled);
    } else {
      setProvider('openai');
      setBaseUrl('');
      setModel('');
      setEnabled(true);
    }
    setApiKey('');
    setFormError(null);
  }, [editing, credential]);

  const requiresBaseUrl = PROVIDERS_REQUIRING_BASE_URL.has(provider);
  const requiresApiKey = PROVIDERS_REQUIRING_API_KEY.has(provider);

  // Only treat the existing key as "carry-over" when the user keeps the
  // same provider — switching providers must require a fresh key.
  const hasExistingKey = Boolean(
    credential?.has_api_key && credential?.provider === provider,
  );

  const providerHint = useMemo(() => providerHintFor(provider), [provider]);

  const onSave = async () => {
    setFormError(null);
    if (requiresBaseUrl && !baseUrl.trim()) {
      setFormError(`${PROVIDER_LABEL[provider]} requires a base URL.`);
      return;
    }
    if (requiresApiKey && !apiKey.trim() && !hasExistingKey) {
      setFormError(`${PROVIDER_LABEL[provider]} requires an API key.`);
      return;
    }

    const payload: LlmCredentialUpsert = {
      provider,
      base_url: baseUrl.trim() ? baseUrl.trim() : null,
      model: model.trim() ? model.trim() : null,
      api_key: apiKey.trim() ? apiKey.trim() : null,
      enabled,
    };

    setSubmitting(true);
    try {
      await deploymentApi.upsertLlmCredential(payload);
      toast.success(
        credential ? 'BYOK credential updated.' : 'BYOK credential saved.',
      );
      setEditing(false);
      onChanged();
    } catch (err) {
      const detail = extractApiDetail(err, 'Could not save BYOK credential.');
      setFormError(detail);
      toast.error(detail);
    } finally {
      setSubmitting(false);
    }
  };

  const onCancel = () => {
    setEditing(false);
  };

  const onDeleteClick = async () => {
    if (!confirmingDelete) {
      setConfirmingDelete(true);
      return;
    }
    setSubmitting(true);
    try {
      await deploymentApi.deleteLlmCredential();
      toast.success(
        'BYOK credential removed. Falling back to platform defaults.',
      );
      setConfirmingDelete(false);
      onChanged();
    } catch (err) {
      toast.error(extractApiDetail(err, 'Could not remove BYOK credential.'));
    } finally {
      setSubmitting(false);
    }
  };

  if (isLoading && !credential) {
    return <Skeleton className="h-32 w-full rounded-lg" />;
  }

  // Credential fetch is independent of the read-only LLM snapshot, so a
  // failure here shouldn't poison the rest of the panel — render a soft
  // inline notice instead.
  if (error) {
    return (
      <section className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
        <p className="text-sm font-medium text-amber-200">
          BYOK panel unavailable
        </p>
        <p className="mt-1 text-xs text-amber-300/70">
          {extractApiDetail(error, 'Could not load tenant LLM credential.')}
        </p>
      </section>
    );
  }

  // ── VIEW: have credential, not editing ──────────────────────────────────
  if (credential && !editing) {
    return (
      <section className="rounded-lg border border-gray-800 bg-gray-950/40 p-5">
        <header className="flex items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-gray-200">
                Bring-your-own-LLM (BYOK)
              </h3>
              {credential.enabled ? (
                <StatusPill tone="emerald" label="Active" />
              ) : (
                <StatusPill tone="gray" label="Disabled" />
              )}
            </div>
            <p className="mt-1 text-xs text-gray-500">
              Per-tenant override for this AiSOC workspace. The platform
              uses these settings instead of the pod-level defaults.
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              type="button"
              onClick={() => setEditing(true)}
              className="rounded-md border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs font-medium text-gray-200 hover:bg-gray-800"
            >
              Edit
            </button>
            <button
              type="button"
              onClick={onDeleteClick}
              disabled={submitting}
              className={clsx(
                'rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50',
                confirmingDelete
                  ? 'border border-red-500/50 bg-red-500/15 text-red-200 hover:bg-red-500/25'
                  : 'border border-gray-700 bg-gray-900 text-gray-200 hover:bg-gray-800',
              )}
            >
              {confirmingDelete ? 'Confirm remove' : 'Remove'}
            </button>
          </div>
        </header>
        <dl className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <KeyValue label="Provider">
            <span className="text-sm text-gray-200">
              {PROVIDER_LABEL[credential.provider]}
            </span>
          </KeyValue>
          <KeyValue label="Endpoint">
            {credential.base_url ? (
              <span className="break-all font-mono text-xs text-gray-300">
                {credential.base_url}
              </span>
            ) : (
              <span className="text-xs text-gray-500">Provider default</span>
            )}
          </KeyValue>
          <KeyValue label="Model">
            {credential.model ? (
              <span className="font-mono text-xs text-gray-300">
                {credential.model}
              </span>
            ) : (
              <span className="text-xs text-gray-500">Provider default</span>
            )}
          </KeyValue>
          <KeyValue label="API key">
            <span
              className={clsx(
                'inline-flex items-center gap-1.5 text-xs',
                credential.has_api_key ? 'text-emerald-300' : 'text-gray-400',
              )}
            >
              <span
                aria-hidden
                className={clsx(
                  'inline-block h-1.5 w-1.5 rounded-full',
                  credential.has_api_key ? 'bg-emerald-400' : 'bg-gray-600',
                )}
              />
              {credential.has_api_key ? 'Set (vault-encrypted)' : 'Not set'}
            </span>
          </KeyValue>
          <KeyValue label="Last rotated">
            {credential.last_rotated_at ? (
              <span
                className="text-xs text-gray-300"
                title={credential.last_rotated_at}
              >
                {formatDistanceToNow(new Date(credential.last_rotated_at), {
                  addSuffix: true,
                })}
              </span>
            ) : (
              <span className="text-xs text-gray-500">Never</span>
            )}
          </KeyValue>
          <KeyValue label="Updated">
            <span
              className="text-xs text-gray-300"
              title={credential.updated_at}
            >
              {formatDistanceToNow(new Date(credential.updated_at), {
                addSuffix: true,
              })}
            </span>
          </KeyValue>
        </dl>
        {confirmingDelete ? (
          <p className="mt-4 text-xs text-amber-300/80">
            Click <span className="font-semibold">Confirm remove</span> again
            to delete this credential. The platform will fall back to the
            pod-level LLM defaults.
            <button
              type="button"
              onClick={() => setConfirmingDelete(false)}
              className="ml-2 underline hover:text-amber-200"
            >
              Cancel
            </button>
          </p>
        ) : null}
      </section>
    );
  }

  // ── EMPTY: no credential, not editing ────────────────────────────────────
  if (!credential && !editing) {
    return (
      <section className="rounded-lg border border-gray-800 bg-gray-950/40 p-5">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-gray-200">
              Bring-your-own-LLM (BYOK)
            </h3>
            <p className="mt-1 text-xs text-gray-500">
              No tenant override configured. Investigations use the pod-level
              defaults shown above. Configure BYOK to point this tenant at
              your own provider — keys are stored vault-encrypted.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setEditing(true)}
            className="shrink-0 rounded-md border border-blue-500/50 bg-blue-500/15 px-3 py-1.5 text-xs font-medium text-blue-200 hover:bg-blue-500/25"
          >
            Configure BYOK
          </button>
        </div>
      </section>
    );
  }

  // ── EDIT: form (creating or editing) ─────────────────────────────────────
  return (
    <section className="rounded-lg border border-blue-500/30 bg-blue-500/5 p-5">
      <header className="mb-4">
        <h3 className="text-sm font-semibold text-gray-200">
          {credential ? 'Edit BYOK credential' : 'Configure BYOK credential'}
        </h3>
        <p className="mt-1 text-xs text-gray-500">
          API keys are encrypted with the platform credential vault before
          persistence and are never returned to the UI.
        </p>
      </header>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Field label="Provider">
          <select
            value={provider}
            onChange={e => setProvider(e.target.value as LlmWritableProvider)}
            disabled={submitting}
            className={inputClass()}
          >
            {WRITABLE_PROVIDERS.map(p => (
              <option key={p} value={p}>
                {PROVIDER_LABEL[p]}
              </option>
            ))}
          </select>
        </Field>
        <Field
          label="Model"
          hint="Provider-specific identifier (e.g. 'gpt-4o-mini', 'llama3.1:8b'). Leave blank for provider default."
        >
          <input
            type="text"
            value={model}
            onChange={e => setModel(e.target.value)}
            placeholder="provider default"
            disabled={submitting}
            className={inputClass()}
          />
        </Field>
        <Field
          label={`Base URL${requiresBaseUrl ? ' *' : ''}`}
          hint={
            requiresBaseUrl
              ? `Required. ${providerHint.baseUrlHint}`
              : providerHint.baseUrlHint
              ? `Optional override. ${providerHint.baseUrlHint}`
              : 'Optional override. Leave blank to use the provider default.'
          }
        >
          <input
            type="url"
            value={baseUrl}
            onChange={e => setBaseUrl(e.target.value)}
            placeholder={providerHint.baseUrlPlaceholder}
            disabled={submitting}
            className={inputClass()}
          />
        </Field>
        <Field
          label={`API key${requiresApiKey && !hasExistingKey ? ' *' : ''}`}
          hint={
            hasExistingKey
              ? 'A key is already stored. Leave blank to keep it; type a new value to rotate.'
              : requiresApiKey
              ? 'Required for hosted SaaS providers. Vault-encrypted before storage.'
              : 'Optional — most local providers do not require auth.'
          }
        >
          <input
            type="password"
            autoComplete="new-password"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            placeholder={
              hasExistingKey ? '•••••••• (unchanged)' : 'paste your API key'
            }
            disabled={submitting}
            className={inputClass()}
          />
        </Field>
      </div>
      <div className="mt-4">
        <Toggle
          checked={enabled}
          onChange={setEnabled}
          label="Use this credential"
          description="When disabled, the platform falls back to the pod-level defaults shown above without deleting your saved settings."
        />
      </div>
      {formError ? (
        <p className="mt-4 rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-200">
          {formError}
        </p>
      ) : null}
      <footer className="mt-5 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
        <button
          type="button"
          onClick={onCancel}
          disabled={submitting}
          className="rounded-md border border-gray-700 bg-gray-900 px-4 py-2 text-sm font-medium text-gray-200 hover:bg-gray-800 disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onSave}
          disabled={submitting}
          className="rounded-md bg-blue-500/80 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
        >
          {submitting
            ? 'Saving…'
            : credential
            ? 'Save changes'
            : 'Save credential'}
        </button>
      </footer>
    </section>
  );
}

function KeyValue({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1">
      <dt className="text-[11px] uppercase tracking-wide text-gray-500">
        {label}
      </dt>
      <dd className="text-sm text-gray-200">{children}</dd>
    </div>
  );
}

function StatusPill({
  tone,
  label,
}: {
  tone: 'emerald' | 'amber' | 'red' | 'gray';
  label: string;
}) {
  const cls = clsx(
    'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium',
    tone === 'emerald' && 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200',
    tone === 'amber' && 'border-amber-500/40 bg-amber-500/10 text-amber-200',
    tone === 'red' && 'border-red-500/40 bg-red-500/10 text-red-200',
    tone === 'gray' && 'border-gray-700 bg-gray-900 text-gray-300',
  );
  const dotCls = clsx(
    'inline-block h-1.5 w-1.5 rounded-full',
    tone === 'emerald' && 'bg-emerald-400',
    tone === 'amber' && 'bg-amber-400',
    tone === 'red' && 'bg-red-400',
    tone === 'gray' && 'bg-gray-500',
  );
  return (
    <span className={cls}>
      <span aria-hidden className={dotCls} />
      {label}
    </span>
  );
}

// ─── Panel: Audit ─────────────────────────────────────────────────────────────

function AuditPanel() {
  return (
    <div>
      <PanelHeader
        title="Audit log"
        description="Recent administrative events. Full searchable audit history is available via the API."
      />
      <ol className="divide-y divide-gray-800">
        {DEMO_AUDIT.map((a) => (
          <li key={a.id} className="flex items-start gap-3 px-6 py-4">
            <span
              aria-hidden
              className={clsx(
                'mt-1 inline-block h-2 w-2 shrink-0 rounded-full',
                a.action === 'failed-sync'
                  ? 'bg-red-400'
                  : a.action === 'rotated'
                  ? 'bg-amber-400'
                  : 'bg-emerald-400',
              )}
            />
            <div className="min-w-0 flex-1">
              <p className="text-sm text-gray-100">
                <span className="font-medium">{a.actor}</span>{' '}
                <span className="text-gray-400">{a.action}</span>{' '}
                <span>{a.target}</span>
              </p>
              <p className="text-xs text-gray-500" suppressHydrationWarning>
                {formatDistanceToNow(new Date(a.at), { addSuffix: true })}
              </p>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

// ─── Panel: About ─────────────────────────────────────────────────────────────

function AboutPanel() {
  return (
    <div>
      <PanelHeader
        title="About AiSOC"
        description="Open-source SOC platform — community-built, MIT licensed."
      />
      <div className="grid gap-4 px-6 py-5 sm:grid-cols-2">
        <InfoTile label="Version" value="v6.0.1" />
        <InfoTile label="Build" value="local • dev" />
        <InfoTile label="License" value="MIT" />
        <InfoTile label="Source" value="github.com/beenuar/AiSOC" mono />
      </div>
      <div className="border-t border-gray-800 px-6 py-5 text-sm text-gray-400">
        <p>
          AiSOC is community-driven. Issues, ideas, and PRs welcome on GitHub.
          See the{' '}
          <a
            className="text-blue-400 hover:text-blue-300"
            href="https://github.com/beenuar/AiSOC/blob/main/CONTRIBUTING.md"
            target="_blank"
            rel="noreferrer"
          >
            contributing guide
          </a>{' '}
          to get started.
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          <a
            className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs text-gray-200 hover:bg-gray-800"
            href="https://github.com/beenuar/AiSOC"
            target="_blank"
            rel="noreferrer"
          >
            GitHub →
          </a>
          <a
            className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs text-gray-200 hover:bg-gray-800"
            href="https://github.com/beenuar/AiSOC/blob/main/CHANGELOG.md"
            target="_blank"
            rel="noreferrer"
          >
            Changelog →
          </a>
          <a
            className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs text-gray-200 hover:bg-gray-800"
            href="https://github.com/beenuar/AiSOC/blob/main/SECURITY.md"
            target="_blank"
            rel="noreferrer"
          >
            Report a vulnerability →
          </a>
        </div>
      </div>
    </div>
  );
}
