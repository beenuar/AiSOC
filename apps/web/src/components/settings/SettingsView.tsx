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
import { connectorsApi, type Connector, type ConnectorStatus } from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorState } from '@/components/ui/ErrorState';
import { EmptyState } from '@/components/ui/EmptyState';

// ─── Types ────────────────────────────────────────────────────────────────────

type TabId =
  | 'profile'
  | 'workspace'
  | 'integrations'
  | 'api-keys'
  | 'notifications'
  | 'appearance'
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
  email: 'sasha.lin@cyble.com',
  title: 'Senior SOC Analyst',
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
};

// ─── Demo fallbacks ───────────────────────────────────────────────────────────

const NOW = Date.now();
const ago = (mins: number) => new Date(NOW - mins * 60 * 1000).toISOString();

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
    actor: 'sasha.lin@cyble.com',
    action: 'enabled',
    target: 'Detection rule “Impossible Travel — Same User”',
    at: ago(12),
  },
  {
    id: 'a-2',
    actor: 'admin@cyble.com',
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
    actor: 'sasha.lin@cyble.com',
    action: 'invited',
    target: 'avi.sharma@cyble.com (analyst)',
    at: ago(60 * 24 * 1),
  },
  {
    id: 'a-5',
    actor: 'admin@cyble.com',
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

const TABS: { id: TabId; label: string; description: string; icon: string }[] = [
  {
    id: 'profile',
    label: 'Profile',
    description: 'Identity and personal display preferences.',
    icon: '👤',
  },
  {
    id: 'workspace',
    label: 'Workspace',
    description: 'Tenant, branding, locale.',
    icon: '🏢',
  },
  {
    id: 'integrations',
    label: 'Integrations',
    description: 'Connected log sources, EDRs, identity providers.',
    icon: '🔌',
  },
  {
    id: 'api-keys',
    label: 'API keys',
    description: 'Programmatic access for pipelines and integrations.',
    icon: '🔑',
  },
  {
    id: 'notifications',
    label: 'Notifications',
    description: 'How and when AiSOC should ping you.',
    icon: '🔔',
  },
  {
    id: 'appearance',
    label: 'Appearance',
    description: 'Theme, density, animations.',
    icon: '🎨',
  },
  {
    id: 'audit',
    label: 'Audit log',
    description: 'Recent administrative events.',
    icon: '📜',
  },
  {
    id: 'about',
    label: 'About',
    description: 'Version, license, links.',
    icon: 'ℹ️',
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
                      'flex w-full items-start gap-3 rounded-lg px-3 py-2.5 text-left text-sm transition-colors',
                      active
                        ? 'bg-gray-800/80 text-gray-50 ring-1 ring-blue-500/40'
                        : 'text-gray-300 hover:bg-gray-800/50 hover:text-gray-100',
                    )}
                  >
                    <span aria-hidden className="text-base leading-5">
                      {t.icon}
                    </span>
                    <span className="flex flex-col">
                      <span className="font-medium">{t.label}</span>
                      <span className="text-xs text-gray-500">
                        {t.description}
                      </span>
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
              {tab === 'api-keys' && <ApiKeysPanel />}
              {tab === 'notifications' && <NotificationsPanel />}
              {tab === 'appearance' && <AppearancePanel />}
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
            className="flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-blue-500 to-purple-600 text-xl font-semibold text-white shadow-lg ring-2 ring-gray-800"
          >
            {initials || '?'}
          </div>
          <div className="min-w-0">
            <p className="truncate text-base font-semibold text-gray-100">
              {profile.displayName || 'Unnamed user'}
            </p>
            <p className="truncate text-sm text-gray-400">{profile.email}</p>
            <p className="mt-1 text-xs text-gray-500">
              Avatar generated from initials. Custom avatars coming soon.
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
          Profile preferences are stored locally for this demo build. In
          production they sync to the directory provider configured for your
          tenant.
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
        <InfoTile label="Workspace name" value="Cyble — AiSOC Demo" />
        <InfoTile label="Tenant ID" value="tenant_demo_01H0XE4T2WJ9N6" mono />
        <InfoTile label="Plan" value="Open-source (MIT)" />
        <InfoTile label="Region" value="us-east-1 / Multi-AZ" />
        <InfoTile label="Created" value={format(NOW - 1000 * 60 * 60 * 24 * 96, 'PPP')} />
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
            { name: 'Sasha Lin', email: 'sasha.lin@cyble.com', role: 'Admin' },
            { name: 'Avi Sharma', email: 'avi.sharma@cyble.com', role: 'Analyst' },
            { name: 'Diego Vega', email: 'diego.vega@cyble.com', role: 'Analyst' },
            { name: 'Mia Ocampo', email: 'mia.ocampo@cyble.com', role: 'Hunter' },
            { name: 'CI Service', email: 'ci@cyble.com', role: 'Service' },
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
        await connectorsApi.update(connector.id, { enabled: next });
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
                        <span>
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
    const id = `key-${Math.random().toString(36).slice(2, 8)}`;
    const secretBody = Math.random().toString(36).slice(2, 14);
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
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {format(new Date(k.createdAt), 'PPP')}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">
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
            AiSOC ships dark-first; light mode coming soon.
          </p>
          <div className="mt-3 grid grid-cols-3 gap-3">
            {(['system', 'dark', 'light'] as const).map((t) => {
              const active = prefs.theme === t;
              const disabled = t === 'light';
              return (
                <button
                  key={t}
                  type="button"
                  disabled={disabled}
                  onClick={() => update('theme', t)}
                  className={clsx(
                    'rounded-xl border p-3 text-left transition-colors',
                    active
                      ? 'border-blue-500/60 bg-blue-500/10'
                      : 'border-gray-800 bg-gray-950/40 hover:border-gray-700',
                    disabled && 'cursor-not-allowed opacity-40',
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
                      : 'Coming soon'}
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
              <p className="text-xs text-gray-500">
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
        description="Open-source SOC platform — by Cyble, MIT licensed."
      />
      <div className="grid gap-4 px-6 py-5 sm:grid-cols-2">
        <InfoTile label="Version" value="v3.0.0-rc.1" />
        <InfoTile label="Build" value="local • dev" />
        <InfoTile label="License" value="MIT" />
        <InfoTile label="Source" value="github.com/cybeio/aisoc" mono />
      </div>
      <div className="border-t border-gray-800 px-6 py-5 text-sm text-gray-400">
        <p>
          AiSOC is community-driven. Issues, ideas, and PRs welcome on GitHub.
          For commercial deployment support, see{' '}
          <a
            className="text-blue-400 hover:text-blue-300"
            href="https://cyble.com"
            target="_blank"
            rel="noreferrer"
          >
            cyble.com
          </a>
          .
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          <a
            className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs text-gray-200 hover:bg-gray-800"
            href="https://github.com/cybeio/aisoc"
            target="_blank"
            rel="noreferrer"
          >
            GitHub →
          </a>
          <a
            className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs text-gray-200 hover:bg-gray-800"
            href="https://github.com/cybeio/aisoc/blob/main/CHANGELOG.md"
            target="_blank"
            rel="noreferrer"
          >
            Changelog →
          </a>
          <a
            className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs text-gray-200 hover:bg-gray-800"
            href="https://github.com/cybeio/aisoc/blob/main/SECURITY.md"
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
