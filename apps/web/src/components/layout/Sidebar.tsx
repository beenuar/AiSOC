'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { clsx } from 'clsx';
import packageJson from '../../../package.json';

const APP_VERSION = packageJson.version;

interface NavItem {
  label: string;
  href: string;
  icon: React.ReactNode;
  badge?: number;
  badgeColor?: string;
}

interface NavSection {
  title?: string;
  items: NavItem[];
}

const ShieldIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
  </svg>
);

const BellIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
  </svg>
);

const FolderIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
  </svg>
);

const EyeIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
  </svg>
);

const PuzzleIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M14.25 6.087c0-.355.186-.676.401-.959.221-.29.349-.634.349-1.003 0-1.036-1.007-1.875-2.25-1.875s-2.25.84-2.25 1.875c0 .369.128.713.349 1.003.215.283.401.604.401.959v0a.64.64 0 01-.657.643 48.39 48.39 0 01-4.163-.3c.186 1.613.293 3.25.315 4.907a.656.656 0 01-.658.663v0c-.355 0-.676-.186-.959-.401a1.647 1.647 0 00-1.003-.349c-1.036 0-1.875 1.007-1.875 2.25s.84 2.25 1.875 2.25c.369 0 .713-.128 1.003-.349.283-.215.604-.401.959-.401v0c.31 0 .555.26.532.57a48.039 48.039 0 01-.642 5.056c1.518.19 3.058.309 4.616.354a.64.64 0 00.657-.643v0c0-.355-.186-.676-.401-.959a1.647 1.647 0 01-.349-1.003c0-1.035 1.008-1.875 2.25-1.875 1.243 0 2.25.84 2.25 1.875 0 .369-.128.713-.349 1.003-.215.283-.4.604-.4.959v0c0 .333.277.599.61.58a48.1 48.1 0 005.427-.63 48.05 48.05 0 00.582-4.717.532.532 0 00-.533-.57v0c-.355 0-.676.186-.959.401-.29.221-.634.349-1.003.349-1.035 0-1.875-1.007-1.875-2.25s.84-2.25 1.875-2.25c.37 0 .713.128 1.003.349.283.215.604.401.959.401v0a.656.656 0 00.658-.663 48.422 48.422 0 00-.37-5.36c-1.886.342-3.81.574-5.766.689a.578.578 0 01-.61-.58v0z" />
  </svg>
);

const GlobeIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
  </svg>
);

const CogIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.24-.438.613-.431.992a6.759 6.759 0 010 .255c-.007.378.138.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.02-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.99l-1.004-.828a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281z" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
  </svg>
);

const ChartBarIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
  </svg>
);

const SearchIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
  </svg>
);

const GraphIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <circle cx="6" cy="6" r="2" strokeWidth={1.5} />
    <circle cx="18" cy="6" r="2" strokeWidth={1.5} />
    <circle cx="12" cy="18" r="2" strokeWidth={1.5} />
    <path strokeWidth={1.5} strokeLinecap="round" d="M7.5 7.5L11 16.5M16.5 7.5L13 16.5M8 6h8" />
  </svg>
);

const PlaybookIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
  </svg>
);

const SparklesIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.847.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 00-2.456 2.456zM16.894 20.567L16.5 21.75l-.394-1.183a2.25 2.25 0 00-1.423-1.423L13.5 18.75l1.183-.394a2.25 2.25 0 001.423-1.423l.394-1.183.394 1.183a2.25 2.25 0 001.423 1.423l1.183.394-1.183.394a2.25 2.25 0 00-1.423 1.423z" />
  </svg>
);

const ClockIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const ScanIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7.5 3.75H6A2.25 2.25 0 003.75 6v1.5M16.5 3.75H18A2.25 2.25 0 0120.25 6v1.5m0 9V18A2.25 2.25 0 0118 20.25h-1.5m-9 0H6A2.25 2.25 0 013.75 18v-1.5M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
  </svg>
);

const MarketplaceIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.5 21v-7.5a.75.75 0 01.75-.75h3a.75.75 0 01.75.75V21m-4.5 0H2.36m11.14 0H18m0 0h3.64m-1.39 0V9.349m-16.5 11.65V9.35m0 0a3.001 3.001 0 003.75-.615A2.993 2.993 0 009.75 9.75c.896 0 1.7-.393 2.25-1.016a2.993 2.993 0 002.25 1.016c.896 0 1.7-.393 2.25-1.016a3.001 3.001 0 003.75.614m-16.5 0a3.004 3.004 0 01-.621-4.72L4.318 3.44A1.5 1.5 0 015.378 3h13.243a1.5 1.5 0 011.06.44l1.19 1.189a3 3 0 01-.621 4.72m-13.5 8.65h3.75a.75.75 0 00.75-.75V13.5a.75.75 0 00-.75-.75H6.75a.75.75 0 00-.75.75v3.75c0 .415.336.75.75.75z" />
  </svg>
);

const DocumentReportIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 17.25v-3.75M12 17.25V9.75M15 17.25v-1.5M19.5 19.5h-15A2.25 2.25 0 012.25 17.25V6.75A2.25 2.25 0 014.5 4.5h15a2.25 2.25 0 012.25 2.25v10.5a2.25 2.25 0 01-2.25 2.25z" />
  </svg>
);

const CurrencyIcon = () => (
  <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 6v12m-3-2.818l.879.659c1.171.879 3.07.879 4.242 0 1.172-.879 1.172-2.303 0-3.182C13.536 12.219 12.768 12 12 12c-.725 0-1.45-.22-2.003-.659-1.106-.879-1.106-2.303 0-3.182s2.9-.879 4.006 0l.415.33M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const navSections: NavSection[] = [
  {
    items: [
      {
        label: 'Dashboard',
        href: '/dashboard',
        icon: <ChartBarIcon />,
      },
    ],
  },
  {
    title: 'Threat Operations',
    items: [
      {
        label: 'Alerts',
        href: '/alerts',
        icon: <BellIcon />,
        badge: 0,
        badgeColor: 'bg-red-500',
      },
      {
        label: 'Cases',
        href: '/cases',
        icon: <FolderIcon />,
      },
      {
        label: 'Hunt',
        href: '/hunt',
        icon: <SearchIcon />,
      },
      {
        label: 'Detection Rules',
        href: '/detection',
        icon: <EyeIcon />,
      },
      {
        label: 'Detection Catalog',
        href: '/detection/catalog',
        icon: <SearchIcon />,
      },
      {
        label: 'MITRE Coverage',
        href: '/detection/coverage',
        icon: <ChartBarIcon />,
      },
      {
        label: 'Shifts',
        href: '/shifts',
        icon: <ClockIcon />,
      },
    ],
  },
  {
    title: 'Intelligence',
    items: [
      {
        label: 'Threat Intel',
        href: '/threat-intel',
        icon: <GlobeIcon />,
      },
      {
        label: 'Attack Graph',
        href: '/graph',
        icon: <GraphIcon />,
      },
      {
        label: 'AI Copilot',
        href: '/copilot',
        icon: <SparklesIcon />,
      },
      {
        label: 'Investigation Chat',
        href: '/investigate',
        icon: <SparklesIcon />,
      },
      {
        label: 'Coverage Advisor',
        href: '/coverage-advisor',
        icon: <ShieldIcon />,
      },
      {
        label: 'EASM',
        href: '/easm',
        icon: <ScanIcon />,
      },
    ],
  },
  {
    title: 'Automation',
    items: [
      {
        label: 'Playbooks',
        href: '/playbooks',
        icon: <PlaybookIcon />,
      },
      {
        label: 'Marketplace',
        href: '/marketplace',
        icon: <MarketplaceIcon />,
      },
      {
        label: 'Honeytokens',
        href: '/honeytokens',
        icon: <EyeIcon />,
      },
      {
        label: 'Purple Team',
        href: '/purple-team',
        icon: <ShieldIcon />,
      },
    ],
  },
  {
    title: 'Platform',
    items: [
      {
        label: 'Get started',
        href: '/onboarding',
        icon: <SparklesIcon />,
      },
      {
        label: 'Connectors',
        href: '/connectors',
        icon: <PuzzleIcon />,
      },
      {
        label: 'Roles & Permissions',
        href: '/settings/rbac',
        icon: <ShieldIcon />,
      },
      {
        label: 'Compliance',
        href: '/compliance',
        icon: <ShieldIcon />,
      },
      {
        label: 'Noise Tuning',
        href: '/noise-tuning',
        icon: <ChartBarIcon />,
      },
      {
        label: 'MSSP Dashboard',
        href: '/mssp',
        icon: <GlobeIcon />,
      },
      {
        label: 'Team Analytics',
        href: '/analytics/team',
        icon: <ChartBarIcon />,
      },
      {
        label: 'SLA Tracking',
        href: '/sla',
        icon: <ChartBarIcon />,
      },
      {
        label: 'Executive Digest',
        href: '/reports/digest',
        icon: <DocumentReportIcon />,
      },
      {
        label: 'Cost Dashboard',
        href: '/costs',
        icon: <CurrencyIcon />,
      },
      {
        label: 'Audit Log',
        href: '/audit',
        icon: <EyeIcon />,
      },
      {
        label: 'Settings',
        href: '/settings',
        icon: <CogIcon />,
      },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  const isActive = (href: string) => {
    if (href === '/dashboard') return pathname === '/dashboard';
    return pathname.startsWith(href);
  };

  return (
    <>
      {/* Mobile hamburger */}
      <button
        type="button"
        aria-label="Open navigation"
        onClick={() => setMobileOpen(true)}
        className="md:hidden fixed top-4 left-4 z-40 p-2 rounded-lg bg-surface-card/90 text-fg-secondary hover:text-fg-primary"
      >
        <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
        </svg>
      </button>

      {/* Backdrop */}
      {mobileOpen && (
        <div
          className="md:hidden fixed inset-0 z-30 bg-black/60"
          onClick={() => setMobileOpen(false)}
        />
      )}

    <aside
      aria-label="Application sidebar"
      className={clsx(
        'fixed inset-y-0 left-0 w-60 flex flex-col bg-surface-raised/95 border-r border-surface-border z-40 transition-transform duration-200',
        mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 h-16 border-b border-surface-border">
        <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-brand-600/20 border border-brand-600/30 flex items-center justify-center">
          <span className="text-brand-400">
            <ShieldIcon />
          </span>
        </div>
        <div>
          <span className="text-fg-primary font-bold text-base tracking-tight">Ai</span>
          <span className="text-brand-400 font-bold text-base tracking-tight">SOC</span>
          <p className="text-xs text-fg-subtle -mt-0.5">open-source</p>
        </div>
        {/* Live indicator — decorative, status conveyed by the green dot label */}
          <div className="ml-auto flex items-center gap-1" aria-hidden="true">
            <div className="w-1.5 h-1.5 rounded-full bg-green-400 pulse-dot" />
            <span className="text-xs text-fg-subtle">Live</span>
          </div>
      </div>

      {/* Nav */}
      <nav aria-label="Main navigation" className="flex-1 overflow-y-auto py-4 px-3 space-y-5">
        {navSections.map((section, si) => (
          <div key={si}>
            {section.title && (
              <p className="px-3 mb-1.5 text-xs font-semibold text-fg-subtle uppercase tracking-wider">
                {section.title}
              </p>
            )}
            <ul className="space-y-0.5">
              {section.items.map((item) => {
                const active = isActive(item.href);
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      onClick={() => setMobileOpen(false)}
                      className={clsx(
                        'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-150',
                        active
                          ? 'bg-brand-600/15 text-brand-300 border border-brand-600/20'
                          : 'text-fg-muted hover:text-fg-secondary hover:bg-surface-hover'
                      )}
                    >
                      <span className={active ? 'text-brand-400' : 'text-fg-subtle'}>{item.icon}</span>
                      <span>{item.label}</span>
                      {typeof item.badge === 'number' && item.badge > 0 && (
                        <span
                          className={`ml-auto text-xs font-bold px-1.5 py-0.5 rounded-full text-white ${item.badgeColor ?? 'bg-gray-600'}`}
                        >
                          {item.badge > 99 ? '99+' : item.badge}
                        </span>
                      )}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-surface-border">
        <div className="flex items-center gap-2 text-xs text-fg-subtle">
          <span className="font-mono">v{APP_VERSION}</span>
          <span>·</span>
          <a
            href="https://github.com/beenuar/AiSOC"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-fg-muted transition-colors"
          >
            MIT License
          </a>
        </div>
      </div>
    </aside>
    </>
  );
}
