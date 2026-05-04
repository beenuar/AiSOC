'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { clsx } from 'clsx';
import { isAuthenticated, getProfile, clearSession } from '@/lib/responder/auth';
import {
  registerServiceWorker,
  subscribeToPush,
  unsubscribeFromPush,
} from '@/lib/pwa';

interface NavItem {
  label: string;
  href: string;
  icon: React.ReactNode;
  match: (pathname: string) => boolean;
}

const TriageIcon = () => (
  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth={1.75}
      d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0"
    />
  </svg>
);

const CasesIcon = () => (
  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth={1.75}
      d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z"
    />
  </svg>
);

const ApprovalsIcon = () => (
  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth={1.75}
      d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
    />
  </svg>
);

const OnCallIcon = () => (
  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth={1.75}
      d="M2.25 6.75c0 8.284 6.716 15 15 15h2.25a2.25 2.25 0 002.25-2.25v-1.372c0-.516-.351-.966-.852-1.091l-4.423-1.106c-.44-.11-.902.055-1.173.417l-.97 1.293c-.282.376-.769.542-1.21.38a12.035 12.035 0 01-7.143-7.143c-.162-.441.004-.928.38-1.21l1.293-.97c.363-.271.527-.734.417-1.173L6.963 3.102a1.125 1.125 0 00-1.091-.852H4.5A2.25 2.25 0 002.25 4.5v2.25z"
    />
  </svg>
);

const SettingsIcon = () => (
  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth={1.75}
      d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.24-.438.613-.431.992a6.759 6.759 0 010 .255c-.007.378.138.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.02-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.99l-1.004-.828a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281z"
    />
    <path
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth={1.75}
      d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
    />
  </svg>
);

const NAV_ITEMS: NavItem[] = [
  {
    label: 'Triage',
    href: '/responder/triage',
    icon: <TriageIcon />,
    match: (p) => p.startsWith('/responder/triage'),
  },
  {
    label: 'Cases',
    href: '/responder/case',
    icon: <CasesIcon />,
    match: (p) => p.startsWith('/responder/case'),
  },
  {
    label: 'Approvals',
    href: '/responder/approvals',
    icon: <ApprovalsIcon />,
    match: (p) => p.startsWith('/responder/approvals'),
  },
  {
    label: 'On-call',
    href: '/responder/oncall',
    icon: <OnCallIcon />,
    match: (p) => p.startsWith('/responder/oncall'),
  },
  {
    label: 'Settings',
    href: '/responder/settings',
    icon: <SettingsIcon />,
    match: (p) => p.startsWith('/responder/settings'),
  },
];

const PUBLIC_ROUTES = ['/responder/login'];

export function ResponderShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname() ?? '/responder/triage';
  const router = useRouter();
  const [authReady, setAuthReady] = useState(false);
  const [authed, setAuthed] = useState(false);
  const [profileName, setProfileName] = useState<string | null>(null);

  const isPublicRoute = PUBLIC_ROUTES.some((p) => pathname.startsWith(p));

  useEffect(() => {
    const ok = isAuthenticated();
    setAuthed(ok);
    const profile = getProfile();
    setProfileName(profile?.name ?? profile?.email ?? null);
    setAuthReady(true);

    if (!ok && !isPublicRoute) {
      const next = encodeURIComponent(pathname);
      router.replace(`/responder/login?next=${next}`);
    }
  }, [pathname, isPublicRoute, router]);

  // Listen for storage events so a passkey login in another tab updates the
  // shell immediately without a hard refresh.
  useEffect(() => {
    const handler = () => {
      setAuthed(isAuthenticated());
      const profile = getProfile();
      setProfileName(profile?.name ?? profile?.email ?? null);
    };
    window.addEventListener('storage', handler);
    return () => window.removeEventListener('storage', handler);
  }, []);

  // Register the SW once we have an authenticated responder. This is silent
  // (no permission prompt) — the actual push subscription requires a user
  // gesture and is handled from /responder/settings.
  //
  // If the browser already granted notification permission on a prior visit,
  // we re-bind the existing subscription to the responder's tenant via the
  // gateway — that handles the case where a user signs in on a fresh tab and
  // the SW survived from before.
  useEffect(() => {
    if (!authed) return;
    let cancelled = false;
    (async () => {
      const reg = await registerServiceWorker();
      if (cancelled || !reg) return;
      if (
        typeof Notification !== 'undefined' &&
        Notification.permission === 'granted'
      ) {
        try {
          await subscribeToPush();
        } catch {
          // Best-effort. Settings page surfaces the failure if the user
          // tries to enable push from there.
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [authed]);

  const handleSignOut = () => {
    // Tear down the push subscription before we drop the JWT so the gateway
    // can authorise the unsubscribe call. We don't await it on the happy
    // path — sign-out should feel instant — and any failure is benign
    // (the push key is also auto-rotated server-side on token revocation).
    void unsubscribeFromPush().catch(() => undefined);
    clearSession();
    setAuthed(false);
    setProfileName(null);
    router.replace('/responder/login');
  };

  // Render login (and other public) routes without the chrome.
  if (isPublicRoute) {
    return (
      <div className="min-h-screen bg-zinc-950 text-zinc-100 antialiased">
        {children}
      </div>
    );
  }

  // Avoid flashing protected content while we resolve auth state.
  if (!authReady || !authed) {
    return (
      <div className="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center">
        <div className="text-sm text-zinc-500">Loading…</div>
      </div>
    );
  }

  return (
    <div className="min-h-[100dvh] bg-zinc-950 text-zinc-100 antialiased flex flex-col">
      {/* Top bar: identity + sign out. Stays compact for portrait phones. */}
      <header className="sticky top-0 z-30 bg-zinc-950/95 backdrop-blur border-b border-zinc-900 supports-[padding:max(0px)]:pt-[max(0px,env(safe-area-inset-top))]">
        <div className="flex items-center justify-between px-4 h-14">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center">
              <svg
                className="w-5 h-5 text-white"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.75}
                  d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
                />
              </svg>
            </div>
            <div className="leading-tight">
              <div className="text-sm font-semibold">AiSOC Responder</div>
              {profileName ? (
                <div className="text-[10px] uppercase tracking-wider text-zinc-500 truncate max-w-[140px]">
                  {profileName}
                </div>
              ) : null}
            </div>
          </div>
          <button
            type="button"
            onClick={handleSignOut}
            className="text-xs text-zinc-400 hover:text-zinc-200 px-2 py-1.5 rounded-md border border-zinc-800 hover:border-zinc-700 transition"
          >
            Sign out
          </button>
        </div>
      </header>

      {/* Main scroll area */}
      <main className="flex-1 overflow-y-auto pb-[calc(4.5rem+env(safe-area-inset-bottom))]">
        {children}
      </main>

      {/* Bottom nav: thumb-reachable on portrait phones. */}
      <nav className="fixed bottom-0 inset-x-0 z-30 bg-zinc-950/95 backdrop-blur border-t border-zinc-900 supports-[padding:max(0px)]:pb-[max(0px,env(safe-area-inset-bottom))]">
        <ul className="grid grid-cols-5 h-16">
          {NAV_ITEMS.map((item) => {
            const active = item.match(pathname);
            return (
              <li key={item.href} className="flex">
                <Link
                  href={item.href}
                  className={clsx(
                    'flex-1 flex flex-col items-center justify-center gap-0.5 text-[10px] uppercase tracking-wider transition',
                    active
                      ? 'text-indigo-400'
                      : 'text-zinc-500 hover:text-zinc-300',
                  )}
                  aria-current={active ? 'page' : undefined}
                >
                  <span
                    className={clsx(
                      'transition',
                      active ? 'scale-105' : 'scale-100',
                    )}
                  >
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
    </div>
  );
}
