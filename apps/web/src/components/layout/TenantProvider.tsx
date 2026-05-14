'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import {
  authApi,
  getActiveTenantId,
  msspApi,
  setActiveTenantId,
  tenantsApi,
  type AuthUser,
  type ChildTenant,
  type MyTenant,
} from '@/lib/api';

export interface TenantOption {
  /** Stable tenant UUID — matches the `X-Tenant-Id` header value. */
  id: string;
  /** Human-readable display name. */
  name: string;
  /** What kind of tenant this is (parent / child / standalone). */
  role: 'parent' | 'child' | 'standalone';
}

interface TenantContextValue {
  /** Tenant the active session is currently operating against. */
  current: TenantOption | null;
  /** Every tenant the operator can flip to (incl. `current`). */
  available: TenantOption[];
  /** The signed-in user's *org-level* role (analyst / responder / admin / …). */
  userRole: string | null;
  /** Switch the active tenant. Triggers an SWR-level cache invalidation upstream. */
  setTenant: (tenantId: string) => void;
  /** True while we're loading the tenant list (e.g. on first paint). */
  loading: boolean;
  /** Last error, if any — surfaced through the TopBar role badge tooltip. */
  error: string | null;
}

const TenantContext = createContext<TenantContextValue | null>(null);

function toOption(t: MyTenant | (ChildTenant & { domain?: string | null })): TenantOption {
  // Normalise the two API response shapes (MyTenant vs ChildTenant) into one
  // dropdown-friendly type. ChildTenant.mssp_role is always 'child' (by the
  // /mssp/children query filter) but we coerce defensively.
  const role: TenantOption['role'] =
    t.mssp_role === 'parent' || t.mssp_role === 'child'
      ? t.mssp_role
      : 'standalone';
  return { id: t.id, name: t.name, role };
}

/**
 * Tracks the active tenant + every tenant the user can flip to (W5).
 *
 * For a standalone tenant user, `available` is `[current]` and the
 * TenantSwitcher renders as a read-only RoleBadge. For an MSSP parent
 * operator, `available` lists `[parent, ...children]` and the switcher
 * actually opens.
 *
 * Switching writes the new tenant ID through `setActiveTenantId()` so the
 * shared `request()` helper picks it up on the *next* API call — callers
 * that need to refetch should listen for `window.dispatchEvent('aisoc:tenant-switched')`
 * and call SWR `mutate(() => true)`. Today we hard-reload the page (see
 * `setTenant()` below) which is the safest option given how many SWR keys
 * are tenant-scoped — a future iteration can wire that into a dedicated
 * SWR cache reset.
 */
export function TenantProvider({ children }: { children: ReactNode }) {
  const [current, setCurrent] = useState<TenantOption | null>(null);
  const [available, setAvailable] = useState<TenantOption[]>([]);
  const [userRole, setUserRole] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      // The user record is in localStorage (post-login) so we can populate
      // `userRole` and a fallback `current` synchronously without waiting on
      // the network. This avoids a flicker of "loading…" in the TopBar for
      // returning users.
      const user: AuthUser | null = authApi.currentUser();
      if (!cancelled) setUserRole(user?.role ?? null);

      // No bearer token → don't bother hitting protected endpoints; the
      // TopBar will simply render without the badge. This is the demo-page /
      // logged-out fallback.
      if (!authApi.isAuthenticated()) {
        if (!cancelled) {
          setLoading(false);
        }
        return;
      }

      try {
        // Fetch the canonical tenant record first; this is the only one we
        // truly need to render the badge. Children come second and any
        // failure there is non-fatal (e.g. /mssp/children 403 for a
        // tenant-level user).
        const me = await tenantsApi.me();
        if (cancelled) return;
        const meOption = toOption(me);

        // Carry the user's previously-selected tenant forward, but only if
        // it's still resolvable. Anything stale falls back to "me".
        const activeId = getActiveTenantId();
        let activeOption = meOption;

        let children: ChildTenant[] = [];
        if (me.mssp_role === 'parent') {
          try {
            children = await msspApi.listChildren();
          } catch {
            // Non-fatal: an MSSP parent without children is valid; a 403 here
            // just means the user lacks `mssp:read` and we render the badge
            // alone.
            children = [];
          }
        }
        if (cancelled) return;

        const childOptions = children.map(toOption);
        const list: TenantOption[] = [meOption, ...childOptions];
        if (activeId) {
          const match = list.find((t) => t.id === activeId);
          if (match) activeOption = match;
        }

        setAvailable(list);
        setCurrent(activeOption);
        setError(null);
      } catch (err) {
        if (cancelled) return;
        const message = err instanceof Error ? err.message : 'Failed to load tenant';
        setError(message);
        // We still want a usable badge — synthesise a `current` from the
        // cached auth user so the TopBar isn't blank.
        if (user) {
          const fallback: TenantOption = {
            id: user.tenant_id,
            name: 'My tenant',
            role: 'standalone',
          };
          setCurrent(fallback);
          setAvailable([fallback]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  const setTenant = useCallback((tenantId: string) => {
    setActiveTenantId(tenantId);
    // Find the new tenant inside our resolved list before navigating, so the
    // post-reload paint already has the right context.
    setCurrent((prev) => {
      const next = available.find((t) => t.id === tenantId);
      return next ?? prev;
    });
    if (typeof window !== 'undefined') {
      // Hard reload is intentionally conservative: every SWR cache key has
      // the old tenant scope baked in, and patching every consumer to
      // re-key on `current.id` is a future workstream. Reloading guarantees
      // a clean read.
      window.dispatchEvent(new CustomEvent('aisoc:tenant-switched', { detail: { tenantId } }));
      window.location.reload();
    }
  }, [available]);

  const value = useMemo<TenantContextValue>(
    () => ({ current, available, userRole, setTenant, loading, error }),
    [current, available, userRole, setTenant, loading, error],
  );

  return <TenantContext.Provider value={value}>{children}</TenantContext.Provider>;
}

export function useTenant(): TenantContextValue {
  const ctx = useContext(TenantContext);
  if (!ctx) {
    throw new Error('useTenant() must be used inside <TenantProvider>');
  }
  return ctx;
}
