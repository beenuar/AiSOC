'use client';

import { useEffect, useState } from 'react';

/**
 * The one place the console asks what version it is.
 *
 * Two surfaces used to answer this differently. `Sidebar.tsx` imported
 * `package.json` and rendered `packageJson.version`; `SettingsView.tsx` read
 * `process.env.NEXT_PUBLIC_APP_VERSION || '0.0.0'`. Both are frozen when the
 * bundle is compiled, by two separate mechanisms, so one image could show two
 * numbers — and `'0.0.0'` is a version-shaped stand-in for a missing value,
 * which is the same defect as the API reporting `0.1.0` for twenty-two
 * majors.
 *
 * `GET /api/runtime-config` is the route whose stated purpose is answering
 * "what does this deployment believe about itself", read per request. Both
 * surfaces now read it, so they cannot disagree.
 *
 * Deliberately not SWR: the version of a loaded bundle cannot change while
 * that bundle is running, so there is nothing to revalidate, and a shared
 * cache would make this hook's behaviour depend on what else had already
 * fetched. A single read per mount is the whole requirement.
 */

/** What an unanswerable version renders as. Never a number — see above. */
export const UNKNOWN_CONSOLE_VERSION = 'unknown';

export interface ConsoleVersion {
  /** The running version, or `null` while the answer is still in flight. */
  version: string | null;
  isLoading: boolean;
}

export function useConsoleVersion(): ConsoleVersion {
  const [version, setVersion] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let active = true;

    const read = async () => {
      let resolved = UNKNOWN_CONSOLE_VERSION;
      try {
        const response = await fetch('/api/runtime-config', { cache: 'no-store' });
        if (response.ok) {
          const body = (await response.json()) as { consoleVersion?: unknown };
          if (typeof body.consoleVersion === 'string' && body.consoleVersion.trim() !== '') {
            resolved = body.consoleVersion;
          }
        }
      } catch {
        // An unreachable route means the version is unknown. It does not mean
        // the version is zero, and it must not take the page down: this hook
        // renders a footer and an About tile.
      }
      if (!active) return;
      setVersion(resolved);
      setIsLoading(false);
    };

    void read();
    return () => {
      active = false;
    };
  }, []);

  return { version, isLoading };
}
