'use client';

import { useEffect, useState, type ReactNode } from 'react';

interface ClientOnlyProps {
  children: ReactNode;
  fallback?: ReactNode;
}

/**
 * Renders children only after the component has mounted on the client.
 *
 * Use for subtrees that depend on browser-only values (localStorage, real-time
 * relative timestamps, window measurements). The server and the first client
 * paint both render `fallback`, so React hydration matches and we avoid
 * minified error #418/#421.
 */
export function ClientOnly({ children, fallback = null }: ClientOnlyProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
}
