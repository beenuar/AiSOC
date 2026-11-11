import { useEffect, useState, type ReactNode } from 'react';
import { SearchParamsContext } from 'next/dist/shared/lib/hooks-client-context.shared-runtime';

/**
 * Supply the real useSearchParams hook with URL changes in component tests.
 * jsdom has browser history, but does not run Next's App Router, which normally
 * updates this context after pushState/replaceState/popstate. Journey tests
 * cover that integration in the real router without this provider.
 */
export function NavigationTestProvider({ children }: { children: ReactNode }) {
  const [params, setParams] = useState(() => new URLSearchParams(window.location.search));

  useEffect(() => {
    const pushState = window.history.pushState;
    const replaceState = window.history.replaceState;
    const sync = () => setParams(new URLSearchParams(window.location.search));

    window.history.pushState = (...args) => {
      pushState.apply(window.history, args);
      sync();
    };
    window.history.replaceState = (...args) => {
      replaceState.apply(window.history, args);
      sync();
    };
    window.addEventListener('popstate', sync);

    return () => {
      window.history.pushState = pushState;
      window.history.replaceState = replaceState;
      window.removeEventListener('popstate', sync);
    };
  }, []);

  return <SearchParamsContext.Provider value={params}>{children}</SearchParamsContext.Provider>;
}
