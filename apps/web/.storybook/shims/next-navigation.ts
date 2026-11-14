/**
 * Storybook shim for next/navigation. Storybook runs on Vite (not
 * Next), so the App Router hooks aren't available; we provide just
 * enough surface for components that call ``useRouter().push`` /
 * ``useRouter().replace`` etc.
 */

type RouterAction = (..._args: unknown[]) => void;

interface FakeRouter {
  push: RouterAction;
  replace: RouterAction;
  back: RouterAction;
  forward: RouterAction;
  refresh: RouterAction;
  prefetch: RouterAction;
}

const noop: RouterAction = () => undefined;

const fakeRouter: FakeRouter = {
  push: noop,
  replace: noop,
  back: noop,
  forward: noop,
  refresh: noop,
  prefetch: noop,
};

export function useRouter(): FakeRouter {
  return fakeRouter;
}

export function usePathname(): string {
  return '/';
}

export function useSearchParams(): URLSearchParams {
  return new URLSearchParams();
}

export function useParams(): Record<string, string> {
  return {};
}

export function redirect(_url: string): never {
  throw new Error(`redirect(${_url}) called in Storybook shim`);
}

export function notFound(): never {
  throw new Error('notFound() called in Storybook shim');
}
