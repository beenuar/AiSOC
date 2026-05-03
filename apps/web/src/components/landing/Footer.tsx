import Link from 'next/link';
import { Logo } from './Logo';

const COLUMNS = [
  {
    label: 'Platform',
    links: [
      { label: 'Features', href: '#features' },
      { label: 'How it works', href: '#architecture' },
      { label: 'MITRE coverage', href: '#mitre' },
      { label: 'Console', href: '/dashboard' },
    ],
  },
  {
    label: 'Open source',
    links: [
      { label: 'GitHub', href: 'https://github.com/beenuar/AiSOC' },
      { label: 'Quickstart', href: 'https://github.com/beenuar/AiSOC#quickstart' },
      { label: 'Roadmap', href: 'https://github.com/beenuar/AiSOC/blob/main/ROADMAP.md' },
      { label: 'Changelog', href: 'https://github.com/beenuar/AiSOC/blob/main/CHANGELOG.md' },
    ],
  },
  {
    label: 'Community',
    links: [
      { label: 'Issues', href: 'https://github.com/beenuar/AiSOC/issues' },
      { label: 'Discussions', href: 'https://github.com/beenuar/AiSOC/discussions' },
      { label: 'Contributing', href: 'https://github.com/beenuar/AiSOC/blob/main/CONTRIBUTING.md' },
      { label: 'Code of conduct', href: 'https://github.com/beenuar/AiSOC/blob/main/CODE_OF_CONDUCT.md' },
    ],
  },
  {
    label: 'Cyble',
    links: [
      { label: 'About Cyble', href: 'https://cyble.com' },
      { label: 'Security policy', href: 'https://github.com/beenuar/AiSOC/blob/main/SECURITY.md' },
      { label: 'License (MIT)', href: 'https://github.com/beenuar/AiSOC/blob/main/LICENSE' },
    ],
  },
];

export function Footer() {
  return (
    <footer className="relative border-t border-white/5 bg-surface-base">
      <div className="mx-auto max-w-7xl px-6 py-16">
        <div className="grid grid-cols-2 gap-10 md:grid-cols-6">
          <div className="col-span-2">
            <Logo size={36} withWordmark />
            <p className="mt-4 max-w-sm text-sm leading-relaxed text-gray-400">
              The open-source AI Security Operations Center. Maintained by Cyble. MIT licensed,
              forever.
            </p>
            <div className="mt-5 flex gap-3">
              <a
                href="https://github.com/beenuar/AiSOC"
                target="_blank"
                rel="noreferrer"
                aria-label="GitHub"
                className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-white/10 bg-white/[0.03] text-gray-300 transition hover:border-white/20 hover:text-white"
              >
                <svg viewBox="0 0 24 24" className="h-4 w-4" fill="currentColor" aria-hidden="true">
                  <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56 0-.28-.01-1.02-.02-2-3.2.69-3.88-1.54-3.88-1.54-.52-1.32-1.27-1.67-1.27-1.67-1.04-.71.08-.69.08-.69 1.15.08 1.76 1.18 1.76 1.18 1.02 1.75 2.68 1.24 3.34.95.1-.74.4-1.24.73-1.53-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.18-3.1-.12-.29-.51-1.46.11-3.05 0 0 .96-.31 3.15 1.18a10.9 10.9 0 015.74 0c2.19-1.49 3.15-1.18 3.15-1.18.62 1.59.23 2.76.11 3.05.74.81 1.18 1.84 1.18 3.1 0 4.42-2.7 5.39-5.27 5.68.41.36.78 1.06.78 2.14 0 1.55-.01 2.79-.01 3.17 0 .31.21.68.8.56C20.21 21.39 23.5 17.08 23.5 12 23.5 5.65 18.35.5 12 .5z" />
                </svg>
              </a>
              <a
                href="https://cyble.com"
                target="_blank"
                rel="noreferrer"
                aria-label="Cyble"
                className="inline-flex h-9 items-center gap-1.5 rounded-md border border-white/10 bg-white/[0.03] px-3 text-xs font-semibold text-gray-300 transition hover:border-white/20 hover:text-white"
              >
                cyble.com
              </a>
            </div>
          </div>

          {COLUMNS.map((col) => (
            <div key={col.label}>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-500">
                {col.label}
              </h4>
              <ul className="mt-4 space-y-2.5">
                {col.links.map((link) => {
                  const external = link.href.startsWith('http');
                  return (
                    <li key={link.label}>
                      {external ? (
                        <a
                          href={link.href}
                          target="_blank"
                          rel="noreferrer"
                          className="text-sm text-gray-400 transition hover:text-white"
                        >
                          {link.label}
                        </a>
                      ) : (
                        <Link
                          href={link.href}
                          className="text-sm text-gray-400 transition hover:text-white"
                        >
                          {link.label}
                        </Link>
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>

        <div className="mt-12 flex flex-col items-start justify-between gap-3 border-t border-white/5 pt-6 text-xs text-gray-500 sm:flex-row sm:items-center">
          <div>
            © {new Date().getFullYear()} Cyble Inc. AiSOC is open-source software released under
            the MIT License.
          </div>
          <div className="flex items-center gap-4">
            <span className="inline-flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              All systems operational
            </span>
            <a
              href="https://github.com/beenuar/AiSOC/releases"
              target="_blank"
              rel="noreferrer"
              className="font-mono hover:text-white"
            >
              v0.3.0
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
