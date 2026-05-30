import Link from 'next/link';
import packageJson from '../../../package.json';
import { docs } from '@/lib/docs';
import { Logo } from './Logo';

const APP_VERSION = packageJson.version;

const COLUMNS = [
  {
    label: 'Platform',
    links: [
      { label: 'Features', href: '/#features' },
      { label: 'How it works', href: '/#architecture' },
      { label: 'MITRE coverage', href: '/#mitre' },
      { label: 'Sovereign + air-gap', href: '/sovereign' },
      { label: 'Customers', href: '/customers' },
      { label: 'Benchmark', href: '/benchmark' },
      { label: 'Console', href: '/dashboard' },
    ],
  },
  {
    label: 'Open source',
    links: [
      { label: 'Why open source', href: '/why-open-source' },
      { label: 'GitHub', href: 'https://github.com/beenuar/AiSOC' },
      { label: 'Quickstart', href: docs('quickstart') },
      { label: 'Roadmap', href: 'https://github.com/beenuar/AiSOC/blob/main/ROADMAP.md' },
      { label: 'Changelog', href: 'https://github.com/beenuar/AiSOC/blob/main/CHANGELOG.md' },
    ],
  },
  {
    label: 'Community',
    links: [
      { label: 'Issues', href: 'https://github.com/beenuar/AiSOC/issues' },
      { label: 'Discussions', href: 'https://github.com/beenuar/AiSOC/discussions' },
      { label: 'Contributing', href: docs('contributing/guidelines') },
      { label: 'Code of conduct', href: 'https://github.com/beenuar/AiSOC/blob/main/CODE_OF_CONDUCT.md' },
    ],
  },
  {
    label: 'Project',
    links: [
      { label: 'Security policy', href: 'https://github.com/beenuar/AiSOC/blob/main/SECURITY.md' },
      { label: 'License (MIT)', href: 'https://github.com/beenuar/AiSOC/blob/main/LICENSE' },
      { label: 'Releases', href: 'https://github.com/beenuar/AiSOC/releases' },
    ],
  },
];

export function Footer() {
  return (
    <footer className="relative border-t border-velvet-border bg-velvet-surface-base font-velvet-body text-velvet-content-secondary">
      <div className="mx-auto max-w-7xl px-6 py-16">
        <div className="grid grid-cols-2 gap-10 md:grid-cols-6">
          <div className="col-span-2">
            <Logo size={36} withWordmark />
            <p className="mt-4 max-w-sm text-sm font-light leading-relaxed text-velvet-content-secondary">
              An open-source AI security operations centre, maintained by the
              AiSOC community and released under the MIT licence.
            </p>
            <div className="mt-5 flex gap-3">
              <a
                href="https://github.com/beenuar/AiSOC"
                target="_blank"
                rel="noreferrer"
                aria-label="GitHub"
                className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-velvet-border bg-velvet-surface-raised/60 text-velvet-content-secondary transition hover:border-velvet-border-strong hover:text-velvet-content-primary"
              >
                <svg viewBox="0 0 24 24" className="h-4 w-4" fill="currentColor" aria-hidden="true">
                  <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56 0-.28-.01-1.02-.02-2-3.2.69-3.88-1.54-3.88-1.54-.52-1.32-1.27-1.67-1.27-1.67-1.04-.71.08-.69.08-.69 1.15.08 1.76 1.18 1.76 1.18 1.02 1.75 2.68 1.24 3.34.95.1-.74.4-1.24.73-1.53-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.18-3.1-.12-.29-.51-1.46.11-3.05 0 0 .96-.31 3.15 1.18a10.9 10.9 0 015.74 0c2.19-1.49 3.15-1.18 3.15-1.18.62 1.59.23 2.76.11 3.05.74.81 1.18 1.84 1.18 3.1 0 4.42-2.7 5.39-5.27 5.68.41.36.78 1.06.78 2.14 0 1.55-.01 2.79-.01 3.17 0 .31.21.68.8.56C20.21 21.39 23.5 17.08 23.5 12 23.5 5.65 18.35.5 12 .5z" />
                </svg>
              </a>
            </div>
          </div>

          {COLUMNS.map((col) => (
            <div key={col.label}>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-velvet-content-tertiary">
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
                          className="text-sm text-velvet-content-secondary transition hover:text-velvet-content-primary"
                        >
                          {link.label}
                        </a>
                      ) : (
                        <Link
                          href={link.href}
                          className="text-sm text-velvet-content-secondary transition hover:text-velvet-content-primary"
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

        <div className="mt-12 flex flex-col items-start justify-between gap-3 border-t border-velvet-border pt-6 text-xs text-velvet-content-tertiary sm:flex-row sm:items-center">
          <div>
            © {new Date().getFullYear()} AiSOC contributors. Released under the MIT License.
          </div>
          <a
            href="https://github.com/beenuar/AiSOC/releases"
            target="_blank"
            rel="noreferrer"
            className="font-mono hover:text-velvet-content-primary"
          >
            v{APP_VERSION}
          </a>
        </div>
      </div>
    </footer>
  );
}
