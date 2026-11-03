/**
 * The badge on a threat-intel row has to say what the indicator is.
 *
 * On a default install `/threat-intel` showed 1,766 real CISA KEV
 * indicators with **every row badged `IP`** and a CVE in the value column,
 * and filter chips reading `All (100) IP (0) DOMAIN (0) HASH (0) URL (0)` —
 * which sum to zero, so clicking any of them emptied the table. The API was
 * right the whole time: `{"type": "vulnerability", "value": "CVE-…"}`.
 *
 * Two causes, and fixing either alone leaves the page wrong:
 *
 * 1. `TYPE_CONFIG[ioc.type] || TYPE_CONFIG.ip` fell back to `ip` for an
 *    unknown type, so a type nobody had anticipated became a confident
 *    wrong assertion instead of an honest unknown.
 * 2. The chips hardcoded `ip | domain | hash | url`, excluding
 *    `vulnerability` — the only type the one real feed a fresh install
 *    ships actually emits.
 *
 * `useSWR` is mocked rather than `fetch`, matching the sibling suites here:
 * the hook's module-global cache is keyed on a constant string, so a
 * fetch-level mock leaks the first case's rows into the second.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { __setDemoModeForTests } from '@/lib/demoMode';

const swrData = vi.hoisted(() => ({ value: undefined as unknown }));
const swrError = vi.hoisted(() => ({ value: undefined as unknown }));

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({
    data: swrData.value,
    error: swrError.value,
    isLoading: false,
    mutate: vi.fn(),
  }),
}));

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return { ...actual, threatIntelApi: { ...actual.threatIntelApi, list: vi.fn(), lookup: vi.fn() } };
});

import { ThreatIntelView } from './ThreatIntelView';

/** Two KEV rows and one IP, the shape a default install actually serves. */
const KEV_AND_IP = {
  indicators: [
    {
      id: 'kev-1',
      type: 'vulnerability',
      value: 'CVE-2025-21042',
      confidence: 100,
      severity: 'critical',
      malicious: true,
      sources: ['CISA KEV'],
      description: 'Samsung Mobile Devices Out-of-Bounds Write Vulnerability',
      tags: ['kev'],
    },
    {
      id: 'kev-2',
      type: 'vulnerability',
      value: 'CVE-2024-1086',
      confidence: 100,
      severity: 'high',
      malicious: true,
      sources: ['CISA KEV'],
      description: 'Linux Kernel Use-After-Free Vulnerability',
      tags: ['kev'],
    },
    {
      id: 'ip-1',
      type: 'ip',
      value: '198.51.100.9',
      confidence: 80,
      severity: 'medium',
      malicious: true,
      sources: ['Feed'],
      description: 'Scanner with anomalous activity',
      tags: [],
    },
  ],
  total: 1766,
  shown: 3,
};

function rowFor(value: string): HTMLElement {
  const cell = screen.getByText(value);
  return cell.closest('div.flex.items-center') as HTMLElement;
}

beforeEach(() => {
  swrData.value = KEV_AND_IP;
  swrError.value = undefined;
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('a KEV indicator is not an IP', () => {
  it('badges a vulnerability as a vulnerability', () => {
    render(<ThreatIntelView />);

    const row = rowFor('CVE-2025-21042');
    // Pre-fix this reads "IP": `TYPE_CONFIG` has no `vulnerability` key and
    // the lookup falls back to `TYPE_CONFIG.ip`.
    expect(within(row).queryByText('IP')).toBeNull();
    // The badge, not the value cell beside it — both contain "CVE".
    expect(within(row).getByText('CVE')).toBeTruthy();
  });

  it('still badges a real IP as an IP', () => {
    render(<ThreatIntelView />);

    expect(within(rowFor('198.51.100.9')).getByText('IP')).toBeTruthy();
  });

  it('renders an unrecognised type as unknown rather than silently as an IP', () => {
    swrData.value = {
      indicators: [{ ...KEV_AND_IP.indicators[0], id: 'x', type: 'asn-nobody-anticipated', value: 'AS64512' }],
      total: 1,
      shown: 1,
    };
    render(<ThreatIntelView />);

    const row = rowFor('AS64512');
    expect(within(row).queryByText('IP')).toBeNull();
    expect(within(row).getByText(/unknown/i)).toBeTruthy();
  });
});

describe('the type chips describe the rows that are actually there', () => {
  it('offers a chip for every type present', () => {
    render(<ThreatIntelView />);

    // Pre-fix: `IP (0) DOMAIN (0) HASH (0) URL (0)` beside `All (3)`.
    // The chip reuses the badge's label so the two cannot drift.
    expect(screen.getByRole('button', { name: /^cve\s*\(2\)/i })).toBeTruthy();
    expect(screen.getByRole('button', { name: /^ip\s*\(1\)/i })).toBeTruthy();
    expect(screen.getByRole('button', { name: /^all\s*\(3\)/i })).toBeTruthy();
  });

  it('offers no chip that would empty the table', () => {
    render(<ThreatIntelView />);

    // A chip reading `(0)` is an invitation to a blank screen, and five of
    // them summing to zero beside a populated table is the reported defect.
    expect(screen.queryByRole('button', { name: /\(0\)/ })).toBeNull();
  });

  it('the per-type chips sum to the number of rows shown', () => {
    render(<ThreatIntelView />);

    const counts = screen
      .getAllByRole('button')
      .map((b) => /\((\d+)\)\s*$/.exec(b.textContent ?? ''))
      .filter((m): m is RegExpExecArray => Boolean(m))
      .map((m) => Number(m[1]));

    // The largest is `All`; the rest partition it.
    const all = Math.max(...counts);
    const perType = counts.filter((c) => c !== all);
    expect(perType.reduce((a, b) => a + b, 0)).toBe(all);
  });
});

describe('what the chips say when nothing was measured', () => {
  it('keeps the em-dash rather than publishing a measured zero', () => {
    // The route answers 200 with `degraded: true` when it could not read
    // its store. The sibling suite pins this for the fixed five chips; it
    // has to keep holding now that the set is derived from the data.
    swrData.value = undefined;
    render(<ThreatIntelView />);

    const chips = screen
      .getAllByRole('button')
      .map((b) => (b.textContent ?? '').trim())
      .filter((t) => /\(.+\)$/.test(t));

    expect(chips.length).toBeGreaterThan(0);
    for (const label of chips) {
      expect(label, `"${label}" reads as a measured count`).toMatch(/\(—\)$/);
    }
  });
});
