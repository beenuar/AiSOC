import clsx from 'clsx';

interface Vendor {
  name: string;
  type: 'open' | 'closed';
  reduction: string;
  mitre: string;
  audit: string;
  selfHost: string;
  reproducible: string;
}

const VENDORS: Vendor[] = [
  {
    name: 'AiSOC',
    type: 'open',
    reduction: '75.3% (measured)',
    mitre: '97% (measured)',
    audit: 'Per-step ledger',
    selfHost: 'Yes (MIT)',
    reproducible: 'Yes — every commit',
  },
  {
    name: 'Anvilogic',
    type: 'closed',
    reduction: '~90% (vendor claim)',
    mitre: 'Not published',
    audit: 'Vendor portal',
    selfHost: 'No (cloud only)',
    reproducible: 'No',
  },
  {
    name: 'Prophet',
    type: 'closed',
    reduction: '"10x throughput" (no method)',
    mitre: 'Not published',
    audit: 'Vendor portal',
    selfHost: 'No (cloud only)',
    reproducible: 'No',
  },
  {
    name: 'Dropzone',
    type: 'closed',
    reduction: 'Not published',
    mitre: 'Not published',
    audit: 'Vendor portal',
    selfHost: 'No (cloud only)',
    reproducible: 'No',
  },
  {
    name: 'Tines',
    type: 'closed',
    reduction: 'N/A (SOAR)',
    mitre: 'Not applicable',
    audit: 'Run history',
    selfHost: 'On-prem option',
    reproducible: 'No published bench',
  },
];

const COLUMNS = [
  { key: 'reduction', label: 'Alert reduction' },
  { key: 'mitre', label: 'MITRE accuracy' },
  { key: 'audit', label: 'Decision audit' },
  { key: 'selfHost', label: 'Self-host' },
  { key: 'reproducible', label: 'Reproducible benchmark' },
] as const;

export function ComparisonTable() {
  return (
    <div className="overflow-x-auto rounded-xl border border-white/10 bg-white/[0.02]">
      <table className="w-full min-w-[760px] text-left text-sm">
        <thead className="border-b border-white/5 bg-white/[0.02]">
          <tr>
            <th className="px-5 py-3 text-xs font-medium uppercase tracking-wider text-gray-400">
              Product
            </th>
            {COLUMNS.map((col) => (
              <th
                key={col.key}
                className="px-5 py-3 text-xs font-medium uppercase tracking-wider text-gray-400"
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-white/5">
          {VENDORS.map((vendor) => {
            const isUs = vendor.name === 'AiSOC';
            return (
              <tr
                key={vendor.name}
                className={clsx(
                  'transition-colors',
                  isUs ? 'bg-brand-500/[0.06]' : 'hover:bg-white/[0.02]',
                )}
              >
                <td className="px-5 py-4">
                  <div className="flex items-center gap-2">
                    <span
                      className={clsx(
                        'font-semibold',
                        isUs ? 'text-white' : 'text-gray-200',
                      )}
                    >
                      {vendor.name}
                    </span>
                    <span
                      className={clsx(
                        'rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider',
                        vendor.type === 'open'
                          ? 'bg-emerald-500/15 text-emerald-300'
                          : 'bg-white/10 text-gray-400',
                      )}
                    >
                      {vendor.type === 'open' ? 'Open' : 'Closed'}
                    </span>
                  </div>
                </td>
                {COLUMNS.map((col) => (
                  <td
                    key={col.key}
                    className={clsx(
                      'px-5 py-4 text-sm',
                      isUs ? 'text-white' : 'text-gray-300',
                    )}
                  >
                    {vendor[col.key]}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
