'use client';

import useSWR from 'swr';

interface HeatmapCell {
  category: string;
  status: string;
  count: number;
}

interface HeatmapData {
  framework: string;
  framework_name: string;
  categories: string[];
  statuses: string[];
  cells: HeatmapCell[];
}

const STATUS_COLORS: Record<string, string> = {
  approved: 'bg-green-600',
  collected: 'bg-blue-500',
  review: 'bg-yellow-500',
  rejected: 'bg-red-500',
  missing: 'bg-gray-700',
};

const STATUS_LABELS: Record<string, string> = {
  approved: 'Approved',
  collected: 'Collected',
  review: 'In Review',
  rejected: 'Rejected',
  missing: 'Missing',
};

function intensityClass(count: number, max: number): string {
  if (count === 0) return 'opacity-10';
  const ratio = count / max;
  if (ratio < 0.25) return 'opacity-30';
  if (ratio < 0.5) return 'opacity-50';
  if (ratio < 0.75) return 'opacity-70';
  return 'opacity-100';
}

const fetcher = (url: string) =>
  fetch(url).then((r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  });

interface Props {
  framework: string;
}

export function ComplianceHeatmap({ framework }: Props) {
  const { data, error, isLoading } = useSWR<HeatmapData>(
    `/api/v1/compliance/${framework}/heatmap`,
    fetcher,
    { refreshInterval: 60_000 }
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-48 text-gray-400">
        Loading heatmap…
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="text-red-400 text-sm p-4">
        Failed to load heatmap data.
      </div>
    );
  }

  // Build lookup map: category → status → count
  const lookup: Record<string, Record<string, number>> = {};
  for (const cell of data.cells) {
    lookup[cell.category] ??= {};
    lookup[cell.category][cell.status] = cell.count;
  }

  // Find max count for scaling
  const allCounts = data.cells.map((c) => c.count);
  const maxCount = Math.max(...allCounts, 1);

  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg p-4 overflow-x-auto">
      <h3 className="text-white font-semibold text-base mb-4">
        {data.framework_name} — Control Coverage Heatmap
      </h3>

      {/* Legend */}
      <div className="flex flex-wrap gap-3 mb-4">
        {data.statuses.map((st) => (
          <div key={st} className="flex items-center gap-1.5 text-xs text-gray-300">
            <span className={`w-3 h-3 rounded-sm ${STATUS_COLORS[st] ?? 'bg-gray-500'}`} />
            {STATUS_LABELS[st] ?? st}
          </div>
        ))}
      </div>

      {/* Heatmap table */}
      <table className="min-w-full text-xs border-separate border-spacing-0.5">
        <thead>
          <tr>
            <th className="text-left text-gray-400 font-medium pr-3 pb-2 min-w-[180px]">
              Category
            </th>
            {data.statuses.map((st) => (
              <th
                key={st}
                className="text-center text-gray-400 font-medium pb-2 min-w-[70px]"
              >
                {STATUS_LABELS[st] ?? st}
              </th>
            ))}
            <th className="text-right text-gray-400 font-medium pb-2 pl-3 min-w-[50px]">
              Total
            </th>
          </tr>
        </thead>
        <tbody>
          {data.categories.map((cat) => {
            const rowCounts = lookup[cat] ?? {};
            const rowTotal = Object.values(rowCounts).reduce((s, v) => s + v, 0);

            return (
              <tr key={cat}>
                <td className="text-gray-300 pr-3 py-0.5 truncate max-w-[180px]" title={cat}>
                  {cat}
                </td>
                {data.statuses.map((st) => {
                  const count = rowCounts[st] ?? 0;
                  const color = STATUS_COLORS[st] ?? 'bg-gray-500';
                  return (
                    <td key={st} className="text-center py-0.5">
                      {count > 0 ? (
                        <span
                          className={`inline-flex items-center justify-center w-full h-7 rounded text-white font-medium ${color} ${intensityClass(count, maxCount)}`}
                          title={`${count} control(s) — ${STATUS_LABELS[st] ?? st}`}
                        >
                          {count}
                        </span>
                      ) : (
                        <span className="inline-flex items-center justify-center w-full h-7 rounded text-gray-600 bg-gray-800">
                          —
                        </span>
                      )}
                    </td>
                  );
                })}
                <td className="text-right text-gray-400 pl-3 py-0.5 font-medium">
                  {rowTotal}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
