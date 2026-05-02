import React, { useState } from 'react';

export interface Column<T> {
  key: string;
  header: string;
  accessor: (row: T) => React.ReactNode;
  sortable?: boolean;
  width?: string;
  align?: 'left' | 'center' | 'right';
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  selectedRowKey?: string;
  loading?: boolean;
  emptyMessage?: string;
  className?: string;
  stickyHeader?: boolean;
}

export function DataTable<T>({
  columns,
  data,
  rowKey,
  onRowClick,
  selectedRowKey,
  loading = false,
  emptyMessage = 'No data',
  className = '',
  stickyHeader = false,
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  function handleSort(key: string) {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  }

  return (
    <div className={`w-full overflow-auto ${className}`}>
      <table className="w-full text-sm">
        <thead className={stickyHeader ? 'sticky top-0 z-10' : ''}>
          <tr className="border-b border-gray-700/50 bg-gray-900/80">
            {columns.map((col) => (
              <th
                key={col.key}
                style={col.width ? { width: col.width } : undefined}
                className={[
                  'px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider',
                  col.sortable ? 'cursor-pointer select-none hover:text-gray-300' : '',
                  col.align === 'center' ? 'text-center' : '',
                  col.align === 'right' ? 'text-right' : '',
                ].join(' ')}
                onClick={() => col.sortable && handleSort(col.key)}
              >
                <span className="flex items-center gap-1">
                  {col.header}
                  {col.sortable && sortKey === col.key && (
                    <span className="text-blue-400">{sortDir === 'asc' ? '↑' : '↓'}</span>
                  )}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading && (
            <tr>
              <td colSpan={columns.length} className="px-4 py-8 text-center text-gray-500">
                <div className="flex justify-center">
                  <div className="animate-spin h-6 w-6 border-2 border-blue-500 border-t-transparent rounded-full" />
                </div>
              </td>
            </tr>
          )}
          {!loading && data.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-4 py-8 text-center text-gray-500">
                {emptyMessage}
              </td>
            </tr>
          )}
          {!loading &&
            data.map((row) => {
              const key = rowKey(row);
              const isSelected = key === selectedRowKey;
              return (
                <tr
                  key={key}
                  onClick={() => onRowClick?.(row)}
                  className={[
                    'border-b border-gray-700/30 transition-colors',
                    onRowClick ? 'cursor-pointer' : '',
                    isSelected
                      ? 'bg-blue-500/10'
                      : 'hover:bg-gray-800/60',
                  ].join(' ')}
                >
                  {columns.map((col) => (
                    <td
                      key={col.key}
                      className={[
                        'px-4 py-3 text-gray-300',
                        col.align === 'center' ? 'text-center' : '',
                        col.align === 'right' ? 'text-right' : '',
                      ].join(' ')}
                    >
                      {col.accessor(row)}
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
