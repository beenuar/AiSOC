'use client';

/**
 * The SIEM content tab: what detection content the tenant's
 * SIEM runs, and how each rule behaves in outcomes this platform
 * attributed. Honest states throughout: an unreachable API shows the
 * error, an empty inventory explains the refresh path, a rate with no
 * denominator renders "not measured" — never a confident zero.
 */

import { useCallback, useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { apiFetch } from '@/lib/api';

interface InventoryRule {
  connector_type: string;
  vendor_rule_id: string;
  name: string;
  kind: string;
  enabled: boolean | null;
  severity: string;
  attack: string[];
  version: number;
  last_seen: string | null;
}

interface HealthRule {
  vendor_rule_id: string;
  name: string;
  connector_type: string;
  vendor_execution_state: Record<string, unknown>;
  alerts_attributed: number;
  dispositions: number;
  false_positive: { rate: number | null; denominator: number; note?: string };
  last_fired: string | null;
}

export function SiemContentView() {
  const [inventory, setInventory] = useState<InventoryRule[]>([]);
  const [health, setHealth] = useState<HealthRule[]>([]);
  const [note, setNote] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [inventoryResp, healthResp] = await Promise.all([
        apiFetch('/api/v1/siem-content/inventory'),
        apiFetch('/api/v1/siem-content/health'),
      ]);
      if (!inventoryResp.ok || !healthResp.ok) {
        throw new Error(`inventory ${inventoryResp.status}, health ${healthResp.status}`);
      }
      const inventoryBody = await inventoryResp.json();
      setInventory(inventoryBody.rules ?? []);
      setNote(inventoryBody.note ?? '');
      setHealth((await healthResp.json()).rules ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'request failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const refresh = async () => {
    setRefreshing(true);
    try {
      const resp = await apiFetch('/api/v1/siem-content/refresh', { method: 'POST' });
      if (!resp.ok) throw new Error(`refresh ${resp.status}`);
      const body = await resp.json();
      if (body.note) {
        toast(body.note);
      } else {
        toast.success(`Refreshed from ${body.sources?.length ?? 0} source(s)`);
      }
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'refresh failed');
    } finally {
      setRefreshing(false);
    }
  };

  if (loading) return <div className="p-8 text-sm text-slate-400">Loading SIEM content…</div>;

  if (error) {
    return (
      <EmptyState
        icon={EmptyStateIcons.alert}
        title="SIEM content unavailable"
        description={`The API could not be reached: ${error}. Nothing is shown rather than something invented.`}
      />
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-slate-100">SIEM content</h1>
          <p className="text-sm text-slate-400">
            Read-only inventory of the detection content your SIEM runs, with outcomes this
            platform attributed. {note}
          </p>
        </div>
        <button
          type="button"
          onClick={() => void refresh()}
          disabled={refreshing}
          className="rounded-md border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700 disabled:opacity-50"
        >
          {refreshing ? 'Refreshing…' : 'Refresh inventory'}
        </button>
      </div>

      {inventory.length === 0 ? (
        <EmptyState
          icon={EmptyStateIcons.search}
          title="No SIEM content in the inventory"
          description="Connect a Splunk or Elastic connector under Integrations, then refresh. The Sentinel and QRadar legs plug into the same seam and are tracked follow-ups."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-3 py-2">Rule</th>
                <th className="px-3 py-2">SIEM</th>
                <th className="px-3 py-2">Kind</th>
                <th className="px-3 py-2">Vendor state</th>
                <th className="px-3 py-2">ATT&CK</th>
                <th className="px-3 py-2">Attributed alerts</th>
                <th className="px-3 py-2">FP rate</th>
                <th className="px-3 py-2">Last fired</th>
                <th className="px-3 py-2">Content v</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-950/50">
              {inventory.map((rule) => {
                const h = health.find(
                  (x) => x.vendor_rule_id === rule.vendor_rule_id && x.connector_type === rule.connector_type,
                );
                return (
                  <tr key={`${rule.connector_type}:${rule.vendor_rule_id}`} className="text-slate-300">
                    <td className="px-3 py-2 font-medium text-slate-200">{rule.name}</td>
                    <td className="px-3 py-2">{rule.connector_type}</td>
                    <td className="px-3 py-2">{rule.kind}</td>
                    <td className="px-3 py-2">
                      {rule.enabled === null ? (
                        <span className="text-slate-500">could not check</span>
                      ) : rule.enabled ? (
                        <span className="text-emerald-400">enabled</span>
                      ) : (
                        <span className="text-slate-500">disabled</span>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{rule.attack.join(', ') || '—'}</td>
                    <td className="px-3 py-2">{h ? h.alerts_attributed : '—'}</td>
                    <td className="px-3 py-2">
                      {h && h.false_positive.rate !== null ? (
                        <span>
                          {(h.false_positive.rate * 100).toFixed(1)}%{' '}
                          <span className="text-slate-500">of {h.false_positive.denominator}</span>
                        </span>
                      ) : (
                        <span className="text-slate-500">not measured</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {h?.last_fired ? new Date(h.last_fired).toLocaleDateString() : '—'}
                    </td>
                    <td className="px-3 py-2">v{rule.version}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default SiemContentView;
