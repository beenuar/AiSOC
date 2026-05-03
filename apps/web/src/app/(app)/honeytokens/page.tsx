"use client";

import { useState } from "react";
import useSWR, { mutate } from "swr";

const API = process.env.NEXT_PUBLIC_HONEYTOKENS_URL ?? "http://localhost:8005";
const TENANT_ID = process.env.NEXT_PUBLIC_TENANT_ID ?? "00000000-0000-0000-0000-000000000001";

const fetcher = (url: string) => fetch(url).then((r) => r.json());

type TokenStatus = "active" | "triggered" | "expired" | "revoked";

interface HoneytokenRecord {
  id: string;
  name: string;
  description: string | null;
  token_type: string;
  token_value: string;
  metadata: Record<string, unknown>;
  status: TokenStatus;
  expires_at: string | null;
  created_at: string;
  created_by: string | null;
}

interface Trigger {
  id: string;
  source_ip: string | null;
  user_agent: string | null;
  threat_score: number | null;
  alert_sent: boolean;
  triggered_at: string;
}

const TOKEN_TYPES = [
  "aws_key",
  "url",
  "file",
  "db_credential",
  "email",
  "dns",
  "api_key",
  "custom",
];

const STATUS_COLORS: Record<TokenStatus, string> = {
  active: "bg-green-100 text-green-800",
  triggered: "bg-red-100 text-red-800",
  expired: "bg-gray-100 text-gray-700",
  revoked: "bg-yellow-100 text-yellow-800",
};

function TokenRow({
  token,
  onRevoke,
  onDelete,
  onSelect,
}: {
  token: HoneytokenRecord;
  onRevoke: (id: string) => void;
  onDelete: (id: string) => void;
  onSelect: (id: string) => void;
}) {
  return (
    <tr className="hover:bg-gray-50 cursor-pointer" onClick={() => onSelect(token.id)}>
      <td className="px-4 py-3 text-sm font-medium text-gray-900 max-w-xs truncate">
        {token.name}
      </td>
      <td className="px-4 py-3 text-sm text-gray-600">{token.token_type}</td>
      <td className="px-4 py-3">
        <span
          className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${STATUS_COLORS[token.status]}`}
        >
          {token.status}
        </span>
      </td>
      <td className="px-4 py-3 text-sm text-gray-500">
        {token.expires_at ? new Date(token.expires_at).toLocaleDateString() : "—"}
      </td>
      <td className="px-4 py-3 text-sm text-gray-500">
        {new Date(token.created_at).toLocaleDateString()}
      </td>
      <td className="px-4 py-3 text-sm" onClick={(e) => e.stopPropagation()}>
        <div className="flex gap-2">
          {token.status === "active" && (
            <button
              onClick={() => onRevoke(token.id)}
              className="text-yellow-600 hover:text-yellow-800 text-xs"
            >
              Revoke
            </button>
          )}
          <button
            onClick={() => onDelete(token.id)}
            className="text-red-600 hover:text-red-800 text-xs"
          >
            Delete
          </button>
        </div>
      </td>
    </tr>
  );
}

function CreateTokenModal({
  onClose,
  onCreate,
}: {
  onClose: () => void;
  onCreate: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [tokenType, setTokenType] = useState("aws_key");
  const [ttlDays, setTtlDays] = useState(365);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/api/v1/honeytokens`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: TENANT_ID,
          name,
          description: description || null,
          token_type: tokenType,
          ttl_days: ttlDays,
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      onCreate();
      onClose();
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-md p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Create Honeytoken</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Name *</label>
            <input
              className="w-full border rounded-md px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. AWS Prod Key – Finance"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
            <textarea
              className="w-full border rounded-md px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Token Type *</label>
            <select
              className="w-full border rounded-md px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
              value={tokenType}
              onChange={(e) => setTokenType(e.target.value)}
            >
              {TOKEN_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              TTL (days)
            </label>
            <input
              type="number"
              className="w-full border rounded-md px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
              value={ttlDays}
              onChange={(e) => setTtlDays(Number(e.target.value))}
              min={1}
            />
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
        </div>
        <div className="flex justify-end gap-3 mt-6">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={loading || !name}
            className="px-4 py-2 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
          >
            {loading ? "Creating…" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}

function TriggersPanel({ tokenId, onClose }: { tokenId: string; onClose: () => void }) {
  const { data: triggers, isLoading } = useSWR<Trigger[]>(
    `${API}/api/v1/honeytokens/${tokenId}/triggers`,
    fetcher,
    { refreshInterval: 10_000 }
  );

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl p-6 max-h-[80vh] flex flex-col">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-semibold text-gray-900">Trigger History</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-800 text-lg">
            ✕
          </button>
        </div>
        {isLoading ? (
          <p className="text-sm text-gray-500">Loading…</p>
        ) : !triggers?.length ? (
          <p className="text-sm text-gray-500">No triggers yet — token has not been accessed.</p>
        ) : (
          <div className="overflow-y-auto flex-1">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 sticky top-0">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">Triggered</th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">Source IP</th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">Threat Score</th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">Alert Sent</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {triggers.map((t) => (
                  <tr key={t.id} className="hover:bg-gray-50">
                    <td className="px-3 py-2 text-gray-700">
                      {new Date(t.triggered_at).toLocaleString()}
                    </td>
                    <td className="px-3 py-2 text-gray-600">{t.source_ip ?? "—"}</td>
                    <td className="px-3 py-2">
                      {t.threat_score != null ? (
                        <span
                          className={`font-medium ${t.threat_score > 70 ? "text-red-600" : "text-yellow-600"}`}
                        >
                          {t.threat_score.toFixed(0)}
                        </span>
                      ) : (
                        <span className="text-gray-400">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${t.alert_sent ? "bg-green-100 text-green-800" : "bg-gray-100 text-gray-600"}`}
                      >
                        {t.alert_sent ? "Yes" : "No"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default function HoneytokensPage() {
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [showCreate, setShowCreate] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const listKey = `${API}/api/v1/honeytokens?tenant_id=${TENANT_ID}${statusFilter ? `&status=${statusFilter}` : ""}${typeFilter ? `&token_type=${typeFilter}` : ""}`;

  const { data: tokens, isLoading } = useSWR<HoneytokenRecord[]>(listKey, fetcher, {
    refreshInterval: 15_000,
  });

  const refresh = () => mutate(listKey);

  const revoke = async (id: string) => {
    await fetch(`${API}/api/v1/honeytokens/${id}/revoke`, { method: "PATCH" });
    refresh();
  };

  const remove = async (id: string) => {
    if (!confirm("Delete this honeytoken?")) return;
    await fetch(`${API}/api/v1/honeytokens/${id}`, { method: "DELETE" });
    refresh();
  };

  const counts = {
    total: tokens?.length ?? 0,
    active: tokens?.filter((t) => t.status === "active").length ?? 0,
    triggered: tokens?.filter((t) => t.status === "triggered").length ?? 0,
    revoked: tokens?.filter((t) => t.status === "revoked").length ?? 0,
  };

  return (
    <div className="p-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Honeytokens</h1>
          <p className="text-sm text-gray-500 mt-1">
            Deploy deception tokens and get alerted on first access.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700"
        >
          + New Token
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: "Total", value: counts.total, color: "text-gray-900" },
          { label: "Active", value: counts.active, color: "text-green-600" },
          { label: "Triggered", value: counts.triggered, color: "text-red-600" },
          { label: "Revoked", value: counts.revoked, color: "text-yellow-600" },
        ].map((s) => (
          <div key={s.label} className="bg-white border rounded-lg p-4">
            <p className="text-xs text-gray-500 uppercase tracking-wide">{s.label}</p>
            <p className={`text-2xl font-bold mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex gap-3 mb-4">
        <select
          className="border rounded-md px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="triggered">Triggered</option>
          <option value="expired">Expired</option>
          <option value="revoked">Revoked</option>
        </select>
        <select
          className="border rounded-md px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
        >
          <option value="">All types</option>
          {TOKEN_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="bg-white border rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-sm text-gray-500">Loading tokens…</div>
        ) : !tokens?.length ? (
          <div className="p-8 text-center text-sm text-gray-500">
            No honeytokens found. Create your first one.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b">
              <tr>
                <th className="px-4 py-3 text-left font-medium text-gray-600">Name</th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">Type</th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">Status</th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">Expires</th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">Created</th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {tokens.map((token) => (
                <TokenRow
                  key={token.id}
                  token={token}
                  onRevoke={revoke}
                  onDelete={remove}
                  onSelect={(id) => setSelectedId(id)}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Modals */}
      {showCreate && (
        <CreateTokenModal onClose={() => setShowCreate(false)} onCreate={refresh} />
      )}
      {selectedId && (
        <TriggersPanel tokenId={selectedId} onClose={() => setSelectedId(null)} />
      )}
    </div>
  );
}
