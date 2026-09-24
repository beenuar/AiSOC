'use client'

import { useState } from 'react'
import useSWR from 'swr'
import { demoFallback } from '@/lib/demoFallback';

// Same-origin by default — Next.js rewrites proxy `/api/v1/purple-team/*` to
// the purple-team service. Override with `NEXT_PUBLIC_PURPLE_TEAM_API` for
// debugging against a different origin.
const API = process.env.NEXT_PUBLIC_PURPLE_TEAM_API ?? ''

// --------------------------------------------------------------------------
// Types
// --------------------------------------------------------------------------
interface Execution {
  id: string
  source: 'atomic' | 'caldera'
  technique_id: string
  test_name: string
  status: 'pending' | 'running' | 'success' | 'failed' | 'error'
  started_at: string | null
  completed_at: string | null
  detected: boolean | null
  detection_latency_seconds: number | null
  created_at: string
}

interface CoverageSummary {
  total_techniques: number
  tested_techniques: number
  detected_techniques: number
  overall_coverage: number
}

interface TechniqueCell {
  technique_id: string
  technique_name: string
  test_count: number
  pass_count: number
  detected: number
  coverage: number
}

interface CoverageMatrix {
  tactics: string[]
  techniques: Record<string, TechniqueCell[]>
  summary: CoverageSummary
}

// --------------------------------------------------------------------------
// Detection drift (w1-drift) — delta-vs-last-week overlay on the heatmap.
// --------------------------------------------------------------------------
type DriftStatus = 'new' | 'removed' | 'improved' | 'regressed' | 'unchanged'

interface DriftTechnique {
  technique_id: string
  status: DriftStatus
  delta_coverage: number
  delta_detected: number
}

interface DriftSummary {
  current: Partial<CoverageSummary>
  previous: Partial<CoverageSummary>
  delta: {
    delta_total: number
    delta_tested: number
    delta_detected: number
    delta_coverage: number
  }
  regressed: number
  improved: number
  new: number
  removed: number
}

interface SnapshotMeta {
  id: string
  captured_at: string
  trigger: string
  total_techniques: number
  tested_techniques: number
  detected_techniques: number
  overall_coverage: number
}

interface DriftLatestResponse {
  current: SnapshotMeta | null
  previous: SnapshotMeta | null
  drift: {
    techniques: DriftTechnique[]
    summary: DriftSummary
  }
}

interface TabletopSession {
  id: string
  name: string
  description?: string
  scenario: string
  technique_ids: string[]
  findings: Array<{ finding: string; severity: string; owner?: string; added_at: string }>
  status: 'active' | 'completed' | 'archived'
  created_by?: string
  created_at: string
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------
const TENANT_ID = '00000000-0000-0000-0000-000000000001'

const fetcher = (url: string) =>
  fetch(url).then((r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`)
    return r.json()
  })

const STATUS_COLORS: Record<string, string> = {
  pending: 'bg-gray-800 text-gray-400',
  running: 'bg-blue-900/40 text-blue-300',
  success: 'bg-green-900/40 text-green-300',
  failed: 'bg-red-900/40 text-red-300',
  error: 'bg-orange-900/40 text-orange-300',
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-green-400',
  info: 'text-blue-400',
}

function coverageColor(c: number): string {
  if (c >= 0.8) return 'bg-green-500'
  if (c >= 0.5) return 'bg-yellow-400'
  if (c > 0) return 'bg-orange-400'
  return 'bg-gray-700'
}

const MOCK_COVERAGE: CoverageMatrix = {
  tactics: ['initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'lateral-movement', 'command-and-control', 'exfiltration'],
  techniques: {
    'initial-access': [
      { technique_id: 'T1566', technique_name: 'Phishing', test_count: 12, pass_count: 10, detected: 8, coverage: 0.67 },
      { technique_id: 'T1078', technique_name: 'Valid Accounts', test_count: 6, pass_count: 5, detected: 3, coverage: 0.5 },
    ],
    'execution': [
      { technique_id: 'T1059', technique_name: 'Command & Scripting', test_count: 18, pass_count: 16, detected: 14, coverage: 0.78 },
      { technique_id: 'T1204', technique_name: 'User Execution', test_count: 8, pass_count: 7, detected: 5, coverage: 0.63 },
    ],
    'persistence': [
      { technique_id: 'T1053', technique_name: 'Scheduled Task/Job', test_count: 10, pass_count: 9, detected: 7, coverage: 0.7 },
    ],
    'privilege-escalation': [
      { technique_id: 'T1548', technique_name: 'Abuse Elevation', test_count: 5, pass_count: 4, detected: 2, coverage: 0.4 },
    ],
    'defense-evasion': [
      { technique_id: 'T1027', technique_name: 'Obfuscated Files', test_count: 14, pass_count: 12, detected: 10, coverage: 0.71 },
      { technique_id: 'T1070', technique_name: 'Indicator Removal', test_count: 7, pass_count: 5, detected: 3, coverage: 0.43 },
    ],
    'credential-access': [
      { technique_id: 'T1003', technique_name: 'OS Credential Dumping', test_count: 11, pass_count: 10, detected: 9, coverage: 0.82 },
      { technique_id: 'T1110', technique_name: 'Brute Force', test_count: 9, pass_count: 8, detected: 7, coverage: 0.78 },
    ],
    'lateral-movement': [
      { technique_id: 'T1021', technique_name: 'Remote Services', test_count: 6, pass_count: 5, detected: 3, coverage: 0.5 },
    ],
    'command-and-control': [
      { technique_id: 'T1071', technique_name: 'Application Layer Protocol', test_count: 8, pass_count: 7, detected: 5, coverage: 0.63 },
      { technique_id: 'T1105', technique_name: 'Ingress Tool Transfer', test_count: 5, pass_count: 4, detected: 2, coverage: 0.4 },
    ],
    'exfiltration': [
      { technique_id: 'T1048', technique_name: 'Exfil Over Alt Protocol', test_count: 4, pass_count: 3, detected: 1, coverage: 0.25 },
    ],
  },
  summary: { total_techniques: 201, tested_techniques: 14, detected_techniques: 10, overall_coverage: 0.71 },
}

// Visual ring around a technique cell that reflects how it changed since the
// previous snapshot. Kept subtle so the underlying coverage color still reads.
function driftRing(status: DriftStatus | undefined): string {
  switch (status) {
    case 'improved':
      return 'ring-2 ring-emerald-500 ring-offset-1'
    case 'regressed':
      return 'ring-2 ring-red-500 ring-offset-1'
    case 'new':
      return 'ring-2 ring-blue-500 ring-offset-1'
    case 'removed':
      return 'ring-2 ring-amber-500 ring-offset-1 opacity-60'
    default:
      return ''
  }
}

function driftDeltaLabel(d: number, suffix = ''): string {
  if (d === 0) return '±0' + suffix
  return `${d > 0 ? '+' : ''}${d}${suffix}`
}

// --------------------------------------------------------------------------
// Components
// --------------------------------------------------------------------------

function CoverageHeatmap() {
  const { data } = useSWR<CoverageMatrix>(
    `${API}/api/v1/purple-team/coverage?tenant_id=${TENANT_ID}`,
    fetcher,
    { refreshInterval: 30000, fallbackData: demoFallback(MOCK_COVERAGE) }
  )

  const { data: drift, mutate: mutateDrift } = useSWR<DriftLatestResponse>(
    `${API}/api/v1/purple-team/drift/latest?tenant_id=${TENANT_ID}`,
    fetcher,
    { refreshInterval: 60000 }
  )

  const [capturing, setCapturing] = useState(false)
  const [captureError, setCaptureError] = useState<string | null>(null)

  async function captureNow() {
    setCapturing(true)
    setCaptureError(null)
    try {
      const res = await fetch(
        `${API}/api/v1/purple-team/drift/snapshot?tenant_id=${TENANT_ID}&trigger=manual`,
        { method: 'POST' }
      )
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      await mutateDrift()
    } catch (e) {
      setCaptureError(e instanceof Error ? e.message : 'Snapshot failed')
    } finally {
      setCapturing(false)
    }
  }

  // `fallbackData` above withholds MOCK_COVERAGE outside the hosted demo.
  // Naming the constant again here put it back: with the purple-team service
  // absent — it is an `extras`-profile service, so it is not running in
  // `core` or `full` — the page rendered an invented ATT&CK matrix with
  // per-technique test and detection counts as the tenant's own coverage.
  // Zeroed rather than absent: `summary` is required by CoverageMatrix and is
  // dereferenced unguarded below, and "0 of 0 techniques, 0% coverage" is the
  // truthful reading when the service has told us nothing.
  const EMPTY_COVERAGE: CoverageMatrix = {
    tactics: [],
    techniques: {},
    summary: { total_techniques: 0, tested_techniques: 0, detected_techniques: 0, overall_coverage: 0 },
  }
  const resolved = data ?? EMPTY_COVERAGE
  const {
    summary: rawSummary,
    tactics = EMPTY_COVERAGE.tactics,
    techniques = EMPTY_COVERAGE.techniques,
  } = resolved
  const summary = rawSummary ?? EMPTY_COVERAGE.summary

  // Index drift status by technique_id for O(1) lookup while rendering cells.
  const driftByTid = new Map<string, DriftTechnique>()
  for (const t of drift?.drift.techniques ?? []) {
    driftByTid.set(t.technique_id, t)
  }
  const driftSummary = drift?.drift.summary
  const hasPrevious = Boolean(drift?.previous)

  return (
    <div className="space-y-4">
      {/* Summary cards — show absolute values + delta-vs-last-snapshot when available. */}
      <div className="grid grid-cols-4 gap-3">
        {[
          {
            label: 'Total Techniques',
            value: summary.total_techniques,
            delta: driftSummary?.delta.delta_total ?? 0,
          },
          {
            label: 'Tested',
            value: summary.tested_techniques,
            delta: driftSummary?.delta.delta_tested ?? 0,
          },
          {
            label: 'Detected',
            value: summary.detected_techniques,
            delta: driftSummary?.delta.delta_detected ?? 0,
          },
          {
            label: 'Coverage',
            value: `${(summary.overall_coverage * 100).toFixed(0)}%`,
            delta: driftSummary
              ? Math.round(driftSummary.delta.delta_coverage * 100)
              : 0,
            deltaSuffix: 'pp',
          },
        ].map((s) => (
          <div key={s.label} className="bg-gray-900/60 rounded-lg border border-gray-700 p-3 text-center">
            <div className="text-xl font-bold text-gray-100">{s.value}</div>
            <div className="text-xs text-gray-500 mt-1">{s.label}</div>
            {hasPrevious && (
              <div
                className={`text-[10px] font-medium mt-1 ${
                  s.delta > 0
                    ? 'text-emerald-600'
                    : s.delta < 0
                    ? 'text-red-600'
                    : 'text-gray-400'
                }`}
              >
                {driftDeltaLabel(s.delta, s.deltaSuffix ?? '')} vs last snapshot
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Drift banner — controls + counts of regressions/improvements. */}
      <div className="bg-gray-900/60 rounded-lg border border-gray-700 p-3 flex flex-wrap items-center gap-4">
        <div className="flex-1 min-w-[200px]">
          <div className="text-xs font-semibold text-gray-300">Detection drift</div>
          <div className="text-xs text-gray-500 mt-0.5" suppressHydrationWarning>
            {drift?.current
              ? `Last snapshot ${new Date(drift.current.captured_at).toLocaleString()} (${drift.current.trigger})`
              : 'No snapshots yet — capture one to start tracking drift week-over-week.'}
          </div>
        </div>
        {driftSummary && hasPrevious && (
          <div className="flex gap-2 text-xs">
            <span className="px-2 py-0.5 rounded bg-blue-900/40 text-blue-300">
              new {driftSummary.new}
            </span>
            <span className="px-2 py-0.5 rounded bg-emerald-900/40 text-emerald-300">
              improved {driftSummary.improved}
            </span>
            <span className="px-2 py-0.5 rounded bg-red-900/40 text-red-300">
              regressed {driftSummary.regressed}
            </span>
            <span className="px-2 py-0.5 rounded bg-amber-900/40 text-amber-300">
              removed {driftSummary.removed}
            </span>
          </div>
        )}
        <button
          onClick={captureNow}
          disabled={capturing}
          className="px-3 py-1.5 text-xs font-medium bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50"
        >
          {capturing ? 'Capturing…' : 'Capture snapshot'}
        </button>
        {captureError && (
          <span className="text-xs text-red-600">{captureError}</span>
        )}
      </div>

      {/* Drift legend — explains the per-cell ring colors. */}
      {hasPrevious && (
        <div className="flex flex-wrap items-center gap-3 text-[11px] text-gray-400">
          <span className="font-medium">Delta-vs-last-snapshot:</span>
          <span className="inline-flex items-center gap-1">
            <span className="w-3 h-3 rounded ring-2 ring-emerald-500 ring-offset-1" />
            improved
          </span>
          <span className="inline-flex items-center gap-1">
            <span className="w-3 h-3 rounded ring-2 ring-red-500 ring-offset-1" />
            regressed
          </span>
          <span className="inline-flex items-center gap-1">
            <span className="w-3 h-3 rounded ring-2 ring-blue-500 ring-offset-1" />
            new
          </span>
          <span className="inline-flex items-center gap-1">
            <span className="w-3 h-3 rounded ring-2 ring-amber-500 ring-offset-1 opacity-60" />
            removed
          </span>
        </div>
      )}

      {/* Heatmap grid */}
      <div className="bg-gray-900/60 rounded-lg border border-gray-700 overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-gray-800">
              <th className="text-left px-3 py-2 font-medium text-gray-400 w-40">Technique</th>
              {tactics.map((t) => (
                <th key={t} className="px-2 py-2 font-medium text-gray-400 capitalize text-center min-w-[80px]">
                  {t.replace(/-/g, ' ')}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {/* Build a technique × tactic grid view */}
            {(() => {
              const allTechniques = new Set<string>()
              tactics.forEach((t) => (techniques[t] ?? []).forEach((tc) => allTechniques.add(tc.technique_id)))
              // Surface "removed" techniques in the table even when they're
              // gone from the live matrix, so analysts see what dropped off.
              for (const t of drift?.drift.techniques ?? []) {
                if (t.status === 'removed') allTechniques.add(t.technique_id)
              }
              return Array.from(allTechniques).sort().map((tid) => {
                const tDrift = driftByTid.get(tid)
                return (
                  <tr key={tid} className="border-t border-gray-800">
                    <td className="px-3 py-1.5 font-mono text-gray-300">
                      {tid}
                      {tDrift && hasPrevious && tDrift.status !== 'unchanged' && (
                        <span
                          className={`ml-2 text-[9px] uppercase font-semibold tracking-wide ${
                            tDrift.status === 'improved'
                              ? 'text-emerald-600'
                              : tDrift.status === 'regressed'
                              ? 'text-red-600'
                              : tDrift.status === 'new'
                              ? 'text-blue-600'
                              : 'text-amber-600'
                          }`}
                        >
                          {tDrift.status}
                        </span>
                      )}
                    </td>
                    {tactics.map((tactic) => {
                      const cell = (techniques[tactic] ?? []).find((tc) => tc.technique_id === tid)
                      const ring = hasPrevious ? driftRing(tDrift?.status) : ''
                      const tooltipBase = cell
                        ? `${cell.test_count} tests, ${cell.pass_count} passed, ${cell.detected} detected`
                        : ''
                      const tooltipDelta =
                        tDrift && hasPrevious
                          ? ` • ${tDrift.status} (Δdetected ${driftDeltaLabel(tDrift.delta_detected)}, Δcoverage ${driftDeltaLabel(Math.round(tDrift.delta_coverage * 100), 'pp')})`
                          : ''
                      return (
                        <td key={tactic} className="px-2 py-1.5 text-center">
                          {cell ? (
                            <div
                              className={`inline-flex items-center justify-center w-8 h-5 rounded text-white text-[10px] font-semibold ${coverageColor(cell.coverage)} ${ring}`}
                              title={tooltipBase + tooltipDelta}
                            >
                              {(cell.coverage * 100).toFixed(0)}%
                            </div>
                          ) : (
                            <div className="inline-flex items-center justify-center w-8 h-5 rounded bg-gray-800 text-gray-500 text-[10px]">—</div>
                          )}
                        </td>
                      )
                    })}
                  </tr>
                )
              })
            })()}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ExecutionsTable({ onReportDetection }: { onReportDetection: (ex: Execution) => void }) {
  const { data, error, isLoading } = useSWR<Execution[]>(
    `${API}/api/v1/purple-team/executions?tenant_id=${TENANT_ID}&limit=50`,
    fetcher,
    { refreshInterval: 10000 }
  )

  if (isLoading) return <div className="text-sm text-gray-500 p-4">Loading executions…</div>
  if (error || !data) return <div className="text-sm text-red-500 p-4">Failed to load executions</div>

  return (
    <div className="bg-gray-900/60 rounded-lg border border-gray-700 overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-800 border-b border-gray-700">
            {['Source', 'Technique', 'Test Name', 'Status', 'Detected', 'Created'].map((h) => (
              <th key={h} className="text-left px-4 py-2.5 font-medium text-gray-400 text-xs">{h}</th>
            ))}
            <th className="px-4 py-2.5"></th>
          </tr>
        </thead>
        <tbody>
          {data.map((ex) => (
            <tr key={ex.id} className="border-t border-gray-800 hover:bg-gray-800/50">
              <td className="px-4 py-2.5">
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${ex.source === 'caldera' ? 'bg-purple-900/40 text-purple-300' : 'bg-blue-900/40 text-blue-300'}`}>
                  {ex.source}
                </span>
              </td>
              <td className="px-4 py-2.5 font-mono text-xs text-gray-300">{ex.technique_id}</td>
              <td className="px-4 py-2.5 text-gray-200 max-w-xs truncate">{ex.test_name}</td>
              <td className="px-4 py-2.5">
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_COLORS[ex.status] ?? ''}`}>
                  {ex.status}
                </span>
              </td>
              <td className="px-4 py-2.5">
                {ex.detected === null ? (
                  <span className="text-gray-500 text-xs">—</span>
                ) : ex.detected ? (
                  <span className="text-green-400 font-medium text-xs">Yes</span>
                ) : (
                  <span className="text-red-400 font-medium text-xs">No</span>
                )}
              </td>
              <td className="px-4 py-2.5 text-gray-500 text-xs" suppressHydrationWarning>
                {new Date(ex.created_at).toLocaleString()}
              </td>
              <td className="px-4 py-2.5">
                {ex.detected === null && (
                  <button
                    onClick={() => onReportDetection(ex)}
                    className="text-xs text-indigo-400 hover:text-indigo-300 font-medium"
                  >
                    Report
                  </button>
                )}
              </td>
            </tr>
          ))}
          {data.length === 0 && (
            <tr>
              <td colSpan={7} className="px-4 py-8 text-center text-gray-400 text-sm">
                No executions yet. Run an atomic test or Caldera operation.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function TabletopPanel() {
  const [showCreate, setShowCreate] = useState(false)
  const [selectedSession, setSelectedSession] = useState<TabletopSession | null>(null)
  const [newFinding, setNewFinding] = useState('')
  const [newFindingSeverity, setNewFindingSeverity] = useState('medium')

  const { data: sessions, mutate } = useSWR<TabletopSession[]>(
    `${API}/api/v1/purple-team/tabletop?tenant_id=${TENANT_ID}`,
    fetcher,
    { refreshInterval: 15000 }
  )

  const [form, setForm] = useState({ name: '', scenario: '', technique_ids: '' })

  async function createSession() {
    await fetch(`${API}/api/v1/purple-team/tabletop`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tenant_id: TENANT_ID,
        name: form.name,
        scenario: form.scenario,
        technique_ids: form.technique_ids.split(',').map((s) => s.trim()).filter(Boolean),
      }),
    })
    setShowCreate(false)
    setForm({ name: '', scenario: '', technique_ids: '' })
    mutate()
  }

  async function addFinding(sessionId: string) {
    await fetch(`${API}/api/v1/purple-team/tabletop/${sessionId}/findings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding: newFinding, severity: newFindingSeverity }),
    })
    setNewFinding('')
    mutate()
    const res = await fetch(`${API}/api/v1/purple-team/tabletop/${sessionId}`)
    if (!res.ok) return
    const updated = await res.json()
    setSelectedSession(updated)
  }

  async function completeSession(sessionId: string) {
    await fetch(`${API}/api/v1/purple-team/tabletop/${sessionId}/complete`, { method: 'PATCH' })
    mutate()
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-100">Tabletop Sessions</h3>
        <button
          onClick={() => setShowCreate(true)}
          className="px-3 py-1.5 bg-indigo-600 text-white text-xs font-medium rounded-lg hover:bg-indigo-700"
        >
          + New Session
        </button>
      </div>

      {showCreate && (
        <div className="bg-gray-900/60 rounded-lg border border-gray-700 p-4 space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Session Name</label>
            <input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className="w-full px-3 py-2 border border-gray-600 bg-gray-800 text-gray-200 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500"
              placeholder="Q2 Threat Hunt Exercise"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Scenario</label>
            <textarea
              value={form.scenario}
              onChange={(e) => setForm({ ...form, scenario: e.target.value })}
              rows={3}
              className="w-full px-3 py-2 border border-gray-600 bg-gray-800 text-gray-200 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500"
              placeholder="Describe the attack scenario…"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">
              ATT&amp;CK Techniques (comma-separated)
            </label>
            <input
              value={form.technique_ids}
              onChange={(e) => setForm({ ...form, technique_ids: e.target.value })}
              className="w-full px-3 py-2 border border-gray-600 bg-gray-800 text-gray-200 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500"
              placeholder="T1059, T1055, T1003"
            />
          </div>
          <div className="flex gap-2 justify-end">
            <button
              onClick={() => setShowCreate(false)}
              className="px-3 py-1.5 text-sm text-gray-400 border border-gray-600 rounded-lg hover:bg-gray-800"
            >
              Cancel
            </button>
            <button
              onClick={createSession}
              disabled={!form.name || !form.scenario}
              className="px-3 py-1.5 text-sm bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50"
            >
              Create
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {(sessions ?? []).map((s) => (
          <div key={s.id} className="bg-gray-900/60 rounded-lg border border-gray-700 p-4">
            <div className="flex items-start justify-between mb-2">
              <div>
                <div className="font-medium text-gray-100 text-sm">{s.name}</div>
                <div className="text-xs text-gray-500 mt-0.5">
                  {s.technique_ids.length} techniques • {s.findings.length} findings
                </div>
              </div>
              <span className={`px-2 py-0.5 rounded text-xs font-medium ${s.status === 'active' ? 'bg-green-900/40 text-green-300' : 'bg-gray-800 text-gray-400'}`}>
                {s.status}
              </span>
            </div>
            <p className="text-xs text-gray-400 line-clamp-2 mb-3">{s.scenario}</p>
            <div className="flex gap-2">
              <button
                onClick={() => setSelectedSession(s)}
                className="text-xs text-indigo-400 font-medium hover:text-indigo-300"
              >
                View findings
              </button>
              {s.status === 'active' && (
                <button
                  onClick={() => completeSession(s.id)}
                  className="text-xs text-gray-500 hover:text-gray-300"
                >
                  Mark complete
                </button>
              )}
            </div>
          </div>
        ))}
        {!sessions?.length && (
          <div className="col-span-2 text-center py-8 text-gray-400 text-sm">
            No tabletop sessions yet.
          </div>
        )}
      </div>

      {/* Findings panel */}
      {selectedSession && (
        <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4">
          <div className="bg-gray-900 rounded-xl shadow-xl border border-gray-700 w-full max-w-2xl max-h-[80vh] flex flex-col">
            <div className="px-5 py-4 border-b border-gray-700 flex items-center justify-between">
              <div>
                <h2 className="font-semibold text-gray-100">{selectedSession.name}</h2>
                <p className="text-xs text-gray-500 mt-0.5">{selectedSession.technique_ids.join(', ')}</p>
              </div>
              <button onClick={() => setSelectedSession(null)} className="text-gray-500 hover:text-gray-300 text-xl">×</button>
            </div>
            <div className="flex-1 overflow-y-auto p-5 space-y-3">
              {selectedSession.findings.length === 0 && (
                <p className="text-gray-500 text-sm text-center py-4">No findings recorded yet.</p>
              )}
              {selectedSession.findings.map((f, i) => (
                <div key={i} className="flex items-start gap-3 bg-gray-800 rounded-lg p-3">
                  <span className={`text-xs font-semibold uppercase mt-0.5 ${SEVERITY_COLORS[f.severity] ?? ''}`}>
                    {f.severity}
                  </span>
                  <div className="flex-1">
                    <p className="text-sm text-gray-200">{f.finding}</p>
                    {f.owner && <p className="text-xs text-gray-500 mt-0.5">Owner: {f.owner}</p>}
                  </div>
                </div>
              ))}
            </div>
            {selectedSession.status === 'active' && (
              <div className="px-5 py-4 border-t border-gray-700 space-y-2">
                <div className="flex gap-2">
                  <input
                    value={newFinding}
                    onChange={(e) => setNewFinding(e.target.value)}
                    className="flex-1 px-3 py-2 border border-gray-600 bg-gray-800 text-gray-200 rounded-lg text-sm"
                    placeholder="Add a finding…"
                  />
                  <select
                    value={newFindingSeverity}
                    onChange={(e) => setNewFindingSeverity(e.target.value)}
                    className="px-2 py-2 border border-gray-600 bg-gray-800 text-gray-200 rounded-lg text-sm"
                  >
                    {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                  <button
                    onClick={() => addFinding(selectedSession.id)}
                    disabled={!newFinding.trim()}
                    className="px-4 py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 disabled:opacity-50"
                  >
                    Add
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// --------------------------------------------------------------------------
// Detection report modal
// --------------------------------------------------------------------------
function ReportDetectionModal({
  execution,
  onClose,
  onSaved,
}: {
  execution: Execution
  onClose: () => void
  onSaved: () => void
}) {
  const [detected, setDetected] = useState<boolean>(true)
  const [alertId, setAlertId] = useState('')
  const [latency, setLatency] = useState('')

  async function save() {
    await fetch(`${API}/api/v1/purple-team/executions/${execution.id}/detection`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        execution_id: execution.id,
        detected,
        alert_id: alertId || null,
        detection_latency_seconds: latency ? parseFloat(latency) : null,
      }),
    })
    onSaved()
    onClose()
  }

  return (
    <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4">
      <div className="bg-gray-900 rounded-xl shadow-xl border border-gray-700 w-full max-w-md">
        <div className="px-5 py-4 border-b border-gray-700 flex items-center justify-between">
          <h2 className="font-semibold text-gray-100">Report Detection Outcome</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 text-xl">×</button>
        </div>
        <div className="p-5 space-y-4">
          <p className="text-sm text-gray-400">
            <span className="font-mono bg-gray-800 px-1 rounded text-gray-200">{execution.technique_id}</span>{' '}
            {execution.test_name}
          </p>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Detected?</label>
            <div className="flex gap-3">
              <label className="flex items-center gap-1.5 text-sm">
                <input type="radio" checked={detected === true} onChange={() => setDetected(true)} />
                Yes — detected
              </label>
              <label className="flex items-center gap-1.5 text-sm">
                <input type="radio" checked={detected === false} onChange={() => setDetected(false)} />
                No — missed
              </label>
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Alert ID (optional)</label>
            <input
              value={alertId}
              onChange={(e) => setAlertId(e.target.value)}
              className="w-full px-3 py-2 border border-gray-600 bg-gray-800 text-gray-200 rounded-lg text-sm"
              placeholder="ALERT-123"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Detection Latency (seconds)</label>
            <input
              value={latency}
              onChange={(e) => setLatency(e.target.value)}
              type="number"
              min="0"
              className="w-full px-3 py-2 border border-gray-600 bg-gray-800 text-gray-200 rounded-lg text-sm"
              placeholder="120"
            />
          </div>
        </div>
        <div className="px-5 py-4 border-t border-gray-700 flex justify-end gap-2">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 border border-gray-600 rounded-lg hover:bg-gray-800">
            Cancel
          </button>
          <button onClick={save} className="px-4 py-2 text-sm bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
            Save
          </button>
        </div>
      </div>
    </div>
  )
}

// --------------------------------------------------------------------------
// Page
// --------------------------------------------------------------------------
const TABS = ['Coverage', 'Executions', 'Tabletop'] as const
type Tab = typeof TABS[number]

export default function PurpleTeamPage() {
  const [tab, setTab] = useState<Tab>('Coverage')
  const [reportTarget, setReportTarget] = useState<Execution | null>(null)

  const { mutate: mutateExecutions } = useSWR<Execution[]>(
    `${API}/api/v1/purple-team/executions?tenant_id=${TENANT_ID}&limit=50`,
    fetcher,
    { refreshInterval: 10000 }
  )

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Purple Team</h1>
          <p className="text-sm text-gray-500 mt-1">
            Atomic Red Team execution, Caldera integration, ATT&amp;CK coverage heatmap, and tabletop simulator
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-700">
        <nav className="-mb-px flex gap-6">
          {TABS.map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
                tab === t
                  ? 'border-indigo-500 text-indigo-400'
                  : 'border-transparent text-gray-500 hover:text-gray-300 hover:border-gray-600'
              }`}
            >
              {t}
            </button>
          ))}
        </nav>
      </div>

      {/* Content */}
      {tab === 'Coverage' && <CoverageHeatmap />}
      {tab === 'Executions' && (
        <ExecutionsTable onReportDetection={(ex) => setReportTarget(ex)} />
      )}
      {tab === 'Tabletop' && <TabletopPanel />}

      {/* Detection report modal */}
      {reportTarget && (
        <ReportDetectionModal
          execution={reportTarget}
          onClose={() => setReportTarget(null)}
          onSaved={() => mutateExecutions()}
        />
      )}
    </div>
  )
}
