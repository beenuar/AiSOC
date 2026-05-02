'use client';

import { useState } from 'react';
import { usePathname } from 'next/navigation';

const routeLabels: Record<string, { title: string; description: string }> = {
  '/': { title: 'Dashboard', description: 'SOC overview and metrics' },
  '/alerts': { title: 'Alerts', description: 'Security alerts and incidents' },
  '/cases': { title: 'Cases', description: 'Incident case management' },
  '/detection': { title: 'Detection Rules', description: 'SIEM detection rules and tuning' },
  '/threat-intel': { title: 'Threat Intelligence', description: 'IOC lookup and threat feeds' },
  '/connectors': { title: 'Connectors', description: 'Security tool integrations' },
  '/settings': { title: 'Settings', description: 'Platform configuration' },
};

interface TopBarProps {
  onSearch?: (query: string) => void;
}

export function TopBar({ onSearch }: TopBarProps) {
  const pathname = usePathname();
  const [searchQuery, setSearchQuery] = useState('');

  const routeKey = Object.keys(routeLabels).find(
    (key) => key !== '/' && pathname.startsWith(key)
  ) || (pathname === '/' ? '/' : '/alerts');

  const routeInfo = routeLabels[routeKey] || routeLabels['/alerts'];

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    onSearch?.(searchQuery);
  };

  const now = new Date();
  const timeStr = now.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
  const dateStr = now.toLocaleDateString('en-US', {
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });

  return (
    <header className="fixed top-0 left-60 right-0 h-16 flex items-center justify-between px-6 bg-gray-900/90 backdrop-blur-sm border-b border-gray-800/60 z-20">
      {/* Page title */}
      <div>
        <h1 className="text-base font-semibold text-white leading-tight">{routeInfo.title}</h1>
        <p className="text-xs text-gray-500">{routeInfo.description}</p>
      </div>

      {/* Center: NL Search */}
      <form onSubmit={handleSearch} className="flex-1 max-w-lg mx-8">
        <div className="relative">
          <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
            <svg className="w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          </div>
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search alerts, IPs, hashes, domains... (AI-powered)"
            className="w-full pl-10 pr-4 py-2 bg-gray-800/60 border border-gray-700/60 rounded-lg text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500/50 focus:bg-gray-800 transition-all"
          />
          {searchQuery && (
            <div className="absolute inset-y-0 right-3 flex items-center">
              <span className="text-xs text-gray-500 bg-gray-700/60 px-1.5 py-0.5 rounded font-mono">⏎</span>
            </div>
          )}
        </div>
      </form>

      {/* Right: clock, notifications, user */}
      <div className="flex items-center gap-4">
        {/* Clock */}
        <div className="text-right hidden lg:block">
          <p className="text-sm font-mono text-gray-300">{timeStr}</p>
          <p className="text-xs text-gray-500">{dateStr}</p>
        </div>

        {/* Notifications */}
        <button className="relative p-1.5 text-gray-400 hover:text-gray-200 transition-colors">
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
          </svg>
          <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full ring-2 ring-gray-900" />
        </button>

        {/* User avatar */}
        <div className="flex items-center gap-2 cursor-pointer group">
          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center text-xs font-bold text-white">
            SO
          </div>
          <div className="hidden lg:block">
            <p className="text-xs font-medium text-gray-300">SOC Analyst</p>
            <p className="text-xs text-gray-500">Admin</p>
          </div>
        </div>
      </div>
    </header>
  );
}
