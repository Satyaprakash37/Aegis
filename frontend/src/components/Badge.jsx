import React from 'react';

export function CriticalityBadge({ level }) {
  const num = parseInt(level, 10);
  const configs = {
    5: { label: '5 - Critical', bg: 'bg-red-500/10 text-red-400 border-red-500/30' },
    4: { label: '4 - High', bg: 'bg-orange-500/10 text-orange-400 border-orange-500/30' },
    3: { label: '3 - Medium', bg: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
    2: { label: '2 - Low', bg: 'bg-blue-500/10 text-blue-400 border-blue-500/30' },
    1: { label: '1 - Minimal', bg: 'bg-slate-500/10 text-slate-400 border-slate-500/30' },
  };

  const current = configs[num] || configs[1];

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border ${current.bg}`}>
      {current.label}
    </span>
  );
}

export function EnvironmentBadge({ env }) {
  const configs = {
    production: { label: 'Production', bg: 'bg-rose-500/10 text-rose-400 border-rose-500/30' },
    staging: { label: 'Staging', bg: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
    dev: { label: 'Development', bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' },
  };

  const current = configs[env?.toLowerCase()] || {
    label: env || 'Unknown',
    bg: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
  };

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border capitalize ${current.bg}`}>
      {current.label}
    </span>
  );
}
