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

export function ScanStatusBadge({ status }) {
  const s = String(status || '').toLowerCase();

  if (s === 'running') {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border bg-cyan-500/10 text-cyan-400 border-cyan-500/30">
        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse mr-1.5" />
        Running
      </span>
    );
  }

  if (s === 'completed') {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
        Completed
      </span>
    );
  }

  if (s === 'failed') {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border bg-rose-500/10 text-rose-400 border-rose-500/30">
        Failed
      </span>
    );
  }

  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border bg-slate-500/10 text-slate-400 border-slate-500/30">
      Pending
    </span>
  );
}

export function SeverityBadge({ severity }) {
  const s = String(severity || 'none').toLowerCase();
  const configs = {
    critical: { label: 'CRITICAL', bg: 'bg-rose-500/10 text-rose-400 border-rose-500/30' },
    high: { label: 'HIGH', bg: 'bg-orange-500/10 text-orange-400 border-orange-500/30' },
    medium: { label: 'MEDIUM', bg: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
    low: { label: 'LOW', bg: 'bg-blue-500/10 text-blue-400 border-blue-500/30' },
    none: { label: 'NONE', bg: 'bg-slate-500/10 text-slate-400 border-slate-500/30' },
  };

  const current = configs[s] || configs.none;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold tracking-wide border ${current.bg}`}>
      {current.label}
    </span>
  );
}

export function VulnStatusBadge({ status }) {
  const s = String(status || 'open').toLowerCase();
  const configs = {
    open: { label: 'Open', bg: 'bg-rose-500/10 text-rose-400 border-rose-500/30' },
    in_progress: { label: 'In Progress', bg: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
    mitigated: { label: 'Mitigated', bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
    false_positive: { label: 'False Positive', bg: 'bg-slate-500/10 text-slate-400 border-slate-500/30' },
  };

  const current = configs[s] || configs.open;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${current.bg}`}>
      {current.label}
    </span>
  );
}

export function RiskTierBadge({ tier, score }) {
  const t = String(tier || 'NONE').toUpperCase();
  const configs = {
    CRITICAL: { label: 'CRITICAL', bg: 'bg-rose-500/15 text-rose-400 border-rose-500/30' },
    HIGH: { label: 'HIGH', bg: 'bg-orange-500/15 text-orange-400 border-orange-500/30' },
    MEDIUM: { label: 'MEDIUM', bg: 'bg-amber-500/15 text-amber-400 border-amber-500/30' },
    LOW: { label: 'LOW', bg: 'bg-blue-500/15 text-blue-400 border-blue-500/30' },
    NONE: { label: 'NONE', bg: 'bg-slate-500/10 text-slate-400 border-slate-500/30' },
  };

  const current = configs[t] || configs.NONE;

  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono font-bold border ${current.bg}`}>
      <span>{score != null ? Number(score).toFixed(2) : ''}</span>
      <span className="text-[10px] font-sans font-semibold tracking-wider opacity-80 uppercase">
        {current.label}
      </span>
    </span>
  );
}
