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
    lab: { label: 'Lab Environment', bg: 'bg-purple-500/15 text-purple-300 border-purple-500/30' },
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

export function ReportTypeBadge({ type }) {
  const t = String(type || '').toLowerCase();
  const configs = {
    executive: { label: 'Executive', bg: 'bg-purple-500/10 text-purple-400 border-purple-500/30' },
    detailed: { label: 'Detailed', bg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30' },
    compliance: { label: 'Compliance', bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
  };
  const current = configs[t] || { label: type, bg: 'bg-slate-500/10 text-slate-400 border-slate-500/30' };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border ${current.bg}`}>
      {current.label}
    </span>
  );
}

export function ReportFormatBadge({ format }) {
  const f = String(format || '').toLowerCase();
  if (f === 'pdf') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium border bg-rose-500/10 text-rose-400 border-rose-500/30">
        PDF
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium border bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
      Excel
    </span>
  );
}

export function OriginDirectBadge() {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium border bg-amber-500/15 text-amber-300 border-amber-500/30 shadow-[0_0_8px_rgba(245,158,11,0.15)]" title="Discovered directly on origin infrastructure bypassing edge proxy WAF">
      <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
      Origin-Direct
    </span>
  );
}

export function VerificationBadge({ verification, isOriginDirect = false }) {
  const v = String(verification || 'version_match').toLowerCase();
  let badgeEl = null;

  if (v === 'nuclei_verified') {
    badgeEl = (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium border bg-blue-500/15 text-blue-300 border-blue-500/30 shadow-[0_0_8px_rgba(59,130,246,0.15)]">
        <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
        Nuclei Verified ✓
      </span>
    );
  } else if (v === 'nse_verified') {
    badgeEl = (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium border bg-emerald-500/15 text-emerald-300 border-emerald-500/30 shadow-[0_0_8px_rgba(16,185,129,0.15)]">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
        NSE Verified ✓
      </span>
    );
  } else if (v === 'ssl_verified') {
    badgeEl = (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium border bg-purple-500/15 text-purple-300 border-purple-500/30 shadow-[0_0_8px_rgba(168,85,247,0.15)]">
        <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
        SSL Audit ✓
      </span>
    );
  } else {
    badgeEl = (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium border bg-slate-800 text-slate-400 border-slate-700">
        Version Match
      </span>
    );
  }

  if (isOriginDirect) {
    return (
      <div className="inline-flex items-center gap-1.5 flex-wrap">
        {badgeEl}
        <OriginDirectBadge />
      </div>
    );
  }

  return badgeEl;
}

export function DangerScoreBadge({ score, showBar = true }) {
  const num = Number(score) || 0;
  let bg = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
  let barColor = 'bg-emerald-500';

  if (num > 8.0) {
    bg = 'bg-rose-500/15 text-rose-400 border-rose-500/30';
    barColor = 'bg-rose-500';
  } else if (num > 6.0) {
    bg = 'bg-orange-500/15 text-orange-400 border-orange-500/30';
    barColor = 'bg-orange-500';
  } else if (num > 3.0) {
    bg = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    barColor = 'bg-amber-500';
  }

  const pct = Math.min(100, Math.max(0, num * 10));

  return (
    <div className="inline-flex flex-col gap-1 min-w-[50px]">
      <div className={`inline-flex items-center justify-center px-2 py-0.5 rounded text-xs font-mono font-bold border ${bg}`}>
        <span>{num.toFixed(2)}</span>
      </div>
      {showBar && (
        <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
          <div className={`h-full ${barColor} transition-all duration-300`} style={{ width: `${pct}%` }} />
        </div>
      )}
    </div>
  );
}

export function LabBadge() {
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-semibold border bg-purple-500/20 text-purple-300 border-purple-500/40 shadow-[0_0_8px_rgba(168,85,247,0.2)]"
      title="Isolated Attack Simulation Lab Target"
    >
      <span>🧪</span>
      <span>LAB</span>
    </span>
  );
}
