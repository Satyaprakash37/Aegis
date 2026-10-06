import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  ShieldAlert, 
  Server, 
  Activity, 
  AlertTriangle, 
  TrendingUp, 
  ShieldCheck, 
  ArrowUpRight, 
  ExternalLink,
  RefreshCw,
  Zap,
  BarChart3,
  PieChart as PieIcon,
  Flame,
  Clock
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  AreaChart, 
  Area, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  CartesianGrid 
} from 'recharts';
import api from '../api/client';
import { SeverityBadge, RiskTierBadge } from '../components/Badge';

// Count-up animation helper
function AnimatedNumber({ value, duration = 700 }) {
  const [current, setCurrent] = useState(0);

  useEffect(() => {
    const end = Number(value) || 0;
    if (end === 0) {
      setCurrent(0);
      return;
    }
    const steps = 30;
    const increment = end / steps;
    let step = 0;

    const timer = setInterval(() => {
      step++;
      if (step >= steps) {
        setCurrent(end);
        clearInterval(timer);
      } else {
        setCurrent(Math.floor(increment * step));
      }
    }, duration / steps);

    return () => clearInterval(timer);
  }, [value, duration]);

  return <span>{current.toLocaleString()}</span>;
}

// Custom Recharts Dark Tooltip
const CustomChartTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-2.5 shadow-xl text-xs font-mono">
        {label && <p className="text-slate-400 mb-1">{label}</p>}
        {payload.map((entry, index) => (
          <p key={`item-${index}`} style={{ color: entry.color || entry.fill || '#38bdf8' }} className="font-semibold">
            {entry.name}: {entry.value}
          </p>
        ))}
      </div>
    );
  }
  return null;
};

export default function Dashboard() {
  const navigate = useNavigate();

  // Dashboard Data State
  const [summary, setSummary] = useState(null);
  const [severityDist, setSeverityDist] = useState([]);
  const [trendData, setTrendData] = useState([]);
  const [topRiskyAssets, setTopRiskyAssets] = useState([]);
  const [recentVulns, setRecentVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  const fetchDashboardData = useCallback(async (isSilent = false) => {
    if (!isSilent) setLoading(true);
    try {
      const [sumRes, sevRes, trendRes, topRes, recRes] = await Promise.all([
        api.get('/api/dashboard/summary'),
        api.get('/api/dashboard/severity-distribution'),
        api.get('/api/dashboard/trend'),
        api.get('/api/dashboard/top-risky-assets'),
        api.get('/api/dashboard/recent-vulns'),
      ]);

      setSummary(sumRes.data.data || {});
      setSeverityDist(sevRes.data.data || []);
      setTrendData(trendRes.data.data || []);
      setTopRiskyAssets(topRes.data.data || []);
      setRecentVulns(recRes.data.data || []);
      setLastRefreshed(new Date());
    } catch (err) {
      console.error('Failed to load dashboard telemetry:', err);
    } finally {
      if (!isSilent) setLoading(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  // 30-second auto-refresh polling
  useEffect(() => {
    const interval = setInterval(() => {
      fetchDashboardData(true);
    }, 30000);
    return () => clearInterval(interval);
  }, [fetchDashboardData]);

  // Compute total vulns from severity for Donut center
  const totalInDistribution = severityDist.reduce((acc, item) => acc + (item.count || 0), 0);

  const formatDate = (dateStr) => {
    if (!dateStr) return '—';
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="space-y-6 pb-8">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white tracking-wide font-sans">
              Cybersecurity Command Center
            </h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              Live SOC Telemetry
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Continuous vulnerability posture, risk prioritization, and infrastructure analytics
          </p>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono text-slate-500 hidden sm:inline">
            Auto-refresh (30s) · {lastRefreshed.toLocaleTimeString()}
          </span>
          <button
            onClick={() => fetchDashboardData()}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 font-mono transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Sync SOC</span>
          </button>
        </div>
      </div>

      {/* Row 1: KPI Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Vulnerabilities */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md relative overflow-hidden group hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Total Vulnerabilities</span>
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-white tracking-tight">
              {loading ? (
                <div className="h-8 w-16 bg-slate-800 animate-pulse rounded" />
              ) : (
                <AnimatedNumber value={summary?.total_vulnerabilities || 0} />
              )}
            </div>
            <p className="text-[11px] text-slate-500 mt-1 flex items-center gap-1 font-mono">
              <span>{summary?.open_vulns || 0} Open</span>
              <span>·</span>
              <span className="text-emerald-400">{summary?.mitigated_vulns || 0} Mitigated</span>
            </p>
          </div>
        </div>

        {/* Card 2: Critical / High Open (Hero Card with Glow) */}
        <div className={`p-5 rounded-xl border backdrop-blur-md relative overflow-hidden group transition-all ${
          (summary?.critical_high_count || 0) > 0
            ? 'border-rose-500/40 bg-gradient-to-b from-rose-950/20 to-slate-950/70 shadow-[0_0_25px_rgba(244,63,94,0.12)]'
            : 'border-slate-800 bg-slate-950/70'
        }`}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-rose-400 font-semibold flex items-center gap-1.5">
              <Flame className="w-3.5 h-3.5 fill-rose-500/30" />
              <span>Critical / High Open</span>
            </span>
            <div className="w-8 h-8 rounded-lg bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-rose-400 tracking-tight">
              {loading ? (
                <div className="h-8 w-16 bg-slate-800 animate-pulse rounded" />
              ) : (
                <AnimatedNumber value={summary?.critical_high_count || 0} />
              )}
            </div>
            <p className="text-[11px] text-rose-400/80 mt-1 font-mono">
              Immediate remediation required
            </p>
          </div>
        </div>

        {/* Card 3: Assets Monitored */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md relative overflow-hidden group hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Assets Monitored</span>
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-white tracking-tight">
              {loading ? (
                <div className="h-8 w-16 bg-slate-800 animate-pulse rounded" />
              ) : (
                <AnimatedNumber value={summary?.total_assets || 0} />
              )}
            </div>
            <p className="text-[11px] text-slate-500 mt-1 font-mono flex items-center gap-1">
              <span>Active infrastructure nodes</span>
            </p>
          </div>
        </div>

        {/* Card 4: Scans Run (30d) */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md relative overflow-hidden group hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Scans Executed (30d)</span>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-white tracking-tight">
              {loading ? (
                <div className="h-8 w-16 bg-slate-800 animate-pulse rounded" />
              ) : (
                <AnimatedNumber value={summary?.scans_run_30d || 0} />
              )}
            </div>
            <p className="text-[11px] text-slate-500 mt-1 font-mono flex items-center gap-1">
              <span>Automated Nmap audits</span>
            </p>
          </div>
        </div>
      </div>

      {/* Row 2: Charts (Severity Donut & 30-Day Trend Area) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Severity Donut Chart (4 cols) */}
        <div className="lg:col-span-5 p-5 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <PieIcon className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
                Severity Distribution
              </h2>
            </div>
            <span className="text-xs text-slate-500 font-mono">CVSS v3.1</span>
          </div>

          {loading ? (
            <div className="flex-1 flex items-center justify-center min-h-[260px]">
              <div className="w-36 h-36 rounded-full border-4 border-slate-800 border-t-cyan-500 animate-spin" />
            </div>
          ) : totalInDistribution === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center min-h-[260px] text-slate-500">
              <ShieldCheck className="w-10 h-10 text-slate-600 mb-2 opacity-50" />
              <p className="text-sm font-medium text-slate-400">No vulnerabilities recorded</p>
              <p className="text-xs text-slate-600">Run a scan to generate severity telemetry</p>
            </div>
          ) : (
            <div className="flex-1 flex flex-col">
              <div className="relative h-[220px]">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityDist.filter(d => d.count > 0)}
                      dataKey="count"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={85}
                      paddingAngle={3}
                    >
                      {severityDist.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} stroke="#090d16" strokeWidth={2} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomChartTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
                {/* Center Label */}
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-2xl font-bold font-mono text-white">{totalInDistribution}</span>
                  <span className="text-[10px] uppercase font-mono tracking-widest text-slate-500">Total</span>
                </div>
              </div>

              {/* Legend Badges */}
              <div className="grid grid-cols-3 sm:grid-cols-5 gap-2 mt-2 pt-3 border-t border-slate-800/60 font-mono text-xs">
                {severityDist.map((item) => (
                  <div key={item.severity} className="text-center">
                    <span className="text-[10px] text-slate-400 block uppercase">{item.name}</span>
                    <span className="font-bold" style={{ color: item.color }}>{item.count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Vulnerability Discovery Trend Area Chart (7 cols) */}
        <div className="lg:col-span-7 p-5 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
                Discovery Velocity (30 Days)
              </h2>
            </div>
            <span className="text-xs text-slate-500 font-mono">Daily CVE Influx</span>
          </div>

          {loading ? (
            <div className="flex-1 flex items-center justify-center min-h-[260px]">
              <div className="h-40 w-full bg-slate-900/40 animate-pulse rounded-lg" />
            </div>
          ) : (
            <div className="h-[250px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis 
                    dataKey="date" 
                    stroke="#64748b" 
                    fontSize={11} 
                    tickLine={false} 
                    axisLine={{ stroke: '#334155' }} 
                    interval={5}
                  />
                  <YAxis 
                    stroke="#64748b" 
                    fontSize={11} 
                    tickLine={false} 
                    axisLine={{ stroke: '#334155' }}
                    allowDecimals={false}
                  />
                  <Tooltip content={<CustomChartTooltip />} />
                  <Area
                    type="monotone"
                    dataKey="discovered"
                    name="Discovered CVEs"
                    stroke="#06b6d4"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#trendGradient)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Row 3: Top Risky Assets Horizontal Bar Chart */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
              Top Risky Infrastructure Nodes
            </h2>
          </div>
          <span className="text-xs text-slate-500 font-mono">Ranked by Open Critical & High CVEs</span>
        </div>

        {loading ? (
          <div className="h-44 bg-slate-900/40 animate-pulse rounded-lg" />
        ) : topRiskyAssets.length === 0 ? (
          <div className="py-10 text-center text-slate-500">
            <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-emerald-400/50" />
            <p className="text-sm font-medium text-slate-400">No high-risk asset concentrations detected</p>
            <p className="text-xs text-slate-600">Assets are free of open critical/high vulnerabilities</p>
          </div>
        ) : (
          <div className="h-48 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={topRiskyAssets}
                layout="vertical"
                margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" stroke="#64748b" fontSize={11} allowDecimals={false} />
                <YAxis 
                  dataKey="name" 
                  type="category" 
                  stroke="#94a3b8" 
                  fontSize={11} 
                  tickLine={false} 
                  width={140}
                />
                <Tooltip content={<CustomChartTooltip />} />
                <Bar 
                  dataKey="total_open_critical_high" 
                  name="Open Critical & High CVEs" 
                  fill="#f43f5e" 
                  radius={[0, 4, 4, 0]} 
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Row 4: Recent Discoveries Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md overflow-hidden">
        <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
              Recent Vulnerability Telemetry
            </h2>
          </div>
          <button
            onClick={() => navigate('/vulns')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-mono inline-flex items-center gap-1 cursor-pointer"
          >
            <span>View All Findings</span>
            <ExternalLink className="w-3 h-3" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead>
              <tr className="border-b border-slate-800/80 bg-slate-950 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                <th className="py-3 px-4">CVE Identifier</th>
                <th className="py-3 px-4">Contextual Risk</th>
                <th className="py-3 px-4">Base CVSS</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Affected Asset</th>
                <th className="py-3 px-4">Service</th>
                <th className="py-3 px-4 text-right">Discovered</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40">
              {loading ? (
                Array.from({ length: 4 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="py-3.5 px-4"><div className="h-4 w-28 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-24 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-12 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-16 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-32 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-20 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4 text-right"><div className="h-4 w-20 bg-slate-800 rounded ml-auto" /></td>
                  </tr>
                ))
              ) : recentVulns.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-slate-500">
                    No vulnerability telemetry available. Trigger a scan from the Scans page.
                  </td>
                </tr>
              ) : (
                recentVulns.map((v) => (
                  <tr
                    key={v.id}
                    onClick={() => navigate('/vulns')}
                    className="hover:bg-slate-900/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3.5 px-4 font-mono font-bold text-cyan-400 group-hover:text-cyan-300">
                      {v.cve_id}
                    </td>
                    <td className="py-3.5 px-4">
                      <RiskTierBadge tier={v.risk_tier} score={v.risk_score} />
                    </td>
                    <td className="py-3.5 px-4 font-mono font-bold text-white">
                      {Number(v.cvss_score).toFixed(1)}
                    </td>
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={v.severity} />
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-300">
                      {v.asset_name}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-400">
                      {v.service || 'Service'}{v.port ? `:${v.port}` : ''}
                    </td>
                    <td className="py-3.5 px-4 text-right font-mono text-slate-400 text-[11px]">
                      {formatDate(v.first_seen_at)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
