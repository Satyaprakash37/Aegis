import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
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
  Clock,
  Target,
  Layers,
  ChevronDown,
  CheckCircle2
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
import { 
  SeverityBadge, 
  RiskTierBadge,
  VerificationBadge,
  DangerScoreBadge 
} from '../components/Badge';

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
  const [searchParams, setSearchParams] = useSearchParams();
  const urlMode = searchParams.get('mode');
  const urlAssetId = searchParams.get('asset_id');

  // Scope & Asset Selection State
  const [viewMode, setViewMode] = useState(urlMode === 'all' ? 'all' : 'asset');
  const [selectedAssetId, setSelectedAssetId] = useState(urlAssetId ? Number(urlAssetId) : null);
  const [assetsList, setAssetsList] = useState([]);
  const [assetsLoading, setAssetsLoading] = useState(true);

  // Dashboard Data State
  const [summary, setSummary] = useState(null);
  const [severityDist, setSeverityDist] = useState([]);
  const [trendData, setTrendData] = useState([]);
  const [topRiskyAssets, setTopRiskyAssets] = useState([]);
  const [topDangerousVulns, setTopDangerousVulns] = useState([]);
  const [recentVulns, setRecentVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  const fetchAssets = useCallback(async () => {
    try {
      setAssetsLoading(true);
      const res = await api.get('/api/assets?page_size=100');
      const items = res.data?.data || [];
      setAssetsList(items);
      return items;
    } catch (err) {
      console.error('Failed to load assets list:', err);
      return [];
    } finally {
      setAssetsLoading(false);
    }
  }, []);

  const fetchDashboardData = useCallback(async (isSilent = false, overrideAssetId = undefined, overrideMode = undefined) => {
    const activeMode = overrideMode !== undefined ? overrideMode : viewMode;
    const activeAssetId = overrideAssetId !== undefined ? overrideAssetId : selectedAssetId;

    if (!isSilent) setLoading(true);
    try {
      const queryParam = (activeMode === 'asset' && activeAssetId) ? `?asset_id=${activeAssetId}` : '';
      const [sumRes, sevRes, trendRes, topRes, recRes, dangerRes] = await Promise.all([
        api.get(`/api/dashboard/summary${queryParam}`),
        api.get(`/api/dashboard/severity-distribution${queryParam}`),
        api.get(`/api/dashboard/trend${queryParam}`),
        api.get(`/api/dashboard/top-risky-assets${queryParam}`),
        api.get(`/api/dashboard/recent-vulns${queryParam}`),
        api.get(`/api/dashboard/top-dangerous-vulns${queryParam}`),
      ]);

      setSummary(sumRes.data.data || {});
      setSeverityDist(sevRes.data.data || []);
      setTrendData(trendRes.data.data || []);
      setTopRiskyAssets(topRes.data.data || []);
      setRecentVulns(recRes.data.data || []);
      setTopDangerousVulns(dangerRes.data.data || []);
      setLastRefreshed(new Date());
    } catch (err) {
      console.error('Failed to load dashboard telemetry:', err);
    } finally {
      if (!isSilent) setLoading(false);
    }
  }, [viewMode, selectedAssetId]);

  // Initial load: Fetch assets first, then pick asset or all-assets mode
  useEffect(() => {
    let isMounted = true;
    async function init() {
      const items = await fetchAssets();
      if (!isMounted) return;

      let targetId = selectedAssetId;
      let mode = viewMode;

      if (urlMode === 'all') {
        mode = 'all';
      } else if (urlAssetId && items.some(a => a.id === Number(urlAssetId))) {
        targetId = Number(urlAssetId);
        mode = 'asset';
      } else if (items.length > 0) {
        if (!targetId || !items.some(a => a.id === targetId)) {
          targetId = items[0].id;
        }
        mode = 'asset';
      } else {
        mode = 'all';
      }

      setViewMode(mode);
      setSelectedAssetId(targetId);
      fetchDashboardData(false, targetId, mode);
    }

    init();
    return () => { isMounted = false; };
  }, []);

  // 30-second auto-refresh polling
  useEffect(() => {
    const interval = setInterval(() => {
      fetchDashboardData(true);
    }, 30000);
    return () => clearInterval(interval);
  }, [fetchDashboardData]);

  // Real-time refresh on scan completion: Auto-switch to the scanned asset
  useEffect(() => {
    const handleScanComplete = (e) => {
      const completedAssetId = e.detail?.asset_id;
      if (completedAssetId) {
        setViewMode('asset');
        setSelectedAssetId(completedAssetId);
        setSearchParams({ mode: 'asset', asset_id: String(completedAssetId) });
        fetchDashboardData(true, completedAssetId, 'asset');
      } else {
        fetchDashboardData(true);
      }
      fetchAssets();
    };
    window.addEventListener('aegis:scan-completed', handleScanComplete);
    return () => window.removeEventListener('aegis:scan-completed', handleScanComplete);
  }, [fetchDashboardData, fetchAssets, setSearchParams]);

  const handleModeChange = (newMode) => {
    setViewMode(newMode);
    if (newMode === 'asset') {
      const targetId = selectedAssetId || (assetsList.length > 0 ? assetsList[0].id : null);
      setSelectedAssetId(targetId);
      if (targetId) {
        setSearchParams({ mode: 'asset', asset_id: String(targetId) });
        fetchDashboardData(false, targetId, 'asset');
      } else {
        setSearchParams({ mode: 'asset' });
        fetchDashboardData(false, null, 'asset');
      }
    } else {
      setSearchParams({ mode: 'all' });
      fetchDashboardData(false, null, 'all');
    }
  };

  const handleAssetChange = (newAssetId) => {
    setSelectedAssetId(newAssetId);
    setViewMode('asset');
    setSearchParams({ mode: 'asset', asset_id: String(newAssetId) });
    fetchDashboardData(false, newAssetId, 'asset');
  };

  const currentAsset = useMemo(() => {
    if (!selectedAssetId) return summary?.selected_asset || null;
    return assetsList.find(a => a.id === selectedAssetId) || summary?.selected_asset || null;
  }, [selectedAssetId, assetsList, summary]);

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
      {/* Top Header & Context Controls */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white tracking-wide font-sans">
                Cybersecurity Command Center
              </h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                Live SOC Telemetry
              </span>
              {viewMode === 'asset' && currentAsset && (
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  Target Focus
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-1 font-sans">
              {viewMode === 'asset' && currentAsset ? (
                <span>
                  Single-asset vulnerability assessment & live telemetry for{' '}
                  <strong className="text-cyan-300 font-mono">{currentAsset.name}</strong> ({currentAsset.ip_address || 'Domain'})
                </span>
              ) : (
                'Continuous vulnerability posture, risk prioritization, and account-wide infrastructure analytics'
              )}
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

        {/* Scope Switcher & Asset Selector Toolbar */}
        <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md flex flex-col md:flex-row md:items-center justify-between gap-3">
          {/* View Mode Toggle */}
          <div className="flex items-center gap-1.5 p-1 rounded-lg bg-slate-900/90 border border-slate-800/80 w-fit">
            <button
              type="button"
              onClick={() => handleModeChange('asset')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono transition-all cursor-pointer ${
                viewMode === 'asset'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Target className="w-3.5 h-3.5" />
              <span>Single Asset Focus</span>
            </button>
            <button
              type="button"
              onClick={() => handleModeChange('all')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono transition-all cursor-pointer ${
                viewMode === 'all'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>All Assets (Macro)</span>
            </button>
          </div>

          {/* Asset Dropdown Selector (when in Single Asset mode) */}
          {viewMode === 'asset' && (
            <div className="flex-1 flex flex-col sm:flex-row sm:items-center justify-end gap-2.5">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400 whitespace-nowrap">Target Asset:</span>
                <div className="relative min-w-[260px] max-w-full">
                  <select
                    value={selectedAssetId || ''}
                    onChange={(e) => handleAssetChange(Number(e.target.value))}
                    disabled={assetsLoading || assetsList.length === 0}
                    className="w-full appearance-none bg-slate-900 border border-slate-700/80 hover:border-cyan-500/50 rounded-lg px-3 py-1.5 pr-8 text-xs font-mono text-white focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer disabled:opacity-50"
                  >
                    {assetsList.length === 0 ? (
                      <option value="">No assets registered</option>
                    ) : (
                      assetsList.map((asset) => (
                        <option key={asset.id} value={asset.id}>
                          {asset.name} ({asset.ip_address || asset.resolved_ip || 'No IP'}) — Tier {asset.criticality}
                        </option>
                      ))
                    )}
                  </select>
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                </div>
              </div>

              {selectedAssetId && (
                <button
                  onClick={() => navigate('/scans')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-mono transition-colors cursor-pointer"
                >
                  <Zap className="w-3.5 h-3.5" />
                  <span>Scan Target</span>
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Single Asset Context & Latest Scan Telemetry Banner */}
      {viewMode === 'asset' && currentAsset && (
        <div className="p-5 rounded-xl border border-cyan-500/30 bg-gradient-to-r from-slate-950 via-slate-900/90 to-slate-950 shadow-lg relative overflow-hidden">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5">
            {/* Target Asset Identity */}
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <div className="w-7 h-7 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  <Target className="w-4 h-4" />
                </div>
                <h2 className="text-base font-bold text-white font-mono">{currentAsset.name}</h2>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-800 text-slate-300 border border-slate-700">
                  {currentAsset.target_type || 'Asset'}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/30">
                  Criticality {currentAsset.criticality}/5
                </span>
              </div>
              <div className="text-xs font-mono text-slate-400 flex flex-wrap items-center gap-3">
                <span>Target IP / Host: <strong className="text-white">{currentAsset.ip_address || '—'}</strong></span>
                {currentAsset.resolved_ip && currentAsset.resolved_ip !== currentAsset.ip_address && (
                  <span>Resolved IP: <strong className="text-slate-300">{currentAsset.resolved_ip}</strong></span>
                )}
                <span>Environment: <strong className="text-slate-300">{currentAsset.environment || 'Production'}</strong></span>
              </div>
            </div>

            {/* Latest Scan Telemetry for this Asset */}
            <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/80 font-mono text-xs flex flex-col sm:flex-row sm:items-center gap-4">
              {summary?.latest_scan ? (
                <>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] uppercase tracking-wider text-slate-400">Latest Scan:</span>
                      <span className="font-bold text-cyan-400">Scan #{summary.latest_scan.id}</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase ${
                        summary.latest_scan.status === 'completed'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                      }`}>
                        {summary.latest_scan.status}
                      </span>
                      <span className="text-[10px] text-slate-400">({summary.latest_scan.scan_type})</span>
                    </div>
                    <div className="text-[11px] text-slate-400 flex items-center gap-2">
                      <span>Executed: {formatDate(summary.latest_scan.completed_at || summary.latest_scan.started_at)}</span>
                    </div>
                  </div>

                  <div className="h-8 w-px bg-slate-800 hidden sm:block" />

                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] text-slate-400">Latest Run Findings:</span>
                      <span className="font-bold text-rose-400">{summary.latest_scan.scan_findings_count || 0}</span>
                      <span className="text-slate-600">·</span>
                      <span className="text-[11px] text-slate-400">Cumulative Unique:</span>
                      <span className="font-bold text-white">{summary.total_vulnerabilities || 0}</span>
                    </div>
                    <p className="text-[10px] text-slate-500">
                      Scan dossier & asset records synchronized
                    </p>
                  </div>

                  <button
                    onClick={() => navigate(`/scans/${summary.latest_scan.id}`)}
                    className="px-2.5 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-cyan-400 border border-slate-700 text-xs font-mono transition-colors inline-flex items-center gap-1 cursor-pointer whitespace-nowrap self-start sm:self-auto"
                  >
                    <span>Dossier</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                </>
              ) : (
                <div className="flex items-center justify-between gap-4 w-full">
                  <span className="text-slate-400 text-xs">No scan runs recorded for this asset yet.</span>
                  <button
                    onClick={() => navigate('/scans')}
                    className="px-3 py-1.5 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-mono transition-colors"
                  >
                    Run First Scan
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Row 1: KPI Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Card 1: Total Vulnerabilities */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md relative overflow-hidden group hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              {viewMode === 'asset' ? 'Target Findings' : 'Total Vulnerabilities'}
            </span>
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
              {viewMode === 'asset' ? 'Remediation prioritized on target' : 'Immediate remediation required'}
            </p>
          </div>
        </div>

        {/* Card 3: Verified Dangerous Vulns */}
        <div className={`p-5 rounded-xl border backdrop-blur-md relative overflow-hidden group transition-all ${
          (summary?.verified_dangerous_count || 0) > 0
            ? 'border-amber-500/40 bg-gradient-to-b from-amber-950/20 to-slate-950/70 shadow-[0_0_25px_rgba(245,158,11,0.12)]'
            : 'border-slate-800 bg-slate-950/70'
        }`}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-amber-400 font-semibold flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 fill-amber-400/30" />
              <span>Verified Dangerous</span>
            </span>
            <div className="w-8 h-8 rounded-lg bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-amber-400 tracking-tight">
              {loading ? (
                <div className="h-8 w-16 bg-slate-800 animate-pulse rounded" />
              ) : (
                <AnimatedNumber value={summary?.verified_dangerous_count || 0} />
              )}
            </div>
            <p className="text-[11px] text-amber-400/80 mt-1 font-mono">
              Danger &gt; 6.0 (Active Proof)
            </p>
          </div>
        </div>

        {/* Card 4: Assets Monitored OR Target Criticality */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md relative overflow-hidden group hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              {viewMode === 'asset' ? 'Target Criticality' : 'Assets Monitored'}
            </span>
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-white tracking-tight">
              {loading ? (
                <div className="h-8 w-16 bg-slate-800 animate-pulse rounded" />
              ) : viewMode === 'asset' ? (
                <span>Tier {currentAsset?.criticality || summary?.selected_asset?.criticality || '1'}</span>
              ) : (
                <AnimatedNumber value={summary?.total_assets || 0} />
              )}
            </div>
            <p className="text-[11px] text-slate-500 mt-1 font-mono flex items-center gap-1">
              <span>{viewMode === 'asset' ? `${currentAsset?.target_type || 'Node'} target profile` : 'Active infrastructure nodes'}</span>
            </p>
          </div>
        </div>

        {/* Card 5: Scans Run (30d) */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md relative overflow-hidden group hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              {viewMode === 'asset' ? 'Target Scans (30d)' : 'Scans Run (30d)'}
            </span>
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
              <span>{viewMode === 'asset' ? (summary?.latest_scan ? `Latest: Scan #${summary.latest_scan.id}` : 'No scans on target') : 'Automated audit pipelines'}</span>
            </p>
          </div>
        </div>
      </div>

      {/* Row 2: Charts (Severity Donut & 30-Day Trend Area) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Severity Donut Chart (5 cols) */}
        <div className="lg:col-span-5 p-5 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <PieIcon className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
                {viewMode === 'asset' ? 'Target Severity Profile' : 'Severity Distribution'}
              </h2>
            </div>
            <span className="text-xs text-slate-500 font-mono">CVSS v3.1</span>
          </div>

          {loading ? (
            <div className="flex-1 flex items-center justify-center min-h-[260px]">
              <div className="w-36 h-36 rounded-full border-4 border-slate-800 border-t-cyan-500 animate-spin" />
            </div>
          ) : totalInDistribution === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center min-h-[260px] text-slate-500 text-center p-4">
              <ShieldCheck className="w-10 h-10 text-emerald-400/60 mb-2" />
              <p className="text-sm font-medium text-slate-300">No vulnerabilities recorded</p>
              <p className="text-xs text-slate-500 mt-1 max-w-xs">
                {viewMode === 'asset'
                  ? `Target ${currentAsset?.name || 'asset'} has zero recorded findings.`
                  : 'Run a scan to generate severity telemetry.'}
              </p>
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
                  <span className="text-[10px] uppercase font-mono tracking-widest text-slate-500">
                    {viewMode === 'asset' ? 'Target Vulns' : 'Total'}
                  </span>
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
            <span className="text-xs text-slate-500 font-mono">
              {viewMode === 'asset' ? `${currentAsset?.name || 'Target'} Influx` : 'Daily CVE Influx'}
            </span>
          </div>

          {loading ? (
            <div className="flex-1 flex items-center justify-center min-h-[260px]">
              <div className="h-40 w-full bg-slate-900/40 animate-pulse rounded-lg" />
            </div>
          ) : !trendData || trendData.length === 0 || !trendData.some((d) => (d.discovered || d.count || 0) > 0) ? (
            <div className="flex-1 flex flex-col items-center justify-center min-h-[250px] text-center p-6 space-y-3">
              <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-500">
                <TrendingUp className="w-6 h-6 text-slate-500" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-mono text-slate-300 font-medium">
                  No discovery history yet
                </p>
                <p className="text-xs font-mono text-slate-500 max-w-sm">
                  {viewMode === 'asset'
                    ? `No vulnerability discoveries recorded for ${currentAsset?.name || 'this target'} in the last 30 days.`
                    : 'No discovery history yet — run a scan to populate this chart.'}
                </p>
              </div>
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

      {/* Row 3: Risky Assets OR Target Exposure Deep Dive */}
      {viewMode === 'all' ? (
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
      ) : (
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
                Target Threat Exposure & Posture
              </h2>
            </div>
            <span className="text-xs text-slate-400 font-mono">
              Target: <strong className="text-cyan-300">{currentAsset?.name}</strong> ({currentAsset?.ip_address || '—'})
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 block uppercase">Critical CVEs</span>
              <span className="text-xl font-bold font-mono text-rose-400 mt-1 block">
                {severityDist.find(s => s.severity === 'critical')?.count || 0}
              </span>
              <span className="text-[10px] text-slate-500 font-mono">CVSS 9.0 – 10.0</span>
            </div>
            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 block uppercase">High CVEs</span>
              <span className="text-xl font-bold font-mono text-amber-400 mt-1 block">
                {severityDist.find(s => s.severity === 'high')?.count || 0}
              </span>
              <span className="text-[10px] text-slate-500 font-mono">CVSS 7.0 – 8.9</span>
            </div>
            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 block uppercase">Medium CVEs</span>
              <span className="text-xl font-bold font-mono text-yellow-400 mt-1 block">
                {severityDist.find(s => s.severity === 'medium')?.count || 0}
              </span>
              <span className="text-[10px] text-slate-500 font-mono">CVSS 4.0 – 6.9</span>
            </div>
            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
              <div>
                <span className="text-[11px] font-mono text-slate-400 block uppercase">Remediation Status</span>
                <span className="text-xs font-mono text-white mt-1 block">
                  <strong className="text-emerald-400">{summary?.mitigated_vulns || 0}</strong> Mitigated / <strong className="text-slate-300">{summary?.open_vulns || 0}</strong> Open
                </span>
              </div>
              <button
                onClick={() => navigate(selectedAssetId ? `/vulns?asset_id=${selectedAssetId}` : '/vulns')}
                className="mt-2 text-xs font-mono text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 cursor-pointer self-start"
              >
                <span>Browse Target Findings</span>
                <ExternalLink className="w-3 h-3" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Row 4: Top Dangerous Vulnerabilities */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md overflow-hidden">
        <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Flame className="w-4 h-4 text-rose-400 fill-rose-500/30" />
            <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
              {viewMode === 'asset' && currentAsset
                ? `Top Dangerous Vulnerabilities on ${currentAsset.name}`
                : 'Top Dangerous Active Vulnerabilities'}
            </h2>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-rose-500/10 text-rose-400 border border-rose-500/30">
              Composite Danger Engine
            </span>
          </div>
          <button
            onClick={() => navigate(selectedAssetId && viewMode === 'asset' ? `/vulns?asset_id=${selectedAssetId}&sort_by=danger_score&order=desc` : '/vulns?sort_by=danger_score&order=desc')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-mono inline-flex items-center gap-1 cursor-pointer"
          >
            <span>View All Ranked</span>
            <ExternalLink className="w-3 h-3" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead>
              <tr className="border-b border-slate-800/80 bg-slate-950 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                <th className="py-3 px-4">CVE Identifier</th>
                <th className="py-3 px-4">Danger Score</th>
                <th className="py-3 px-4">Verification</th>
                <th className="py-3 px-4">CVSS</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Affected Asset</th>
                <th className="py-3 px-4">Service</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40">
              {loading ? (
                Array.from({ length: 3 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="py-3.5 px-4"><div className="h-4 w-28 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-16 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-24 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-12 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-16 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-32 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-20 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4 text-right"><div className="h-4 w-16 bg-slate-800 rounded ml-auto" /></td>
                  </tr>
                ))
              ) : topDangerousVulns.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-mono text-xs">
                    {viewMode === 'asset'
                      ? `No active high-danger vulnerabilities detected on ${currentAsset?.name || 'this target'}.`
                      : 'No active high-danger vulnerabilities detected. Run a Deep Scan to actively audit targets.'}
                  </td>
                </tr>
              ) : (
                topDangerousVulns.map((v) => (
                  <tr
                    key={v.id}
                    onClick={() => navigate('/vulns')}
                    className="hover:bg-slate-900/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3.5 px-4 font-mono font-bold text-cyan-400 group-hover:text-cyan-300">
                      <div className="flex items-center gap-1.5">
                        <span>{v.cve_id}</span>
                        {v.public_exploit && (
                          <span title="Public exploit code weaponized" className="text-sm">🔥</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <DangerScoreBadge score={v.danger_score} />
                    </td>
                    <td className="py-3.5 px-4">
                      <VerificationBadge verification={v.verification} />
                    </td>
                    <td className="py-3.5 px-4 font-mono font-bold text-white">
                      {Number(v.cvss_score || 0).toFixed(1)}
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
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate('/vulns');
                        }}
                        className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-cyan-400 border border-slate-800 text-xs font-mono transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Row 5: Recent Discoveries Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md overflow-hidden">
        <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
              {viewMode === 'asset' && currentAsset
                ? `Recent Vulnerability Telemetry for ${currentAsset.name}`
                : 'Recent Vulnerability Telemetry'}
            </h2>
          </div>
          <button
            onClick={() => navigate(selectedAssetId && viewMode === 'asset' ? `/vulns?asset_id=${selectedAssetId}` : '/vulns')}
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
                  <td colSpan={7} className="py-10 text-center text-slate-500 font-mono text-xs">
                    {viewMode === 'asset'
                      ? `No vulnerability telemetry recorded for ${currentAsset?.name || 'this target'}. Run a scan to discover findings.`
                      : 'No vulnerability telemetry available. Trigger a scan from the Scans page.'}
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
