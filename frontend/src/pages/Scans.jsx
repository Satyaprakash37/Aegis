import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Activity, 
  Play, 
  RefreshCw, 
  Server, 
  ShieldAlert, 
  Clock, 
  CheckCircle2, 
  XCircle, 
  Zap, 
  Search,
  ExternalLink,
  Terminal,
  AlertCircle,
  Check,
  ChevronDown,
  Crosshair,
  Globe,
  Layers,
  ShieldCheck,
  AlertTriangle,
  Lock,
  X
} from 'lucide-react';
import api from '../api/client';
import { ScanStatusBadge, SeverityBadge, VerificationBadge } from '../components/Badge';
import Toast from '../components/Toast';

export default function Scans() {
  const navigate = useNavigate();

  // State
  const [scans, setScans] = useState([]);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [toast, setToast] = useState(null);

  // New Scan Form State (Direct target input is primary)
  const [targetInput, setTargetInput] = useState('');
  const [isSavedAssetsOpen, setIsSavedAssetsOpen] = useState(false);
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [scanType, setScanType] = useState('quick');

  // Scan Details Drawer State
  const [selectedScan, setSelectedScan] = useState(null);
  const [scanDetails, setScanDetails] = useState(null);
  const [detailsLoading, setDetailsLoading] = useState(false);

  // Pagination
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const pageSize = 10;

  // Track if polling is active
  const pollIntervalRef = useRef(null);

  // Live elapsed timer state (ticks every second when there are active scans)
  const [nowTimestamp, setNowTimestamp] = useState(Date.now());
  useEffect(() => {
    const timer = setInterval(() => {
      setNowTimestamp(Date.now());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  // Helper to normalize and match inputs
  const cleanInput = (raw) => {
    if (!raw) return '';
    let str = raw.trim().toLowerCase();
    str = str.replace(/^[a-zA-Z]+:\/\//, '');
    str = str.split(/[/?#]/)[0];
    if (str.includes(':')) {
      const parts = str.split(':');
      if (parts.length === 2 && !isNaN(parts[1])) str = parts[0];
    }
    return str.trim();
  };

  const cleanedTarget = cleanInput(targetInput);
  const isIpv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(cleanedTarget);
  const isDomain = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(cleanedTarget);
  const isValidFormat = isIpv4 || isDomain;

  const matchedAsset = assets.find((a) => {
    if (!cleanedTarget) return false;
    const aClean = cleanInput(a.ip_address);
    const aRes = a.resolved_ip ? cleanInput(a.resolved_ip) : null;
    const aName = a.name ? a.name.toLowerCase() : null;
    return aClean === cleanedTarget || aRes === cleanedTarget || aName === cleanedTarget;
  });

  // Fetch registered assets for the dropdown
  const fetchAssets = async () => {
    try {
      const res = await api.get('/api/assets', { params: { page: 1, page_size: 100 } });
      const assetList = res.data.data || [];
      setAssets(assetList);
      if (assetList.length > 0 && !selectedAssetId) {
        setSelectedAssetId(assetList[0].id.toString());
      }
    } catch (err) {
      console.error('Failed to load assets for scan initiation:', err);
    }
  };

  // Fetch scans list
  const fetchScans = useCallback(async (isPolling = false) => {
    if (!isPolling) setLoading(true);
    try {
      const res = await api.get('/api/scans', {
        params: { page, page_size: pageSize }
      });
      setScans(res.data.data || []);
      setTotal(res.data.total || 0);

      // If a scan detail is open, keep it in sync
      if (selectedScan) {
        const updated = (res.data.data || []).find(s => s.id === selectedScan.id);
        if (updated) {
          setSelectedScan(updated);
        }
      }
    } catch (err) {
      if (!isPolling) {
        showToast(err.response?.data?.detail || 'Failed to fetch scan telemetry', 'error');
      }
    } finally {
      if (!isPolling) setLoading(false);
    }
  }, [page, pageSize, selectedScan]);

  // Initial load
  useEffect(() => {
    fetchAssets();
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  // Live polling for running/pending scans every 3 seconds
  useEffect(() => {
    const hasActiveScans = scans.some(
      (s) => s.status === 'running' || s.status === 'pending'
    );

    if (hasActiveScans) {
      if (!pollIntervalRef.current) {
        pollIntervalRef.current = setInterval(() => {
          fetchScans(true);
        }, 3000);
      }
    } else {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    }

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    };
  }, [scans, fetchScans]);

  // Open Scan Details
  const handleOpenScanDetails = async (scan) => {
    setSelectedScan(scan);
    setDetailsLoading(true);
    try {
      const res = await api.get(`/api/scans/${scan.id}`);
      setScanDetails(res.data);
    } catch (err) {
      console.error('Failed to load scan details:', err);
      setScanDetails(scan);
    } finally {
      setDetailsLoading(false);
    }
  };

  // Handle Scan Initiation (Direct scan or saved asset scan)
  const handleStartScan = async (e) => {
    e.preventDefault();
    const trimmedTarget = targetInput.trim();
    if (!trimmedTarget && !selectedAssetId) {
      showToast('Please enter a target IP, domain or select a saved asset', 'error');
      return;
    }

    setSubmitting(true);
    try {
      if (trimmedTarget) {
        // Direct scan endpoint: auto-discovers/reuses asset seamlessly
        const res = await api.post('/api/scans/direct', {
          target: trimmedTarget,
          scan_type: scanType,
        });
        const targetLabel = res.data.target || res.data.asset_name || trimmedTarget;
        showToast(`Scan launched on ${targetLabel}`);
      } else {
        const payload = {
          asset_id: parseInt(selectedAssetId, 10),
          scan_type: scanType,
        };
        const res = await api.post('/api/scans', payload);
        showToast(`Scan initiated on ${res.data.asset_name || 'asset'}`);
      }
      fetchScans();
      fetchAssets();
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to launch scan pipeline', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return '—';
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return dateStr;
    }
  };

  const formatElapsed = (startedAt, completedAt = null) => {
    if (!startedAt) return '0s';
    const start = new Date(startedAt).getTime();
    const end = completedAt ? new Date(completedAt).getTime() : nowTimestamp;
    const diffSec = Math.max(0, Math.floor((end - start) / 1000));
    const mins = Math.floor(diffSec / 60);
    const secs = diffSec % 60;
    if (mins === 0) return `${secs}s`;
    return `${mins}m ${secs < 10 ? '0' : ''}${secs}s`;
  };

  // Find currently active running scan if any
  const runningScans = scans.filter((s) => s.status === 'running' || s.status === 'pending');

  return (
    <div className="space-y-6">
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white tracking-wide font-sans">
              Network Vulnerability Scanner
            </h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              Recon Engine + Nmap + Nuclei v3 + testssl.sh
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Real-world reconnaissance, subdomain discovery, active verification & cryptographic audit
          </p>
        </div>

        <button
          onClick={() => fetchScans()}
          className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 font-mono transition-colors self-start sm:self-auto cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
          <span>Refresh Status</span>
        </button>
      </div>

      {/* LIVE PROGRESS BANNER (Visible during active execution) */}
      {runningScans.length > 0 && (
        <div className="p-4 rounded-xl border border-cyan-500/40 bg-gradient-to-r from-slate-950 via-cyan-950/20 to-slate-950 shadow-[0_0_20px_rgba(6,182,212,0.15)] space-y-3">
          {runningScans.map((rScan) => {
            const prog = rScan.progress || {};
            const stageNum = prog.stage_number || 1;
            const totalStages = prog.stages_total || (rScan.scan_type === 'deep' ? 7 : 3);
            const pct = Math.min(100, Math.max(5, Math.round((stageNum / totalStages) * 100)));
            const stageLabel = prog.current_stage || (rScan.status === 'pending' ? 'Queued / Initializing' : 'Executing Scan Probes');
            const detailText = prog.detail || 'Initializing engine processes...';
            const elapsed = formatElapsed(rScan.started_at);

            return (
              <div key={rScan.id} className="space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className="relative flex h-3 w-3">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-500"></span>
                    </span>
                    <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                      Live Scan #{rScan.id}: {rScan.asset_name}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                      {rScan.scan_type.toUpperCase()}
                    </span>
                  </div>

                  <div className="flex items-center gap-4 text-xs font-mono text-slate-300">
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
                      <span>{elapsed} elapsed</span>
                    </div>
                    <span className="text-cyan-400 font-bold">
                      Stage {stageNum} of {totalStages} ({pct}%)
                    </span>
                  </div>
                </div>

                {/* Progress bar */}
                <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-emerald-400 transition-all duration-500 rounded-full"
                    style={{ width: `${pct}%` }}
                  />
                </div>

                {/* Stage Detail narrative */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-[11px] font-mono text-slate-400">
                  <div className="flex items-center gap-2 text-slate-300">
                    <span className="font-semibold text-cyan-300">[{stageLabel}]</span>
                    <span>{detailText}</span>
                  </div>
                  {prog.hosts_total > 0 && (
                    <span className="text-slate-400">
                      Hosts: {prog.hosts_processed || 0} / {prog.hosts_total}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Top Section: Scan Launcher */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
              Initiate Vulnerability Scan
            </h2>
          </div>
          <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/40">
            Nmap Engine + Nuclei v3 + testssl.sh Recon
          </span>
        </div>

        <form onSubmit={handleStartScan} className="space-y-4">
          {/* PRIMARY INPUT: Direct Scan Target */}
          <div className="max-w-2xl space-y-2">
            <div className="flex items-center justify-between">
              <label className="block text-xs font-mono text-slate-300 uppercase tracking-wider font-semibold">
                Scan Target *
              </label>
              {targetInput.trim() && (
                <div className="flex items-center gap-1.5">
                  {isValidFormat ? (
                    <span className="flex items-center gap-1 text-[11px] font-mono font-medium text-emerald-400 bg-emerald-950/50 border border-emerald-800/40 px-2 py-0.5 rounded">
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span>{isIpv4 ? 'Valid IPv4 Host' : 'Valid Domain / URL'}</span>
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-[11px] font-mono text-amber-400/90 bg-amber-950/40 border border-amber-800/40 px-2 py-0.5 rounded">
                      <span>Analyzing target format...</span>
                    </span>
                  )}
                </div>
              )}
            </div>

            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                <Crosshair className="w-4 h-4 text-cyan-400" />
              </div>
              <input
                type="text"
                value={targetInput}
                onChange={(e) => {
                  setTargetInput(e.target.value);
                  if (selectedAssetId) setSelectedAssetId('');
                }}
                placeholder="Enter IP, domain or URL (e.g. 192.168.1.1, example.com, https://site.com)"
                className="w-full pl-10 pr-4 py-3 bg-slate-900 border border-slate-800 rounded-xl text-sm text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50 transition-all shadow-inner"
              />
            </div>

            {/* Hint below input: matched existing asset or format help */}
            {matchedAsset ? (
              <div className="text-xs font-mono text-cyan-400 bg-cyan-950/30 border border-cyan-800/30 px-3 py-1.5 rounded-lg flex items-center gap-2 animate-in fade-in duration-150">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                <span>Existing asset found:</span>
                <strong className="text-white font-semibold">{matchedAsset.name}</strong>
                <span className="text-slate-400">({matchedAsset.ip_address}{matchedAsset.resolved_ip ? ` ↳ ${matchedAsset.resolved_ip}` : ''})</span>
              </div>
            ) : targetInput.trim() && !isValidFormat ? (
              <p className="text-[11px] font-mono text-slate-500 pl-1">
                Enter an IPv4 address (e.g. 192.168.1.1), domain name (e.g. google.com), or URL (https://site.com).
              </p>
            ) : null}

            {/* Collapsible Secondary: Saved Assets Selection */}
            <div className="pt-1">
              <button
                type="button"
                onClick={() => setIsSavedAssetsOpen(!isSavedAssetsOpen)}
                className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-cyan-400 transition-colors cursor-pointer select-none"
              >
                <ChevronDown className={`w-3.5 h-3.5 transform transition-transform duration-150 ${isSavedAssetsOpen ? 'rotate-180' : ''}`} />
                <span>Or select from saved assets ({assets.length})</span>
              </button>

              {isSavedAssetsOpen && (
                <div className="mt-2 p-3 bg-slate-900/60 border border-slate-800/80 rounded-xl space-y-2 animate-in fade-in duration-150">
                  <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                    Select registered inventory asset
                  </label>
                  <select
                    value={selectedAssetId}
                    onChange={(e) => {
                      const id = e.target.value;
                      setSelectedAssetId(id);
                      const found = assets.find(a => a.id.toString() === id);
                      if (found) {
                        setTargetInput(found.ip_address);
                      }
                    }}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-cyan-500 transition-colors font-mono"
                  >
                    <option value="">-- Choose a saved asset --</option>
                    {assets.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name} — {a.target_type === 'domain' ? `🌐 ${a.ip_address} (IP: ${a.resolved_ip || 'resolving'})` : `🖥️ ${a.ip_address}`} ({a.asset_type})
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>
          </div>

          {/* 3 Profile Selection Cards */}
          <div>
            <label className="block text-xs font-mono text-slate-400 uppercase tracking-wider mb-2">
              Select Scan Profile
            </label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {/* Card 1: Quick */}
              <button
                type="button"
                onClick={() => setScanType('quick')}
                className={`p-4 rounded-xl border text-left transition-all cursor-pointer relative flex flex-col justify-between ${
                  scanType === 'quick'
                    ? 'border-cyan-500 bg-cyan-950/20 shadow-[0_0_15px_rgba(6,182,212,0.15)] ring-1 ring-cyan-500/50'
                    : 'border-slate-800 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/60'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-mono font-bold uppercase text-white">Quick Scan</span>
                    <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">~1 min</span>
                  </div>
                  <p className="text-xs text-slate-300 font-sans leading-relaxed">
                    Nmap service fingerprinting on top 100 common ports with NVD version correlation.
                  </p>
                </div>
                <div className="mt-3 pt-2 border-t border-slate-800/60 text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                  <span>-sV --top-ports 100</span>
                </div>
              </button>

              {/* Card 2: Full */}
              <button
                type="button"
                onClick={() => setScanType('full')}
                className={`p-4 rounded-xl border text-left transition-all cursor-pointer relative flex flex-col justify-between ${
                  scanType === 'full'
                    ? 'border-cyan-500 bg-cyan-950/20 shadow-[0_0_15px_rgba(6,182,212,0.15)] ring-1 ring-cyan-500/50'
                    : 'border-slate-800 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/60'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-mono font-bold uppercase text-white">Full Port Scan</span>
                    <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">~2-3 min</span>
                  </div>
                  <p className="text-xs text-slate-300 font-sans leading-relaxed">
                    Deeper port sweep across standard services (ports 1-1000) with CVE intelligence matching.
                  </p>
                </div>
                <div className="mt-3 pt-2 border-t border-slate-800/60 text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                  <span>-sV -p 1-1000</span>
                </div>
              </button>

              {/* Card 3: Deep Active Verification (RECOMMENDED) */}
              <button
                type="button"
                onClick={() => setScanType('deep')}
                className={`p-4 rounded-xl border text-left transition-all cursor-pointer relative flex flex-col justify-between ${
                  scanType === 'deep'
                    ? 'border-emerald-500 bg-emerald-950/20 shadow-[0_0_20px_rgba(16,185,129,0.2)] ring-1 ring-emerald-500/50'
                    : 'border-slate-800 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/60'
                }`}
              >
                <div className="absolute -top-2.5 right-3 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold tracking-wider bg-emerald-500 text-slate-950 shadow-[0_0_10px_rgba(16,185,129,0.4)]">
                  RECOMMENDED
                </div>
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-mono font-bold uppercase text-emerald-400 flex items-center gap-1.5">
                      <Zap className="w-3.5 h-3.5 fill-emerald-400 text-emerald-400" />
                      Deep Recon + Active Verification
                    </span>
                    <span className="text-[10px] font-mono text-emerald-400/80 bg-emerald-950/60 border border-emerald-800/40 px-1.5 py-0.5 rounded">7-Stage Recon</span>
                  </div>
                  <p className="text-xs text-slate-300 font-sans leading-relaxed">
                    Full recon: subdomain discovery, live host probing, technology detection, 3000+ vulnerability checks, SSL/TLS audit (10-30 min)
                  </p>
                </div>
                <div className="mt-3 pt-2 border-t border-slate-800/60 text-[11px] font-mono text-emerald-300/80 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  <span>Subfinder + httpx + Nuclei v3 + testssl.sh</span>
                </div>
              </button>
            </div>
          </div>

          {/* Action Launch Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
            <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
              <Zap className="w-3.5 h-3.5 text-cyan-400" />
              <span>
                {scanType === 'deep' 
                  ? 'Deep scan performs full reconnaissance, active exploit verification, and cryptographic SSL audit.' 
                  : scanType === 'full' 
                  ? 'Full scan covers 1,000 standard ports with NVD version matching.' 
                  : 'Quick scan offers fast discovery on top 100 ports.'}
              </span>
            </div>

            <button
              type="submit"
              disabled={submitting || (!targetInput.trim() && !selectedAssetId)}
              className={`w-full sm:w-auto py-2.5 px-6 rounded-lg font-semibold text-xs font-mono transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer ${
                scanType === 'deep'
                  ? 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-[0_0_15px_rgba(16,185,129,0.3)]'
                  : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-[0_0_15px_rgba(6,182,212,0.25)]'
              }`}
            >
              {submitting ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Launching Pipeline...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Start {scanType === 'deep' ? 'Deep Recon' : scanType === 'full' ? 'Full' : 'Quick'} Scan</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Scan History Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/60 backdrop-blur-md overflow-hidden">
        <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
              Scan Execution History
            </h2>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-900 border border-slate-800 text-slate-400">
              {total} Total Executions
            </span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead>
              <tr className="border-b border-slate-800/80 bg-slate-950 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                <th className="py-3 px-4">Target Asset</th>
                <th className="py-3 px-4">Scan Type</th>
                <th className="py-3 px-4">Status & Progress</th>
                <th className="py-3 px-4">Started</th>
                <th className="py-3 px-4">Duration</th>
                <th className="py-3 px-4 text-center">Vulns Found</th>
                <th className="py-3 px-4 text-right">Details & Findings</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40">
              {loading ? (
                Array.from({ length: 4 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="py-3.5 px-4"><div className="h-4 w-32 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-16 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-20 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-24 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-24 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4 text-center"><div className="h-4 w-8 bg-slate-800 rounded mx-auto" /></td>
                    <td className="py-3.5 px-4 text-right"><div className="h-4 w-16 bg-slate-800 rounded ml-auto" /></td>
                  </tr>
                ))
              ) : scans.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    <Activity className="w-8 h-8 mx-auto mb-2 text-slate-600 opacity-50" />
                    <p className="font-medium text-slate-400">No scans executed yet</p>
                    <p className="text-xs text-slate-600 mt-0.5">
                      Select an asset above and click 'Start Scan' to trigger port discovery
                    </p>
                  </td>
                </tr>
              ) : (
                scans.map((scan) => {
                  const isRunning = scan.status === 'running';
                  const prog = scan.progress || {};
                  const stageNum = prog.stage_number || 1;
                  const totalStages = prog.stages_total || (scan.scan_type === 'deep' ? 7 : 3);
                  const pct = Math.min(100, Math.max(5, Math.round((stageNum / totalStages) * 100)));

                  return (
                    <tr
                      key={scan.id}
                      className="hover:bg-slate-900/40 transition-colors group cursor-pointer"
                      onClick={() => handleOpenScanDetails(scan)}
                    >
                      {/* Target Asset */}
                      <td className="py-3.5 px-4">
                        <div className="font-medium text-white font-mono flex items-center gap-2 flex-wrap">
                          <span>{scan.asset_name}</span>
                          {scan.asset_ip && (
                            <span className="text-[11px] text-cyan-300 bg-cyan-950/40 px-1.5 py-0.5 rounded border border-cyan-800/30 flex items-center gap-1">
                              {scan.target_type === 'domain' ? <span>🌐</span> : <span>🖥️</span>}
                              <span>{scan.asset_ip}</span>
                            </span>
                          )}
                          {scan.target_type === 'domain' && scan.resolved_ip && (
                            <span className="text-[10px] font-mono text-slate-400">
                              ↳ {scan.resolved_ip}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Scan Type */}
                      <td className="py-3.5 px-4 font-mono text-xs">
                        {scan.scan_type === 'deep' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 shadow-[0_0_8px_rgba(16,185,129,0.15)]">
                            <Zap className="w-3 h-3 fill-emerald-400 text-emerald-400" />
                            <span>DEEP RECON</span>
                          </span>
                        ) : scan.scan_type === 'full' ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-blue-500/10 text-blue-300 border border-blue-500/20">
                            FULL (1-1000)
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-slate-800 text-slate-300 border border-slate-700">
                            QUICK
                          </span>
                        )}
                      </td>

                      {/* Status & Inline Progress */}
                      <td className="py-3.5 px-4 min-w-[150px]">
                        {isRunning ? (
                          <div className="space-y-1">
                            <div className="flex items-center justify-between text-[10px] font-mono">
                              <span className="text-cyan-400 font-semibold flex items-center gap-1">
                                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                                {prog.current_stage ? `${prog.current_stage.slice(0, 18)}...` : 'Running...'}
                              </span>
                              <span className="text-slate-400">{pct}%</span>
                            </div>
                            <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                              <div
                                className="h-full bg-cyan-400 transition-all duration-300 rounded-full"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                        ) : (
                          <ScanStatusBadge status={scan.status} />
                        )}
                      </td>

                      {/* Started */}
                      <td className="py-3.5 px-4 font-mono text-slate-400 text-[11px]">
                        {formatDate(scan.started_at)}
                      </td>

                      {/* Duration */}
                      <td className="py-3.5 px-4 font-mono text-slate-300 text-[11px]">
                        {formatElapsed(scan.started_at, scan.completed_at)}
                      </td>

                      {/* Vulns Found */}
                      <td className="py-3.5 px-4 text-center">
                        <span
                          className={`inline-flex items-center justify-center px-2 py-0.5 rounded-full text-[11px] font-mono font-bold ${
                            scan.total_vulns_found > 0
                              ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                              : 'bg-slate-900 text-slate-500 border border-slate-800'
                          }`}
                        >
                          {scan.total_vulns_found}
                        </span>
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleOpenScanDetails(scan);
                            }}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 text-xs font-mono transition-colors"
                          >
                            <span>Summary</span>
                          </button>
                          {scan.total_vulns_found > 0 && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                navigate(`/vulns?scan_id=${scan.id}`);
                              }}
                              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-950/40 hover:bg-cyan-900/60 text-cyan-400 border border-cyan-800/40 text-xs font-mono transition-colors"
                            >
                              <span>Findings</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="p-4 border-t border-slate-800/80 bg-slate-950 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400 font-mono">
          <div>
            Showing{' '}
            <span className="text-white font-medium">
              {total === 0 ? 0 : (page - 1) * pageSize + 1}
            </span>{' '}
            to{' '}
            <span className="text-white font-medium">
              {Math.min(page * pageSize, total)}
            </span>{' '}
            of <span className="text-white font-medium">{total}</span> scans
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800 transition-colors"
            >
              Previous
            </button>
            <span className="px-2 text-slate-400">
              Page {page} of {Math.max(1, Math.ceil(total / pageSize))}
            </span>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={page * pageSize >= total}
              className="px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800 transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* SCAN DETAILS & RECONNAISSANCE SUMMARY MODAL */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="relative w-full max-w-4xl max-h-[90vh] bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-cyan-950/60 border border-cyan-800/50 flex items-center justify-center text-cyan-400">
                  <Activity className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-white font-mono">
                      Scan Execution Dossier #{selectedScan.id}
                    </h3>
                    <ScanStatusBadge status={selectedScan.status} />
                  </div>
                  <p className="text-xs font-mono text-slate-400 mt-0.5">
                    Target: <span className="text-white font-semibold">{selectedScan.asset_name}</span>
                    {selectedScan.asset_ip ? ` (${selectedScan.asset_ip})` : ''}
                    {selectedScan.resolved_ip ? ` ↳ ${selectedScan.resolved_ip}` : ''}
                  </p>
                </div>
              </div>

              <button
                onClick={() => {
                  setSelectedScan(null);
                  setScanDetails(null);
                }}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Scrollable Body */}
            <div className="p-6 space-y-6 overflow-y-auto">
              {detailsLoading ? (
                <div className="py-16 text-center text-slate-500 space-y-2">
                  <RefreshCw className="w-6 h-6 animate-spin mx-auto text-cyan-400" />
                  <p className="text-xs font-mono">Loading telemetry and reconnaissance data...</p>
                </div>
              ) : (
                <>
                  {/* High Level Metrics Cards */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800">
                      <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                        Total Findings
                      </span>
                      <div className="text-xl font-bold font-mono text-white flex items-center gap-2">
                        <span>{selectedScan.total_vulns_found}</span>
                        {selectedScan.total_vulns_found > 0 && (
                          <span className="text-xs text-rose-400 font-normal">vulnerabilities</span>
                        )}
                      </div>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800">
                      <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                        Scan Profile
                      </span>
                      <div className="text-sm font-bold font-mono text-cyan-400 uppercase">
                        {selectedScan.scan_type}
                      </div>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800">
                      <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                        Duration
                      </span>
                      <div className="text-sm font-bold font-mono text-slate-200">
                        {formatElapsed(selectedScan.started_at, selectedScan.completed_at)}
                      </div>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800">
                      <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                        Completed At
                      </span>
                      <div className="text-xs font-mono text-slate-300">
                        {selectedScan.completed_at ? formatDate(selectedScan.completed_at) : 'In Progress...'}
                      </div>
                    </div>
                  </div>

                  {/* Verification Breakdown Section */}
                  {scanDetails?.verification_breakdown && (
                    <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800/80 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                          <ShieldCheck className="w-4 h-4 text-emerald-400" />
                          Verification Type Breakdown
                        </span>
                        <span className="text-[11px] font-mono text-slate-400">
                          Proof of Concept & Evidence Engine
                        </span>
                      </div>

                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                        <div className="p-2.5 rounded-lg bg-blue-950/20 border border-blue-800/30 flex items-center justify-between">
                          <span className="text-xs font-mono text-blue-300 flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-blue-400" />
                            Nuclei
                          </span>
                          <span className="text-xs font-bold font-mono text-white">
                            {scanDetails.verification_breakdown.nuclei_verified || 0}
                          </span>
                        </div>

                        <div className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-800/30 flex items-center justify-between">
                          <span className="text-xs font-mono text-emerald-300 flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-emerald-400" />
                            NSE Script
                          </span>
                          <span className="text-xs font-bold font-mono text-white">
                            {scanDetails.verification_breakdown.nse_verified || 0}
                          </span>
                        </div>

                        <div className="p-2.5 rounded-lg bg-purple-950/20 border border-purple-800/30 flex items-center justify-between">
                          <span className="text-xs font-mono text-purple-300 flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-purple-400" />
                            SSL Audit
                          </span>
                          <span className="text-xs font-bold font-mono text-white">
                            {scanDetails.verification_breakdown.ssl_verified || 0}
                          </span>
                        </div>

                        <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
                          <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-slate-500" />
                            Version Match
                          </span>
                          <span className="text-xs font-bold font-mono text-white">
                            {scanDetails.verification_breakdown.version_match || 0}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* RECONNAISSANCE SUMMARY SECTION */}
                  {scanDetails?.raw_output?.recon ? (
                    <div className="p-5 rounded-xl bg-slate-900/60 border border-cyan-800/40 space-y-4">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                        <div className="flex items-center gap-2">
                          <Globe className="w-4 h-4 text-cyan-400" />
                          <h4 className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                            Reconnaissance Summary
                          </h4>
                        </div>

                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-950/60 text-cyan-300 border border-cyan-800/40">
                            {scanDetails.raw_output.recon.subdomains_found || 0} Subdomains Discovered
                          </span>
                          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
                            {scanDetails.raw_output.recon.live_hosts_found || 0} Live Targets Probed
                          </span>
                          {scanDetails.raw_output.recon.cdn_detected ? (
                            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-amber-950/60 text-amber-300 border border-amber-800/40 flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3 text-amber-400" />
                              <span>CDN: {scanDetails.raw_output.recon.cdn_name || 'Protected'}</span>
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                              Origin Direct (No CDN)
                            </span>
                          )}
                        </div>
                      </div>

                      {/* CDN Warning banner if detected */}
                      {scanDetails.raw_output.recon.cdn_detected && (
                        <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-800/40 text-xs font-sans text-amber-200 flex items-start gap-2.5">
                          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                          <div>
                            <span className="font-semibold font-mono text-amber-300">CDN Edge Detected: </span>
                            Target apex resolves to an edge proxy network ({scanDetails.raw_output.recon.cdn_name || 'Cloudflare/CloudFront'}). Recon engine mapped subdomains and probed virtual hosts directly to bypass CDN obfuscation.
                          </div>
                        </div>
                      )}

                      {/* Live Hosts Table */}
                      <div className="space-y-2">
                        <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                          <span className="uppercase tracking-wider font-semibold">Probed Web Endpoints & Tech Stacks</span>
                          <span>{scanDetails.raw_output.recon.live_hosts?.length || 0} Active Services</span>
                        </div>

                        {scanDetails.raw_output.recon.live_hosts?.length > 0 ? (
                          <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950">
                            <table className="w-full text-left text-xs font-mono">
                              <thead>
                                <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 text-[11px]">
                                  <th className="py-2.5 px-3">Target Endpoint</th>
                                  <th className="py-2.5 px-3">Page Title</th>
                                  <th className="py-2.5 px-3">Detected Technologies</th>
                                  <th className="py-2.5 px-3">Resolved IP</th>
                                  <th className="py-2.5 px-3 text-right">CDN Edge</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-slate-800/50">
                                {scanDetails.raw_output.recon.live_hosts.map((host, idx) => (
                                  <tr key={idx} className="hover:bg-slate-900/30">
                                    <td className="py-2.5 px-3 font-semibold text-cyan-300 truncate max-w-[200px]" title={host.url}>
                                      {host.url}
                                    </td>
                                    <td className="py-2.5 px-3 text-slate-300 truncate max-w-[180px]" title={host.title || 'N/A'}>
                                      {host.title || '—'}
                                    </td>
                                    <td className="py-2.5 px-3">
                                      {host.tech && host.tech.length > 0 ? (
                                        <div className="flex flex-wrap gap-1">
                                          {host.tech.map((t, ti) => (
                                            <span key={ti} className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                                              {t}
                                            </span>
                                          ))}
                                        </div>
                                      ) : (
                                        <span className="text-slate-500">—</span>
                                      )}
                                    </td>
                                    <td className="py-2.5 px-3 text-slate-400">
                                      {host.ip || '—'}
                                    </td>
                                    <td className="py-2.5 px-3 text-right">
                                      {host.cdn ? (
                                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/20">
                                          {host.cdn}
                                        </span>
                                      ) : (
                                        <span className="text-slate-500 text-[10px]">No</span>
                                      )}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <p className="text-xs font-mono text-slate-500 py-2">
                            No live web endpoints responded during probing.
                          </p>
                        )}
                      </div>

                      {/* Discovered Subdomains List (if any) */}
                      {scanDetails.raw_output.recon.subdomains?.length > 0 && (
                        <div className="space-y-1.5 pt-2 border-t border-slate-800/80">
                          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block font-semibold">
                            Discovered Subdomains ({scanDetails.raw_output.recon.subdomains.length})
                          </span>
                          <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto p-2 bg-slate-950 border border-slate-800 rounded-lg">
                            {scanDetails.raw_output.recon.subdomains.map((sub, i) => (
                              <span key={i} className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-slate-300 border border-slate-800">
                                {sub}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="p-4 rounded-xl bg-slate-900/30 border border-slate-800/80 text-xs font-mono text-slate-400 flex items-center gap-2">
                      <Layers className="w-4 h-4 text-slate-500" />
                      <span>
                        Reconnaissance data (subdomains, live web probing, CDN detection & testssl cryptographic audit) is gathered when executing Deep Recon scans.
                      </span>
                    </div>
                  )}
                </>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex items-center justify-between">
              <button
                onClick={() => {
                  setSelectedScan(null);
                  setScanDetails(null);
                }}
                className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-mono border border-slate-800 transition-colors cursor-pointer"
              >
                Close Dossier
              </button>

              {selectedScan.total_vulns_found > 0 && (
                <button
                  onClick={() => {
                    const sid = selectedScan.id;
                    setSelectedScan(null);
                    setScanDetails(null);
                    navigate(`/vulns?scan_id=${sid}`);
                  }}
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono transition-colors flex items-center gap-1.5 cursor-pointer shadow-[0_0_12px_rgba(6,182,212,0.25)]"
                >
                  <span>Explore All {selectedScan.total_vulns_found} Vulnerability Findings</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
