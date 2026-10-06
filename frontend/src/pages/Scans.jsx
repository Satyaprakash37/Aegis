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
  AlertCircle
} from 'lucide-react';
import api from '../api/client';
import { ScanStatusBadge } from '../components/Badge';
import Toast from '../components/Toast';

export default function Scans() {
  const navigate = useNavigate();

  // State
  const [scans, setScans] = useState([]);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [toast, setToast] = useState(null);

  // New Scan Form State
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [scanType, setScanType] = useState('quick');

  // Pagination
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const pageSize = 10;

  // Track if polling is active
  const pollIntervalRef = useRef(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

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
    } catch (err) {
      if (!isPolling) {
        showToast(err.response?.data?.detail || 'Failed to fetch scan telemetry', 'error');
      }
    } finally {
      if (!isPolling) setLoading(false);
    }
  }, [page, pageSize]);

  // Initial load
  useEffect(() => {
    fetchAssets();
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  // Live polling for running/pending scans every 5 seconds
  useEffect(() => {
    const hasActiveScans = scans.some(
      (s) => s.status === 'running' || s.status === 'pending'
    );

    if (hasActiveScans) {
      if (!pollIntervalRef.current) {
        pollIntervalRef.current = setInterval(() => {
          fetchScans(true);
        }, 5000);
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

  // Handle Scan Initiation
  const handleStartScan = async (e) => {
    e.preventDefault();
    if (!selectedAssetId) {
      showToast('Please select a target asset first', 'error');
      return;
    }

    setSubmitting(true);
    try {
      const payload = {
        asset_id: parseInt(selectedAssetId, 10),
        scan_type: scanType,
      };

      const res = await api.post('/api/scans', payload);
      showToast(`Scan initiated on ${res.data.asset_name || 'asset'}. Pipeline executing in background.`);
      fetchScans();
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
              Nmap Engine + NVD 2.0
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Launch background port fingerprinting and correlate live CVE intelligence
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
            Nmap Engine + Nuclei v3 Active Verification
          </span>
        </div>

        <form onSubmit={handleStartScan} className="space-y-4">
          {/* Target Asset Dropdown */}
          <div className="max-w-xl">
            <label className="block text-xs font-mono text-slate-400 uppercase tracking-wider mb-1.5">
              Target Infrastructure Asset *
            </label>
            <div className="relative">
              <select
                value={selectedAssetId}
                onChange={(e) => setSelectedAssetId(e.target.value)}
                disabled={submitting || assets.length === 0}
                className="w-full px-3 py-2.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-cyan-500 transition-colors font-mono disabled:opacity-50"
              >
                {assets.length === 0 ? (
                  <option value="">No assets registered. Add assets first.</option>
                ) : (
                  assets.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} — {a.target_type === 'domain' ? `🌐 ${a.ip_address} (IP: ${a.resolved_ip || 'resolved'})` : `🖥️ ${a.ip_address}`} ({a.asset_type})
                    </option>
                  ))
                )}
              </select>
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
                      Deep Active Verification
                    </span>
                    <span className="text-[10px] font-mono text-emerald-400/80 bg-emerald-950/60 border border-emerald-800/40 px-1.5 py-0.5 rounded">Multi-Stage</span>
                  </div>
                  <p className="text-xs text-slate-300 font-sans leading-relaxed">
                    Active verification with Nmap NSE vuln scripts and live Nuclei dynamic exploitation with proof of concept evidence.
                  </p>
                </div>
                <div className="mt-3 pt-2 border-t border-slate-800/60 text-[11px] font-mono text-emerald-300/80 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  <span>Nmap Top 500 + NSE + Nuclei v3</span>
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
                  ? 'Deep scan actively probes for verified exploitability without guessing.' 
                  : scanType === 'full' 
                  ? 'Full scan covers 1,000 standard ports with NVD version matching.' 
                  : 'Quick scan offers fast discovery on top 100 ports.'}
              </span>
            </div>

            <button
              type="submit"
              disabled={submitting || assets.length === 0}
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
                  <span>Start {scanType === 'deep' ? 'Deep Active' : scanType === 'full' ? 'Full' : 'Quick'} Scan</span>
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
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Started</th>
                <th className="py-3 px-4">Completed</th>
                <th className="py-3 px-4 text-center">Vulns Found</th>
                <th className="py-3 px-4 text-right">Actions</th>
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
                scans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="hover:bg-slate-900/40 transition-colors group cursor-pointer"
                    onClick={() => {
                      if (scan.total_vulns_found > 0) {
                        navigate(`/vulns?scan_id=${scan.id}`);
                      }
                    }}
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
                          <span>DEEP ACTIVE</span>
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

                    {/* Status */}
                    <td className="py-3.5 px-4">
                      <ScanStatusBadge status={scan.status} />
                    </td>

                    {/* Started */}
                    <td className="py-3.5 px-4 font-mono text-slate-400 text-[11px]">
                      {formatDate(scan.started_at)}
                    </td>

                    {/* Completed */}
                    <td className="py-3.5 px-4 font-mono text-slate-400 text-[11px]">
                      {formatDate(scan.completed_at)}
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
                      {scan.total_vulns_found > 0 ? (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/vulns?scan_id=${scan.id}`);
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-cyan-400 border border-slate-800 hover:border-cyan-500/40 text-xs font-mono transition-colors"
                        >
                          <span>Findings</span>
                          <ExternalLink className="w-3 h-3" />
                        </button>
                      ) : scan.status === 'completed' ? (
                        <span className="text-slate-500 text-[11px] font-mono">0 Findings</span>
                      ) : scan.status === 'failed' ? (
                        <span className="text-rose-400/80 text-[11px] font-mono flex items-center justify-end gap-1">
                          <AlertCircle className="w-3 h-3" /> Error
                        </span>
                      ) : (
                        <span className="text-cyan-400/80 text-[11px] font-mono animate-pulse">Running</span>
                      )}
                    </td>
                  </tr>
                ))
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
    </div>
  );
}
