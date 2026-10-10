import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  X, 
  ExternalLink, 
  Info, 
  Server, 
  Calendar, 
  ShieldCheck, 
  FileCode,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  RefreshCw,
  Cpu,
  Layers,
  CheckCircle2,
  Flame,
  Zap,
  Terminal,
  AlertTriangle
} from 'lucide-react';
import api from '../api/client';
import { 
  SeverityBadge, 
  VulnStatusBadge, 
  RiskTierBadge,
  VerificationBadge,
  DangerScoreBadge 
} from '../components/Badge';
import Toast from '../components/Toast';

export default function Vulnerabilities() {
  const [searchParams, setSearchParams] = useSearchParams();
  const scanIdParam = searchParams.get('scan_id');

  // State
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [recalculating, setRecalculating] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [toast, setToast] = useState(null);

  // Filters & Sorting
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [verificationFilter, setVerificationFilter] = useState('');
  const [minDangerFilter, setMinDangerFilter] = useState('');
  const [sortBy, setSortBy] = useState('risk_score');
  const [order, setOrder] = useState('desc');

  // Pagination
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const pageSize = 15;

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const fetchVulns = useCallback(async () => {
    setLoading(true);
    try {
      const params = {
        page,
        page_size: pageSize,
        sort_by: sortBy,
        order,
      };
      if (search) params.search = search;
      if (severityFilter) params.severity = severityFilter;
      if (statusFilter) params.status = statusFilter;
      if (verificationFilter) params.verification = verificationFilter;
      if (minDangerFilter) params.min_danger = parseFloat(minDangerFilter);
      if (scanIdParam) params.scan_id = parseInt(scanIdParam, 10);

      const res = await api.get('/api/vulns', { params });
      setVulns(res.data.data || []);
      setTotal(res.data.total || 0);
    } catch (err) {
      console.error('Failed to load vulnerabilities:', err);
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, search, severityFilter, statusFilter, verificationFilter, minDangerFilter, scanIdParam, sortBy, order]);

  useEffect(() => {
    fetchVulns();
  }, [fetchVulns]);

  // Handle Sort Toggle
  const handleSort = (field) => {
    if (sortBy === field) {
      setOrder(order === 'desc' ? 'asc' : 'desc');
    } else {
      setSortBy(field);
      setOrder('desc');
    }
    setPage(1);
  };

  // Inline Status Change Handler
  const handleStatusChange = async (vulnId, newStatus, e) => {
    e.stopPropagation();
    try {
      const res = await api.patch(`/api/vulns/${vulnId}/status`, { status: newStatus });
      setVulns((prev) =>
        prev.map((v) => (v.id === vulnId ? { ...v, status: res.data.status } : v))
      );
      if (selectedVuln && selectedVuln.id === vulnId) {
        setSelectedVuln((prev) => ({ ...prev, status: res.data.status }));
      }
      showToast(`Vulnerability status updated to ${newStatus}`);
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to update vulnerability status', 'error');
    }
  };

  // Recalculate Risk Scores (Admin)
  const handleRecalculateRisk = async () => {
    setRecalculating(true);
    try {
      const res = await api.post('/api/vulns/recalculate-risk');
      showToast(res.data.message || 'Risk scores recalculated successfully');
      fetchVulns();
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to recalculate risk scores', 'error');
    } finally {
      setRecalculating(false);
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return '—';
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
      });
    } catch {
      return dateStr;
    }
  };

  const renderSortIcon = (field) => {
    if (sortBy !== field) {
      return <ArrowUpDown className="w-3 h-3 text-slate-500 opacity-60" />;
    }
    return order === 'desc' ? (
      <ArrowDown className="w-3 h-3 text-cyan-400" />
    ) : (
      <ArrowUp className="w-3 h-3 text-cyan-400" />
    );
  };

  return (
    <div className="space-y-6">
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white tracking-wide font-sans">
              Identified Vulnerabilities
            </h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-rose-500/10 text-rose-400 border border-rose-500/30">
              {total} CVE Findings
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Prioritized by Contextual Risk Engine (CVSS 60% + Asset Criticality 40%)
          </p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          {scanIdParam && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-950/40 border border-cyan-800/40 text-xs font-mono text-cyan-300">
              <span>Filter: Scan #{scanIdParam}</span>
              <button
                onClick={() => {
                  searchParams.delete('scan_id');
                  setSearchParams(searchParams);
                }}
                className="text-cyan-400 hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          <button
            onClick={handleRecalculateRisk}
            disabled={recalculating}
            title="Recalculate contextual risk scores for all vulnerabilities"
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 font-mono transition-colors disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${recalculating ? 'animate-spin' : ''}`} />
            <span>Recalculate Risk</span>
          </button>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 backdrop-blur-md flex flex-col md:flex-row items-stretch md:items-center gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
          <input
            type="text"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Search by CVE ID, title, or service..."
            className="w-full pl-10 pr-9 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors font-sans"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Severity Filter */}
        <select
          value={severityFilter}
          onChange={(e) => {
            setSeverityFilter(e.target.value);
            setPage(1);
          }}
          className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical (9.0 - 10.0)</option>
          <option value="high">High (7.0 - 8.9)</option>
          <option value="medium">Medium (4.0 - 6.9)</option>
          <option value="low">Low (0.1 - 3.9)</option>
        </select>

        {/* Verification Filter */}
        <select
          value={verificationFilter}
          onChange={(e) => {
            setVerificationFilter(e.target.value);
            setPage(1);
          }}
          className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
        >
          <option value="">All Verifications</option>
          <option value="nuclei_verified">Nuclei Verified (Active)</option>
          <option value="nse_verified">NSE Verified (Active)</option>
          <option value="ssl_verified">SSL Audit (Active)</option>
          <option value="version_match">Version Match</option>
        </select>

        {/* Min Danger Filter */}
        <select
          value={minDangerFilter}
          onChange={(e) => {
            setMinDangerFilter(e.target.value);
            setPage(1);
          }}
          className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
        >
          <option value="">All Danger Levels</option>
          <option value="8.0">Critical Danger (≥ 8.0)</option>
          <option value="6.0">High Danger (≥ 6.0)</option>
          <option value="4.0">Medium Danger (≥ 4.0)</option>
        </select>

        {/* Status Filter */}
        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(1);
          }}
          className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="mitigated">Mitigated</option>
          <option value="false_positive">False Positive</option>
        </select>
      </div>

      {/* Vulnerabilities Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/60 backdrop-blur-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead>
              <tr className="border-b border-slate-800/80 bg-slate-950 text-slate-400 font-mono text-[11px] uppercase tracking-wider select-none">
                <th className="py-3 px-4">CVE ID</th>
                <th className="py-3 px-4">Verification</th>
                <th 
                  className="py-3 px-4 cursor-pointer hover:text-slate-200 transition-colors"
                  onClick={() => handleSort('danger_score')}
                >
                  <div className="flex items-center gap-1.5">
                    <span>Danger</span>
                    {renderSortIcon('danger_score')}
                  </div>
                </th>
                <th 
                  className="py-3 px-4 cursor-pointer hover:text-slate-200 transition-colors"
                  onClick={() => handleSort('risk_score')}
                >
                  <div className="flex items-center gap-1.5">
                    <span>Risk Score</span>
                    {renderSortIcon('risk_score')}
                  </div>
                </th>
                <th 
                  className="py-3 px-4 cursor-pointer hover:text-slate-200 transition-colors"
                  onClick={() => handleSort('cvss_score')}
                >
                  <div className="flex items-center gap-1.5">
                    <span>CVSS</span>
                    {renderSortIcon('cvss_score')}
                  </div>
                </th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Target Asset</th>
                <th className="py-3 px-4">Service / Port</th>
                <th className="py-3 px-4">Status</th>
                <th 
                  className="py-3 px-4 cursor-pointer hover:text-slate-200 transition-colors"
                  onClick={() => handleSort('first_seen_at')}
                >
                  <div className="flex items-center gap-1.5">
                    <span>Discovered</span>
                    {renderSortIcon('first_seen_at')}
                  </div>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40">
              {loading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="py-3.5 px-4"><div className="h-4 w-28 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-24 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-16 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-24 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-12 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-20 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-32 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-24 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-24 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-20 bg-slate-800 rounded" /></td>
                  </tr>
                ))
              ) : vulns.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-12 text-center text-slate-500">
                    <ShieldAlert className="w-8 h-8 mx-auto mb-2 text-slate-600 opacity-50" />
                    <p className="font-medium text-slate-400">No vulnerabilities recorded</p>
                    <p className="text-xs text-slate-600 mt-0.5">
                      {scanIdParam ? 'This scan discovered no matching CVEs.' : 'Execute a network scan to identify CVEs.'}
                    </p>
                  </td>
                </tr>
              ) : (
                vulns.map((v) => (
                  <tr
                    key={v.id}
                    onClick={() => setSelectedVuln(v)}
                    className="hover:bg-slate-900/40 transition-colors cursor-pointer group"
                  >
                    {/* CVE ID */}
                    <td className="py-3.5 px-4 font-mono font-bold text-cyan-400 group-hover:text-cyan-300 whitespace-nowrap">
                      <div className="flex items-center gap-1.5 whitespace-nowrap">
                        <span>{v.cve_id}</span>
                        {v.public_exploit && (
                          <span title="Known public exploit available in the wild" className="text-sm cursor-help">
                            🔥
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Verification */}
                    <td className="py-3.5 px-4">
                      <VerificationBadge
                        verification={v.verification}
                        isOriginDirect={v.is_origin_direct || (v.evidence && v.evidence.includes('[ORIGIN CONFIG AUDIT]'))}
                      />
                    </td>

                    {/* Danger Score */}
                    <td className="py-3.5 px-4">
                      <DangerScoreBadge score={v.danger_score} />
                    </td>

                    {/* Contextual Risk Score */}
                    <td className="py-3.5 px-4">
                      <RiskTierBadge tier={v.risk_tier} score={v.risk_score} />
                    </td>

                    {/* CVSS Score */}
                    <td className="py-3.5 px-4 font-mono font-bold text-white">
                      {Number(v.cvss_score || 0).toFixed(1)}
                    </td>

                    {/* Severity */}
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={v.severity} />
                    </td>

                    {/* Target Asset */}
                    <td className="py-3.5 px-4">
                      <div className="font-medium text-slate-200 font-mono">
                        {v.asset_name}
                      </div>
                      {v.asset_ip && (
                        <div className="text-[11px] text-slate-500 font-mono">
                          {v.asset_ip} (Crit: {v.asset_criticality || 3})
                        </div>
                      )}
                    </td>

                    {/* Service / Port */}
                    <td className="py-3.5 px-4 font-mono text-slate-300">
                      {v.service || 'Service'}{' '}
                      {v.port ? (
                        <span className="text-slate-500">:{v.port}</span>
                      ) : null}
                      {v.service_version && (
                        <div className="text-[11px] text-slate-500 font-sans truncate max-w-[140px]">
                          v{v.service_version}
                        </div>
                      )}
                    </td>

                    {/* Inline Status Dropdown */}
                    <td className="py-3.5 px-4" onClick={(e) => e.stopPropagation()}>
                      <select
                        value={v.status}
                        onChange={(e) => handleStatusChange(v.id, e.target.value, e)}
                        className={`px-2 py-1 rounded text-xs font-mono font-medium border bg-slate-900 focus:outline-none focus:border-cyan-500 transition-colors cursor-pointer ${
                          v.status === 'open'
                            ? 'text-rose-400 border-rose-500/30'
                            : v.status === 'in_progress'
                            ? 'text-amber-400 border-amber-500/30'
                            : v.status === 'mitigated'
                            ? 'text-emerald-400 border-emerald-500/30'
                            : 'text-slate-400 border-slate-500/30'
                        }`}
                      >
                        <option value="open">Open</option>
                        <option value="in_progress">In Progress</option>
                        <option value="mitigated">Mitigated</option>
                        <option value="false_positive">False Positive</option>
                      </select>
                    </td>

                    {/* First Seen */}
                    <td className="py-3.5 px-4 font-mono text-slate-400 text-[11px]">
                      {formatDate(v.first_seen_at)}
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
            of <span className="text-white font-medium">{total}</span> findings
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

      {/* Vulnerability Detail Drawer / Modal */}
      {selectedVuln && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[88vh]">
            {/* Header */}
            <div className="p-5 border-b border-slate-800 flex items-start justify-between gap-4 bg-slate-950/80">
              <div>
                <div className="flex flex-wrap items-center gap-2.5">
                  <h3 className="text-lg font-bold text-white font-mono flex items-center gap-1.5">
                    <span>{selectedVuln.cve_id}</span>
                    {selectedVuln.public_exploit && (
                      <span title="Known public exploit available in the wild" className="text-sm">🔥</span>
                    )}
                  </h3>
                  <SeverityBadge severity={selectedVuln.severity} />
                  <VerificationBadge
                    verification={selectedVuln.verification}
                    isOriginDirect={selectedVuln.is_origin_direct || (selectedVuln.evidence && selectedVuln.evidence.includes('[ORIGIN CONFIG AUDIT]'))}
                  />
                  <VulnStatusBadge status={selectedVuln.status} />
                  {selectedVuln.public_exploit && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">
                      Public Exploit Available
                    </span>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-3 mt-2 text-xs font-mono text-slate-400">
                  <span>
                    Danger Score:{' '}
                    <span className="text-rose-400 font-bold">
                      {selectedVuln.danger_score != null ? Number(selectedVuln.danger_score).toFixed(2) : 'N/A'}
                    </span>
                  </span>
                  <span>·</span>
                  <span>
                    Contextual Risk: <span className="text-cyan-400 font-bold">{Number(selectedVuln.risk_score || 0).toFixed(2)}</span>
                  </span>
                  <span>·</span>
                  <span>
                    Base CVSS: <span className="text-white font-bold">{Number(selectedVuln.cvss_score || 0).toFixed(1)}</span>
                  </span>
                </div>
              </div>

              <button
                onClick={() => setSelectedVuln(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Body */}
            <div className="p-6 space-y-5 overflow-y-auto">
              {/* Danger Assessment Engine Card */}
              <div className="p-4 rounded-xl bg-gradient-to-b from-rose-950/20 via-slate-950 to-slate-950 border border-rose-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs font-mono font-semibold text-rose-300 uppercase tracking-wider">
                    <Flame className="w-4 h-4 text-rose-400 fill-rose-500/30" />
                    <span>Danger Assessment Engine (CVSS 40% + Exploit 35% + Impact 25%)</span>
                  </div>
                  <DangerScoreBadge score={selectedVuln.danger_score} showBar={false} />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800">
                    <span className="text-slate-400 font-mono uppercase text-[10px] block mb-1 flex items-center gap-1 font-semibold">
                      <Zap className="w-3 h-3 text-amber-400" />
                      Exploitability Assessment
                    </span>
                    <p className="text-slate-300 font-sans leading-relaxed text-[11px]">
                      {selectedVuln.exploitability || "Identified via banner correlation. No active exploitation confirmed."}
                    </p>
                    {selectedVuln.public_exploit && (
                      <div className="mt-2 text-[10px] font-mono text-rose-400 flex items-center gap-1 font-semibold">
                        <span>🔥 Public exploit weaponization verified</span>
                      </div>
                    )}
                  </div>

                  <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800">
                    <span className="text-slate-400 font-mono uppercase text-[10px] block mb-1 flex items-center gap-1 font-semibold">
                      <AlertTriangle className="w-3 h-3 text-rose-400" />
                      Impact & Blast Radius
                    </span>
                    <p className="text-slate-300 font-sans leading-relaxed text-[11px]">
                      {selectedVuln.impact || "Standard system security boundary impact."}
                    </p>
                  </div>
                </div>
              </div>

              {/* Active Verification Evidence & Proof */}
              <div>
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-1.5 flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Active Verification Evidence & Raw Output</span>
                  </div>
                  <VerificationBadge
                    verification={selectedVuln.verification}
                    isOriginDirect={selectedVuln.is_origin_direct || (selectedVuln.evidence && selectedVuln.evidence.includes('[ORIGIN CONFIG AUDIT]'))}
                  />
                </h4>
                {selectedVuln.evidence ? (
                  <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
                    <pre className="text-emerald-400 font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed select-text font-medium">
                      <code>{selectedVuln.evidence}</code>
                    </pre>
                  </div>
                ) : (
                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs text-slate-500 font-sans leading-relaxed">
                    No active dynamic evidence payload captured. This finding was matched from service version headers. Run a <span className="text-emerald-400 font-mono font-medium">Deep Scan</span> on this asset to execute active verification.
                  </div>
                )}
              </div>

              {/* Risk Score Calculation Breakdown Card */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs font-mono font-semibold text-white uppercase tracking-wider">
                    <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Contextual Risk Engine Breakdown</span>
                  </div>
                  <RiskTierBadge tier={selectedVuln.risk_tier} score={selectedVuln.risk_score} />
                </div>

                <div className="grid grid-cols-3 gap-3 text-center font-mono">
                  <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/60">
                    <span className="text-[10px] text-slate-400 uppercase block mb-1">CVSS Component (60%)</span>
                    <span className="text-sm font-bold text-white">
                      {(selectedVuln.cvss_score * 0.6).toFixed(2)}
                    </span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">({selectedVuln.cvss_score.toFixed(1)} × 0.6)</span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/60">
                    <span className="text-[10px] text-slate-400 uppercase block mb-1">Asset Weight (40%)</span>
                    <span className="text-sm font-bold text-white">
                      {(((selectedVuln.asset_criticality || 3) / 5.0 * 10.0) * 0.4).toFixed(2)}
                    </span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">(Crit {selectedVuln.asset_criticality || 3}/5 × 10 × 0.4)</span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-cyan-950/30 border border-cyan-800/40">
                    <span className="text-[10px] text-cyan-400 uppercase block mb-1 font-semibold">Total Risk Score</span>
                    <span className="text-sm font-bold text-cyan-300">
                      {selectedVuln.risk_score.toFixed(2)}
                    </span>
                    <span className="text-[10px] text-cyan-500 block mt-0.5 uppercase font-semibold">{selectedVuln.risk_tier}</span>
                  </div>
                </div>
              </div>

              {/* Asset and Port Info Cards */}
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 font-mono uppercase text-[10px] block mb-1">
                    Affected Target Asset
                  </span>
                  <div className="text-slate-200 font-mono font-medium">
                    {selectedVuln.asset_name}
                  </div>
                  <div className="text-slate-400 font-mono text-[11px]">
                    {selectedVuln.asset_ip} · Criticality {selectedVuln.asset_criticality || 3}/5
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 font-mono uppercase text-[10px] block mb-1">
                    Port & Service Fingerprint
                  </span>
                  <div className="text-slate-200 font-mono font-medium">
                    {selectedVuln.service || 'Service'} (Port {selectedVuln.port || 'N/A'})
                  </div>
                  <div className="text-slate-400 font-mono text-[11px]">
                    {selectedVuln.service_version ? `Version: ${selectedVuln.service_version}` : 'Version: Unspecified'}
                  </div>
                </div>
              </div>

              {/* Description */}
              <div>
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Vulnerability Description</span>
                </h4>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 leading-relaxed font-sans">
                  {selectedVuln.description}
                </div>
              </div>

              {/* Remediation */}
              <div>
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Recommended Remediation</span>
                </h4>
                <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/30 text-xs text-emerald-300 leading-relaxed font-sans">
                  {selectedVuln.remediation || 'Upgrade service to the latest stable release or apply official vendor security patch.'}
                </div>
              </div>

              {/* NVD Link */}
              <div className="pt-2 flex justify-end">
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${selectedVuln.cve_id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-mono hover:underline"
                >
                  <span>View on NVD NIST</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex justify-end">
              <button
                onClick={() => setSelectedVuln(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-mono text-xs transition-colors cursor-pointer"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
