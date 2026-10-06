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
  Tag
} from 'lucide-react';
import api from '../api/client';
import { SeverityBadge, VulnStatusBadge } from '../components/Badge';

export default function Vulnerabilities() {
  const [searchParams, setSearchParams] = useSearchParams();
  const scanIdParam = searchParams.get('scan_id');

  // State
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedVuln, setSelectedVuln] = useState(null);

  // Filters
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  // Pagination
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const pageSize = 15;

  const fetchVulns = useCallback(async () => {
    setLoading(true);
    try {
      const params = {
        page,
        page_size: pageSize,
      };
      if (search) params.search = search;
      if (severityFilter) params.severity = severityFilter;
      if (statusFilter) params.status = statusFilter;
      if (scanIdParam) params.scan_id = parseInt(scanIdParam, 10);

      const res = await api.get('/api/vulns', { params });
      setVulns(res.data.data || []);
      setTotal(res.data.total || 0);
    } catch (err) {
      console.error('Failed to load vulnerabilities:', err);
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, search, severityFilter, statusFilter, scanIdParam]);

  useEffect(() => {
    fetchVulns();
  }, [fetchVulns]);

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

  return (
    <div className="space-y-6">
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
            Enriched CVE findings from NVD database cross-referenced against active network assets
          </p>
        </div>

        {scanIdParam && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-950/40 border border-cyan-800/40 text-xs font-mono text-cyan-300">
            <span>Filtering by Scan #{scanIdParam}</span>
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
              <tr className="border-b border-slate-800/80 bg-slate-950 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                <th className="py-3 px-4">CVE ID</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">CVSS</th>
                <th className="py-3 px-4">Target Asset</th>
                <th className="py-3 px-4">Service / Port</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">First Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40">
              {loading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="py-3.5 px-4"><div className="h-4 w-28 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-20 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-12 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-32 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-24 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-16 bg-slate-800 rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-20 bg-slate-800 rounded" /></td>
                  </tr>
                ))
              ) : vulns.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
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
                    <td className="py-3.5 px-4 font-mono font-bold text-cyan-400 group-hover:text-cyan-300">
                      {v.cve_id}
                    </td>

                    {/* Severity */}
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={v.severity} />
                    </td>

                    {/* CVSS Score */}
                    <td className="py-3.5 px-4 font-mono font-bold text-white">
                      {v.cvss_score.toFixed(1)}
                    </td>

                    {/* Target Asset */}
                    <td className="py-3.5 px-4">
                      <div className="font-medium text-slate-200 font-mono">
                        {v.asset_name}
                      </div>
                      {v.asset_ip && (
                        <div className="text-[11px] text-slate-500 font-mono">
                          {v.asset_ip}
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
                        <div className="text-[11px] text-slate-500 font-sans">
                          v{v.service_version}
                        </div>
                      )}
                    </td>

                    {/* Status */}
                    <td className="py-3.5 px-4">
                      <VulnStatusBadge status={v.status} />
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
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
            {/* Header */}
            <div className="p-5 border-b border-slate-800 flex items-start justify-between gap-4 bg-slate-950/80">
              <div>
                <div className="flex items-center gap-2.5">
                  <h3 className="text-lg font-bold text-white font-mono">
                    {selectedVuln.cve_id}
                  </h3>
                  <SeverityBadge severity={selectedVuln.severity} />
                  <VulnStatusBadge status={selectedVuln.status} />
                </div>
                <p className="text-xs text-slate-400 mt-1 font-mono">
                  Base CVSS Score: <span className="text-white font-bold">{selectedVuln.cvss_score.toFixed(1)}</span>
                </p>
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
              {/* Asset and Port Info Cards */}
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 font-mono uppercase text-[10px] block mb-1">
                    Affected Asset
                  </span>
                  <div className="text-slate-200 font-mono font-medium">
                    {selectedVuln.asset_name}
                  </div>
                  <div className="text-slate-400 font-mono text-[11px]">
                    {selectedVuln.asset_ip}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 font-mono uppercase text-[10px] block mb-1">
                    Port & Service
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
