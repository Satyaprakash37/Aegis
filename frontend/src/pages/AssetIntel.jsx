import React, { useState, useEffect, useCallback } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ArrowLeft,
  Sparkles,
  RefreshCw,
  Globe,
  Network,
  Cpu,
  Layers,
  ShieldCheck,
  AlertTriangle,
  Flame,
  ExternalLink,
  ChevronRight,
  Info,
  Clock,
  Server,
  Lock,
  MessageSquare
} from 'lucide-react';
import api from '../api/client';
import Toast from '../components/Toast';
import { CriticalityBadge, EnvironmentBadge, LabBadge } from '../components/Badge';

export default function AssetIntel() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [asset, setAsset] = useState(null);
  const [report, setReport] = useState(null);
  const [reportGeneratedAt, setReportGeneratedAt] = useState(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [loadingStage, setLoadingStage] = useState(1);
  const [toast, setToast] = useState(null);
  const [selectedCve, setSelectedCve] = useState(null);
  const [cveDetail, setCveDetail] = useState(null);
  const [cveDetailLoading, setCveDetailLoading] = useState(false);

  const showToast = (message, type = 'info') => {
    setToast({ message, type });
  };

  // Fetch Asset & Cached Report
  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      // 1. Fetch asset profile
      const assetRes = await api.get(`/api/assets/${id}`);
      setAsset(assetRes.data);

      // 2. Fetch cached attack surface report
      try {
        const intelRes = await api.get(`/api/assets/${id}/attack-surface`);
        setReport(intelRes.data.data);
        setReportGeneratedAt(intelRes.data.report_generated_at);
      } catch (err) {
        if (err.response?.status === 404) {
          setReport(null);
          setReportGeneratedAt(null);
        } else {
          showToast(err.response?.data?.detail || 'Failed to load intelligence report.', 'error');
        }
      }
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to fetch asset details.', 'error');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Handle Generation / Regeneration
  const handleGenerate = async () => {
    setGenerating(true);
    setLoadingStage(1);

    // Staged progress ticker
    const stageTimer1 = setTimeout(() => setLoadingStage(2), 1200);
    const stageTimer2 = setTimeout(() => setLoadingStage(3), 2600);

    try {
      const res = await api.post(`/api/assets/${id}/attack-surface/generate`);
      setReport(res.data.data);
      setReportGeneratedAt(res.data.report_generated_at);
      showToast('Attack Surface Intelligence report generated successfully.', 'success');
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to generate intelligence report.', 'error');
    } finally {
      clearTimeout(stageTimer1);
      clearTimeout(stageTimer2);
      setGenerating(false);
    }
  };

  // Fetch CVE Quick Detail for Drawer/Modal
  const handleCveClick = async (cveId) => {
    setSelectedCve(cveId);
    setCveDetailLoading(true);
    try {
      const res = await api.get(`/api/threat-intel/enrich/${cveId}`);
      setCveDetail(res.data);
    } catch (err) {
      // Fallback
      setCveDetail({ cve_id: cveId, title: 'Vulnerability record', in_kev: false });
    } finally {
      setCveDetailLoading(false);
    }
  };

  const renderRiskBadge = (level) => {
    const l = (level || 'low').toLowerCase();
    if (l === 'critical') {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
          CRITICAL RISK
        </span>
      );
    }
    if (l === 'high') {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-orange-500/20 text-orange-300 border border-orange-500/30">
          HIGH RISK
        </span>
      );
    }
    if (l === 'medium') {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
          MEDIUM RISK
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
        LOW RISK
      </span>
    );
  };

  const renderLikelihoodBadge = (likelihood) => {
    const l = (likelihood || 'medium').toLowerCase();
    if (l === 'high') {
      return (
        <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1">
          <Flame className="w-3 h-3 text-rose-400" />
          <span>LIKELIHOOD: HIGH</span>
        </span>
      );
    }
    if (l === 'medium') {
      return (
        <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30 flex items-center gap-1">
          <span>LIKELIHOOD: MEDIUM</span>
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
        <span>LIKELIHOOD: LOW</span>
      </span>
    );
  };

  return (
    <div className="space-y-8">
      <Toast toast={toast} onClose={() => setToast(null)} />

      {/* Top Navigation & Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div className="flex items-center gap-3">
          <Link
            to="/assets"
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
            title="Back to Assets Inventory"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
                <span>{asset?.name || 'Loading Asset...'}</span>
              </h1>
              {asset?.is_lab && <LabBadge />}
              {asset?.environment && <EnvironmentBadge env={asset.environment} />}
              {asset?.criticality && <CriticalityBadge level={asset.criticality} />}
            </div>
            <div className="flex items-center gap-3 mt-1 text-xs font-mono text-slate-400">
              <span className="text-cyan-400">{asset?.ip_address}</span>
              {asset?.hostname && <span>• {asset.hostname}</span>}
              {reportGeneratedAt && (
                <span className="text-slate-500 flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  Report: {new Date(reportGeneratedAt).toLocaleString()}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/copilot-test')}
            className="px-3 py-1.5 rounded-lg border border-cyan-800/50 bg-cyan-950/30 hover:bg-cyan-900/40 text-cyan-300 text-xs font-mono font-medium flex items-center gap-1.5 transition-colors"
          >
            <MessageSquare className="w-3.5 h-3.5" />
            <span>Chat with Copilot</span>
          </button>
          <button
            onClick={handleGenerate}
            disabled={generating}
            className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-mono font-semibold flex items-center gap-2 shadow-lg shadow-purple-950/50 disabled:opacity-50 transition-all cursor-pointer"
          >
            <Sparkles className={`w-3.5 h-3.5 ${generating ? 'animate-spin' : ''}`} />
            <span>{generating ? 'Analyzing Target...' : report ? 'Regenerate Analysis' : 'Generate Analysis'}</span>
          </button>
        </div>
      </div>

      {/* Loading Staged Progress */}
      {generating && (
        <div className="p-8 rounded-xl bg-slate-900/80 border border-purple-500/30 backdrop-blur-md text-center space-y-4 shadow-xl">
          <div className="inline-flex p-3 rounded-full bg-purple-500/10 border border-purple-500/30 text-purple-400 animate-pulse">
            <Sparkles className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-bold text-slate-100">AI Attack Surface Profiling in Progress</h3>
          <div className="max-w-md mx-auto space-y-2">
            <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
              <div
                className="bg-gradient-to-r from-purple-500 to-cyan-400 h-1.5 rounded-full transition-all duration-500"
                style={{ width: `${loadingStage * 33}%` }}
              />
            </div>
            <p className="text-xs font-mono text-purple-300 animate-pulse">
              {loadingStage === 1 && 'Gathering findings & asset telemetry...'}
              {loadingStage === 2 && 'Analyzing perimeter exposures & service boundaries...'}
              {loadingStage === 3 && 'Composing verified attack path narratives...'}
            </p>
          </div>
        </div>
      )}

      {/* Initial Loading Spinner */}
      {loading && !generating && (
        <div className="py-20 flex flex-col items-center justify-center text-slate-400 space-y-3 font-mono">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
          <span className="text-xs uppercase tracking-widest">Loading Attack Surface Intelligence...</span>
        </div>
      )}

      {/* Empty State when No Report Generated */}
      {!loading && !generating && !report && (
        <div className="p-12 rounded-xl bg-slate-900/40 border border-dashed border-slate-800 text-center space-y-4 max-w-xl mx-auto my-12">
          <div className="inline-flex p-3 rounded-full bg-slate-800/80 text-slate-400">
            <Layers className="w-8 h-8" />
          </div>
          <h2 className="text-lg font-bold text-slate-200">No Intelligence Report Yet</h2>
          <p className="text-sm text-slate-400">
            Generate an AI-assisted Attack Surface Intelligence report to correlate findings, identify potential
            exploit chains, and build prioritized remediation guidance for this target.
          </p>
          <button
            onClick={handleGenerate}
            className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-mono text-xs font-semibold inline-flex items-center gap-2 shadow-lg shadow-purple-900/40 transition-all cursor-pointer"
          >
            <Sparkles className="w-4 h-4" />
            <span>Generate Analysis</span>
          </button>
        </div>
      )}

      {/* Intelligence Report Display */}
      {!loading && !generating && report && (
        <div className="space-y-8 animate-fadeIn">
          {/* 1. Executive Summary Card */}
          <div className="p-6 rounded-xl bg-gradient-to-br from-slate-900 via-slate-900/90 to-purple-950/20 border border-purple-900/30 shadow-lg space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-mono font-semibold text-purple-300">
                <Sparkles className="w-4 h-4 text-purple-400" />
                <span>EXECUTIVE SECURITY POSTURE ASSESSMENT</span>
              </div>
              <span className="text-[11px] font-mono text-slate-500">Defensive Architect Persona</span>
            </div>
            <div className="text-sm leading-relaxed text-slate-300 space-y-3 whitespace-pre-line font-sans">
              {report.executive_summary}
            </div>
          </div>

          {/* 2. Attack Surface Map */}
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-base font-bold text-white tracking-wide">
              <Network className="w-5 h-5 text-cyan-400" />
              <span>Attack Surface Map & Boundary Telemetry</span>
            </div>

            {/* Entry Points Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {(report.attack_surface_map?.entry_points || []).map((ep, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-lg bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition-colors space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 font-mono text-xs font-semibold text-slate-200 uppercase">
                      {ep.type === 'web' ? (
                        <Globe className="w-4 h-4 text-cyan-400" />
                      ) : (
                        <Server className="w-4 h-4 text-purple-400" />
                      )}
                      <span>{ep.type} Entry Point</span>
                    </div>
                    {renderRiskBadge(ep.risk_level)}
                  </div>
                  <p className="text-xs text-slate-300 font-sans">{ep.detail}</p>
                  {ep.port_if_any && (
                    <div className="text-[11px] font-mono text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-900/50 w-fit">
                      Port: {ep.port_if_any}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Exposed Services Table & Trust Boundaries */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="lg:col-span-2 rounded-lg bg-slate-900/70 border border-slate-800 overflow-hidden">
                <div className="p-3.5 border-b border-slate-800 bg-slate-950/50 flex items-center justify-between text-xs font-mono font-semibold text-slate-300">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-cyan-400" />
                    <span>Exposed Services Inventory</span>
                  </div>
                  <span className="text-slate-500">
                    {report.attack_surface_map?.exposed_services?.length || 0} service(s)
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950/80 text-slate-400 font-mono border-b border-slate-800/80">
                      <tr>
                        <th className="py-2.5 px-4 font-semibold">Service</th>
                        <th className="py-2.5 px-4 font-semibold">Port</th>
                        <th className="py-2.5 px-4 font-semibold">Version</th>
                        <th className="py-2.5 px-4 font-semibold text-right">Identified Issues</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {(report.attack_surface_map?.exposed_services || []).length === 0 ? (
                        <tr>
                          <td colSpan={4} className="py-4 text-center text-slate-500">
                            No exposed application services identified.
                          </td>
                        </tr>
                      ) : (
                        (report.attack_surface_map?.exposed_services || []).map((srv, idx) => (
                          <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                            <td className="py-2.5 px-4 font-semibold text-cyan-300">{srv.service}</td>
                            <td className="py-2.5 px-4 text-slate-300">{srv.port}</td>
                            <td className="py-2.5 px-4 text-slate-400">{srv.version || 'Detected'}</td>
                            <td className="py-2.5 px-4 text-right">
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
                                {srv.known_issues_count} findings
                              </span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Trust Boundaries Card */}
              <div className="p-4 rounded-lg bg-slate-900/70 border border-slate-800 space-y-2 flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-2 text-xs font-mono font-semibold text-slate-200 mb-2">
                    <Lock className="w-4 h-4 text-emerald-400" />
                    <span>Trust Boundaries & Context</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed font-sans">
                    {report.attack_surface_map?.trust_boundaries}
                  </p>
                </div>
                <div className="pt-2 border-t border-slate-800/60 text-[11px] font-mono text-slate-500">
                  Target Isolation: {asset?.is_lab ? 'Lab Network Boundary' : 'Standard Perimeter'}
                </div>
              </div>
            </div>
          </div>

          {/* 3. Attack Paths Section (Horizontal / Vertical Chain Visualization) */}
          <div className="space-y-4" id="attack-paths-section">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-base font-bold text-white tracking-wide">
                <ShieldAlert className="w-5 h-5 text-rose-400" />
                <span>Correlated Attack Path Narratives</span>
              </div>
              <span className="text-xs font-mono text-slate-400">
                {report.attack_paths?.length || 0} potential chain(s) identified
              </span>
            </div>

            {(report.attack_paths || []).length === 0 ? (
              <div className="p-6 rounded-lg bg-slate-900/50 border border-slate-800 text-center text-xs font-mono text-slate-400">
                No active multi-stage attack paths could be correlated from existing vulnerability telemetry.
              </div>
            ) : (
              <div className="space-y-6">
                {report.attack_paths.map((path, idx) => (
                  <div
                    key={idx}
                    className="p-5 rounded-xl bg-slate-900/80 border border-slate-800/90 shadow-md space-y-4 hover:border-slate-700 transition-colors"
                  >
                    {/* Path Header */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
                      <div>
                        <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
                          Path {idx + 1}
                        </span>
                        <h4 className="text-sm font-bold text-slate-100">{path.title}</h4>
                      </div>
                      <div className="flex items-center gap-2">
                        {renderLikelihoodBadge(path.likelihood)}
                      </div>
                    </div>

                    {/* Impact Statement */}
                    <div className="text-xs text-slate-300 font-sans flex items-start gap-2 bg-slate-950/60 p-2.5 rounded border border-slate-800/60">
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <strong className="text-slate-200">Potential Impact: </strong>
                        <span>{path.impact}</span>
                      </div>
                    </div>

                    {/* Step Chain Visualization */}
                    <div className="space-y-2 pt-2">
                      <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider font-semibold">
                        Exploit Sequence Progression:
                      </span>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        {(path.chain || []).map((step, sIdx) => (
                          <div
                            key={sIdx}
                            className="p-3.5 rounded-lg bg-slate-950/90 border border-slate-800/90 flex flex-col justify-between space-y-2 relative"
                          >
                            <div className="flex items-center justify-between">
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/50 text-cyan-300 border border-cyan-800/40">
                                Phase {sIdx + 1}
                              </span>
                              {sIdx < (path.chain.length - 1) && (
                                <ChevronRight className="hidden md:block w-4 h-4 text-slate-600 absolute -right-3.5 top-1/2 -translate-y-1/2 z-10" />
                              )}
                            </div>
                            <p className="text-xs text-slate-300 font-sans leading-relaxed">{step}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Verified CVE Chips */}
                    <div className="flex items-center gap-2 flex-wrap pt-2">
                      <span className="text-[11px] font-mono text-slate-400">Referenced Findings:</span>
                      {(path.findings_refs || []).map((ref, rIdx) => (
                        <button
                          key={rIdx}
                          onClick={() => handleCveClick(ref)}
                          className="px-2.5 py-1 rounded-md text-xs font-mono font-semibold bg-purple-950/50 text-purple-300 border border-purple-800/50 hover:bg-purple-900/60 hover:text-purple-100 flex items-center gap-1 transition-colors cursor-pointer"
                        >
                          <span>{ref}</span>
                          <ExternalLink className="w-3 h-3 text-purple-400" />
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* 4. Prioritized Concerns */}
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-base font-bold text-white tracking-wide">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <span>Prioritized Concerns & Remediation Actions</span>
            </div>

            <div className="space-y-3">
              {(report.prioritized_concerns || []).map((pc, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-lg bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="space-y-1 max-w-2xl">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                        #{pc.rank || idx + 1}
                      </span>
                      <h4 className="text-sm font-semibold text-slate-100">{pc.concern}</h4>
                    </div>
                    <p className="text-xs text-amber-300 font-mono">
                      <strong className="text-slate-400">Why Now: </strong>
                      {pc.why_now}
                    </p>
                    <p className="text-xs text-slate-300 font-sans">
                      <strong className="text-emerald-400">Remediation: </strong>
                      {pc.recommended_action}
                    </p>
                  </div>

                  <Link
                    to={`/vulns?search=${encodeURIComponent(pc.concern.split(':')[0])}`}
                    className="shrink-0 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 hover:bg-slate-800 text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 transition-colors"
                  >
                    <span>View Finding</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* CVE Quick Detail Modal/Drawer */}
      {selectedCve && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-lg rounded-xl bg-slate-900 border border-slate-800 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-purple-400" />
                <h3 className="text-base font-bold text-white font-mono">{selectedCve}</h3>
              </div>
              <button
                onClick={() => setSelectedCve(null)}
                className="text-slate-400 hover:text-white transition-colors text-sm font-mono cursor-pointer"
              >
                ✕
              </button>
            </div>

            {cveDetailLoading ? (
              <div className="py-8 text-center text-slate-400 font-mono text-xs">
                <RefreshCw className="w-6 h-6 text-purple-400 animate-spin mx-auto mb-2" />
                Fetching threat telemetry...
              </div>
            ) : (
              <div className="space-y-3 text-xs">
                <p className="text-slate-300 leading-relaxed font-sans">
                  {cveDetail?.summary || cveDetail?.title || 'Telemetry details loaded.'}
                </p>

                <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800 font-mono">
                  <div className="p-2 rounded bg-slate-950 border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px]">CISA KEV Status</span>
                    <span className={cveDetail?.in_kev ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                      {cveDetail?.in_kev ? 'Confirmed KEV Weaponized' : 'Not in KEV Catalog'}
                    </span>
                  </div>
                  <div className="p-2 rounded bg-slate-950 border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px]">FIRST EPSS Probability</span>
                    <span className="text-cyan-400 font-bold">
                      {cveDetail?.epss_score ? `${(cveDetail.epss_score * 100).toFixed(2)}%` : 'Telemetry pending'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-end gap-2 pt-4 border-t border-slate-800">
                  <Link
                    to={`/vulns?search=${selectedCve}`}
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold flex items-center gap-1.5 transition-colors"
                  >
                    <span>Open in Vuln Register</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                  <button
                    onClick={() => setSelectedCve(null)}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs transition-colors cursor-pointer"
                  >
                    Close
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
