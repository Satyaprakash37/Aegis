import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import {
  Terminal,
  Bot,
  Send,
  Trash2,
  Sparkles,
  RefreshCw,
  ShieldAlert,
  Flame,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Plus,
  Clock,
  User,
  Layers,
  FileCode,
  Shield,
  Activity,
  X,
  FileText
} from 'lucide-react';
import api from '../api/client';
import { useAuth } from '../context/AuthContext';
import { CriticalityBadge, EnvironmentBadge, LabBadge } from '../components/Badge';
import Toast from '../components/Toast';

export default function Console() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const assetIdParam = searchParams.get('asset_id');
  const cveParam = searchParams.get('cve');

  // State: Assets & Selection
  const [assets, setAssets] = useState([]);
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [assetVulns, setAssetVulns] = useState([]);
  const [toast, setToast] = useState(null);

  // State: AI Copilot Chat
  const [suggestions, setSuggestions] = useState([]);
  const [messages, setMessages] = useState([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const [copilotError, setCopilotError] = useState('');
  const messagesEndRef = useRef(null);

  // State: Operator Action Log
  const [actions, setActions] = useState([]);
  const [actionsLoading, setActionsLoading] = useState(false);
  const [actionTool, setActionTool] = useState('nmap');
  const [actionCommand, setActionCommand] = useState('');
  const [actionResult, setActionResult] = useState('');
  const [actionEvidence, setActionEvidence] = useState('');
  const [actionLinkedCves, setActionLinkedCves] = useState([]);
  const [showEvidenceInput, setShowEvidenceInput] = useState(false);
  const [loggingAction, setLoggingAction] = useState(false);
  const [expandedEvidence, setExpandedEvidence] = useState({});

  // Quick detail modal state
  const [modalCve, setModalCve] = useState(null);
  const [modalCveLoading, setModalCveLoading] = useState(false);
  const [modalCveData, setModalCveData] = useState(null);

  const showToast = (message, type = 'info') => {
    setToast({ message, type });
  };

  // 1. Fetch Assets on mount
  useEffect(() => {
    const fetchAssets = async () => {
      try {
        const res = await api.get('/api/assets?page_size=100');
        const list = res.data?.data || res.data?.items || (Array.isArray(res.data) ? res.data : []);
        setAssets(list);

        if (list.length > 0) {
          // If query param exists and matches an asset, use it
          if (assetIdParam && list.some(a => a.id.toString() === assetIdParam)) {
            setSelectedAssetId(assetIdParam);
          } else {
            // Default to lab-wordpress or first
            const defaultAsset = list.find(a => a.name === 'lab-wordpress') || list[0];
            setSelectedAssetId(defaultAsset.id.toString());
          }
        }
      } catch (err) {
        showToast('Failed to load asset targets.', 'error');
      }
    };
    fetchAssets();
  }, [assetIdParam]);

  // Pre-fill CVE from query param if provided
  useEffect(() => {
    if (cveParam) {
      setActionLinkedCves([cveParam]);
    }
  }, [cveParam]);

  // 2. Load context when selectedAssetId changes
  const loadTargetData = useCallback(async (assetId) => {
    if (!assetId) return;

    try {
      // A. Fetch Asset Profile & Vuln Telemetry
      const [assetRes, vulnsRes] = await Promise.all([
        api.get(`/api/assets/${assetId}`),
        api.get(`/api/vulns?asset_id=${assetId}&page_size=100`),
      ]);
      setSelectedAsset(assetRes.data);
      const vList = vulnsRes.data?.data || [];
      setAssetVulns(vList);

      // B. Fetch Copilot Suggestions & History
      try {
        const [sugRes, histRes] = await Promise.all([
          api.get(`/api/copilot/suggestions/${assetId}`),
          api.get(`/api/copilot/history/${assetId}`),
        ]);
        setSuggestions(sugRes.data?.suggestions || []);
        setMessages(histRes.data || []);
        setCopilotError('');
      } catch (err) {
        if (err.response?.status === 503) {
          setCopilotError('Copilot not configured - set GEMINI_API_KEY');
        }
      }

      // C. Fetch Operator Actions Log
      setActionsLoading(true);
      try {
        const actRes = await api.get(`/api/operator-actions/${assetId}?page_size=50`);
        setActions(actRes.data?.data || []);
      } catch (err) {
        showToast('Failed to fetch action audit log.', 'error');
      } finally {
        setActionsLoading(false);
      }
    } catch (err) {
      showToast('Error syncing target data.', 'error');
    }
  }, []);

  useEffect(() => {
    if (selectedAssetId) {
      loadTargetData(selectedAssetId);
    }
  }, [selectedAssetId, loadTargetData]);

  // Auto-scroll chat to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, chatLoading]);

  // 3. Send Copilot Message
  const handleSendMessage = async (msgOverride = null) => {
    const text = (msgOverride !== null ? msgOverride : chatInput).trim();
    if (!text || !selectedAssetId || chatLoading) return;

    setChatInput('');
    setChatLoading(true);

    const tempUserMsg = {
      id: Date.now(),
      role: 'user',
      content: text,
      created_at: new Date().toISOString(),
    };
    setMessages(prev => [...prev, tempUserMsg]);

    try {
      const res = await api.post('/api/copilot/chat', {
        asset_id: parseInt(selectedAssetId, 10),
        message: text,
      });

      const assistantMsg = {
        id: Date.now() + 1,
        role: 'assistant',
        content: res.data.reply,
        tools_used: res.data.tools_used || [],
        created_at: new Date().toISOString(),
      };
      setMessages(prev => [...prev, assistantMsg]);
    } catch (err) {
      const errDetail = err.response?.data?.detail || 'Copilot reasoning failed.';
      setMessages(prev => [
        ...prev,
        {
          id: Date.now() + 1,
          role: 'assistant',
          content: `⚠️ **Error**: ${errDetail}`,
          created_at: new Date().toISOString(),
        },
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  // Clear Chat History
  const handleClearChat = async () => {
    if (!selectedAssetId) return;
    try {
      await api.delete(`/api/copilot/history/${selectedAssetId}`);
      setMessages([]);
      showToast('Copilot conversation history cleared.', 'success');
    } catch (err) {
      showToast('Failed to clear conversation history.', 'error');
    }
  };

  // 4. Log Operator Action
  const handleLogAction = async (e) => {
    if (e) e.preventDefault();
    if (!actionCommand.trim() || !actionResult.trim() || !selectedAssetId || loggingAction) {
      return;
    }

    setLoggingAction(true);
    try {
      const payload = {
        asset_id: parseInt(selectedAssetId, 10),
        tool: actionTool,
        command_or_action: actionCommand.trim(),
        result_summary: actionResult.trim(),
        evidence: actionEvidence.trim() || null,
        linked_cves: actionLinkedCves,
      };

      const res = await api.post('/api/operator-actions', payload);
      setActions(prev => [res.data, ...prev]);

      // Reset form
      setActionCommand('');
      setActionResult('');
      setActionEvidence('');
      setActionLinkedCves([]);
      setShowEvidenceInput(false);
      showToast(`Action #${res.data.id} logged to audit trail.`, 'success');
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to record operator action.', 'error');
    } finally {
      setLoggingAction(false);
    }
  };

  // Delete Operator Action (Admin only)
  const handleDeleteAction = async (actionId) => {
    try {
      await api.delete(`/api/operator-actions/${actionId}`);
      setActions(prev => prev.filter(a => a.id !== actionId));
      showToast(`Action #${actionId} removed from audit trail.`, 'success');
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to remove action entry.', 'error');
    }
  };

  // CVE quick detail modal lookup
  const handleCveChipClick = async (cveId) => {
    setModalCve(cveId);
    setModalCveLoading(true);
    try {
      const res = await api.get(`/api/threat-intel/enrich/${cveId}`);
      setModalCveData(res.data);
    } catch (err) {
      setModalCveData({ cve_id: cveId, title: 'Vulnerability record' });
    } finally {
      setModalCveLoading(false);
    }
  };

  // Toggle CVE in action form
  const toggleActionCve = (cveId) => {
    setActionLinkedCves(prev =>
      prev.includes(cveId) ? prev.filter(c => c !== cveId) : [...prev, cveId]
    );
  };

  // Access restriction for Viewer role
  if (user?.role === 'viewer') {
    return (
      <div className="min-h-[70vh] flex items-center justify-center font-mono">
        <div className="p-8 rounded-xl bg-slate-900 border border-rose-500/30 max-w-lg text-center space-y-4 shadow-2xl">
          <div className="w-12 h-12 rounded-full bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 mx-auto">
            <Terminal className="w-6 h-6" />
          </div>
          <h2 className="text-lg font-bold text-rose-400 uppercase tracking-widest">
            ACCESS DENIED: CLEARANCE LEVEL INSUFFICIENT
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed font-sans">
            The Red Team Console is strictly restricted to Security Analysts and Administrators.
            Your current account role is <strong className="text-white font-mono uppercase">Viewer</strong>.
            Please contact your SecOps Administrator for role elevation.
          </p>
          <button
            onClick={() => navigate('/assets')}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium transition-colors"
          >
            ← Return to Asset Inventory
          </button>
        </div>
      </div>
    );
  }

  // Calculated target stats
  const kevCount = assetVulns.filter(v => v.in_kev).length;
  const openVulnsCount = assetVulns.filter(v => v.status === 'open').length;

  const renderToolBadge = (tool) => {
    const t = (tool || '').toLowerCase();
    if (t === 'nmap') {
      return <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/60 text-cyan-300 border border-cyan-800/50">NMAP</span>;
    }
    if (t === 'browser') {
      return <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/60 text-emerald-300 border border-emerald-800/50">BROWSER</span>;
    }
    if (t === 'curl') {
      return <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-sky-950/60 text-sky-300 border border-sky-800/50">CURL</span>;
    }
    if (t === 'nuclei') {
      return <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/60 text-amber-300 border border-amber-800/50">NUCLEI</span>;
    }
    if (t === 'metasploit') {
      return <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950/60 text-rose-300 border border-rose-800/50">METASPLOIT</span>;
    }
    return <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-950/60 text-purple-300 border border-purple-800/50 uppercase">{tool}</span>;
  };

  return (
    <div className="space-y-4 font-mono text-slate-200">
      <Toast toast={toast} onClose={() => setToast(null)} />

      {/* ── ZONE 1: CONSOLE HEADER BAR ── */}
      <div className="p-4 rounded-xl bg-slate-950/90 border border-cyan-900/40 shadow-lg shadow-cyan-950/20 backdrop-blur-md flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        {/* Left: Terminal Prompt & Target Selector */}
        <div className="flex flex-col sm:flex-row sm:items-center gap-3">
          <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm tracking-widest shrink-0">
            <Terminal className="w-5 h-5 text-cyan-400" />
            <span>AEGIS://OPS-CONSOLE/V2.0</span>
          </div>

          <div className="h-4 w-px bg-slate-800 hidden sm:block" />

          {/* Target Selector Dropdown */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-semibold uppercase">TARGET:</span>
            <div className="relative">
              <select
                value={selectedAssetId}
                onChange={(e) => setSelectedAssetId(e.target.value)}
                className="bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500 cursor-pointer pr-8"
              >
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.ip_address}) {a.is_lab ? '[LAB]' : ''}
                  </option>
                ))}
              </select>
              <ChevronDown className="w-3.5 h-3.5 text-slate-400 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            </div>
          </div>
        </div>

        {/* Right: Target Context Chips & Full Intel Link */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {selectedAsset && (
            <>
              {selectedAsset.is_lab && <LabBadge />}
              {selectedAsset.environment && <EnvironmentBadge env={selectedAsset.environment} />}
              {selectedAsset.criticality && <CriticalityBadge level={selectedAsset.criticality} />}

              {/* Vuln Count Chip */}
              <div className="px-2 py-0.5 rounded text-xs font-mono bg-slate-900 border border-slate-800 text-slate-300 flex items-center gap-1.5">
                <ShieldAlert className="w-3 h-3 text-cyan-400" />
                <span>{assetVulns.length} Vulns ({openVulnsCount} Open)</span>
              </div>

              {/* KEV Count Chip */}
              {kevCount > 0 && (
                <div className="px-2 py-0.5 rounded text-xs font-mono bg-rose-500/15 border border-rose-500/40 text-rose-300 font-bold flex items-center gap-1 animate-pulse">
                  <Flame className="w-3 h-3 text-rose-400" />
                  <span>{kevCount} CISA KEV</span>
                </div>
              )}

              {/* Open Full Intel Button */}
              <Link
                to={`/assets/${selectedAssetId}/intel`}
                className="px-3 py-1 rounded-lg bg-purple-950/60 border border-purple-800/60 hover:bg-purple-900/60 text-purple-300 hover:text-purple-100 text-xs font-semibold flex items-center gap-1.5 transition-all shadow-sm"
              >
                <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                <span>Open Full Intel</span>
              </Link>
            </>
          )}
        </div>
      </div>

      {/* ── ZONE 2 & 3: SPLIT VIEW WORKSPACE ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 min-h-[620px]">
        {/* ════════════════════════════════════════════════════════════
            LEFT PANEL: AI OPERATIONS COPILOT (UPGRADED)
            ════════════════════════════════════════════════════════════ */}
        <div className="flex flex-col rounded-xl bg-slate-950/80 border border-cyan-900/30 overflow-hidden shadow-xl">
          {/* Chat Header */}
          <div className="p-3.5 border-b border-slate-800/80 bg-slate-900/70 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              <Bot className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold tracking-wider text-slate-200">
                AI OPERATIONS COPILOT
              </span>
              <span className="text-[10px] text-slate-500 font-normal">
                [Target #{selectedAssetId}]
              </span>
            </div>

            <button
              onClick={handleClearChat}
              title="Clear Thread History"
              className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-rose-400 transition-colors cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Suggested Question Chips */}
          {suggestions.length > 0 && (
            <div className="p-2.5 bg-slate-900/40 border-b border-slate-800/60 overflow-x-auto flex items-center gap-2">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest shrink-0">Prompts:</span>
              {suggestions.slice(0, 3).map((sug, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSendMessage(sug)}
                  className="px-2 py-0.5 rounded text-[11px] bg-slate-900 border border-slate-800 hover:border-cyan-700/60 hover:text-cyan-300 text-slate-300 whitespace-nowrap transition-colors cursor-pointer"
                >
                  {sug}
                </button>
              ))}
            </div>
          )}

          {/* Messages Thread */}
          <div className="flex-1 p-4 overflow-y-auto space-y-3.5 max-h-[460px]">
            {messages.length === 0 && !chatLoading && (
              <div className="py-12 text-center text-slate-500 text-xs space-y-2">
                <Bot className="w-8 h-8 text-cyan-500/40 mx-auto" />
                <p>AEGIS Copilot standing by for target {selectedAsset?.name || 'asset'}.</p>
                <p className="text-[11px] text-slate-600">
                  Ask about attack paths, KEV weaponization, or assessment next steps.
                </p>
              </div>
            )}

            {messages.map((m) => {
              const isUser = m.role === 'user';
              return (
                <div
                  key={m.id}
                  className={`flex flex-col ${isUser ? 'items-end' : 'items-start'} space-y-1`}
                >
                  <div
                    className={`max-w-[90%] rounded-xl p-3 text-xs leading-relaxed font-sans ${
                      isUser
                        ? 'bg-slate-900 border border-teal-500/40 text-slate-100 font-mono shadow-sm'
                        : 'bg-slate-900/90 border border-amber-500/30 text-slate-200'
                    }`}
                  >
                    {!isUser && (
                      <div className="flex items-center gap-1.5 text-[10px] font-mono text-amber-400 font-bold mb-1.5">
                        <span>🤖</span>
                        <span>AEGIS COPILOT</span>
                      </div>
                    )}
                    <div className="whitespace-pre-line font-sans leading-relaxed text-xs">
                      {m.content}
                    </div>

                    {/* Tools Used Chips */}
                    {m.tools_used && m.tools_used.length > 0 && (
                      <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center gap-1.5 flex-wrap font-mono">
                        <span className="text-[10px] text-slate-500">tools:</span>
                        {m.tools_used.map((t, tIdx) => (
                          <span
                            key={tIdx}
                            className="px-1.5 py-0.5 rounded text-[10px] bg-slate-950 border border-slate-800 text-cyan-400"
                          >
                            {typeof t === 'string' ? t : t.tool || 'tool'}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  <span className="text-[9px] text-slate-600 px-1 font-mono">
                    {new Date(m.created_at).toLocaleTimeString()}
                  </span>
                </div>
              );
            })}

            {chatLoading && (
              <div className="flex items-center gap-2 text-cyan-400 text-xs py-2 font-mono animate-pulse">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Copilot reasoning & analyzing telemetry...</span>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Chat Input Bar */}
          <div className="p-3 border-t border-slate-800 bg-slate-900/70">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSendMessage();
              }}
              className="flex items-center gap-2"
            >
              <input
                type="text"
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                placeholder="Ask Copilot about target telemetry, attack paths, or priorities... [Enter]"
                disabled={chatLoading}
                className="flex-1 bg-slate-950 border border-slate-700/80 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                disabled={chatLoading || !chatInput.trim()}
                className="p-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-40 transition-colors cursor-pointer"
                title="Send Message"
              >
                <Send className="w-4 h-4" />
              </button>
            </form>
          </div>
        </div>

        {/* ════════════════════════════════════════════════════════════
            RIGHT PANEL: OPERATOR ACTION AUDIT TRAIL
            ════════════════════════════════════════════════════════════ */}
        <div className="flex flex-col rounded-xl bg-slate-950/80 border border-cyan-900/30 overflow-hidden shadow-xl">
          {/* Action Log Header */}
          <div className="p-3.5 border-b border-slate-800/80 bg-slate-900/70 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-bold tracking-wider text-slate-200">
                OPERATOR ACTION AUDIT TRAIL
              </span>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] bg-slate-900 border border-slate-800 text-emerald-400 font-bold">
              {actions.length} LOGGED
            </span>
          </div>

          {/* "Log Action" Interactive Form */}
          <div className="p-3.5 bg-slate-900/50 border-b border-slate-800 space-y-3">
            <form
              onSubmit={handleLogAction}
              onKeyDown={(e) => {
                if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                  e.preventDefault();
                  handleLogAction();
                }
              }}
              className="space-y-2.5"
            >
              {/* Row 1: Tool Dropdown & Command Input */}
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-2">
                <select
                  data-testid="operator-tool-select"
                  value={actionTool}
                  onChange={(e) => setActionTool(e.target.value)}
                  className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500 cursor-pointer"
                >
                  <option value="nmap">Nmap</option>
                  <option value="manual-test">Manual Test</option>
                  <option value="browser">Browser Probe</option>
                  <option value="curl">cURL</option>
                  <option value="nuclei">Nuclei</option>
                  <option value="metasploit">Metasploit</option>
                  <option value="custom">Custom Tool</option>
                </select>

                <input
                  type="text"
                  value={actionCommand}
                  onChange={(e) => setActionCommand(e.target.value)}
                  placeholder="Action/command (e.g. nmap -sV -p 80...)"
                  className="sm:col-span-3 bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              {/* Row 2: Result Summary */}
              <input
                type="text"
                value={actionResult}
                onChange={(e) => setActionResult(e.target.value)}
                placeholder="Outcome notes (e.g. Discovered Apache 2.4.38; verified HTTP 200)"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />

              {/* Row 3: Optional Evidence Toggle & Linked CVEs */}
              <div className="flex items-center justify-between text-xs pt-1">
                <button
                  type="button"
                  onClick={() => setShowEvidenceInput(!showEvidenceInput)}
                  className="text-[11px] text-slate-400 hover:text-cyan-400 flex items-center gap-1 transition-colors cursor-pointer"
                >
                  <span>{showEvidenceInput ? '− Hide Evidence Paste' : '+ Add Output Evidence'}</span>
                </button>

                {/* Quick-add CVE Chips from Target Asset */}
                {assetVulns.length > 0 && (
                  <div className="flex items-center gap-1.5 overflow-x-auto max-w-[280px]">
                    <span className="text-[10px] text-slate-500 shrink-0">Link CVE:</span>
                    {assetVulns.slice(0, 4).map((v) => {
                      const isLinked = actionLinkedCves.includes(v.cve_id);
                      return (
                        <button
                          key={v.id}
                          type="button"
                          onClick={() => toggleActionCve(v.cve_id)}
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono transition-colors cursor-pointer ${
                            isLinked
                              ? 'bg-purple-600 text-white font-bold'
                              : 'bg-slate-950 border border-slate-800 text-slate-400 hover:text-purple-300'
                          }`}
                        >
                          {v.cve_id}
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Evidence Paste Area */}
              {showEvidenceInput && (
                <textarea
                  value={actionEvidence}
                  onChange={(e) => setActionEvidence(e.target.value)}
                  placeholder="Paste terminal stdout, raw response headers, or proof evidence here..."
                  rows={3}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              )}

              {/* Submit Button */}
              <div className="flex items-center justify-between pt-1">
                <span className="text-[10px] text-slate-500 font-mono">
                  Tip: <kbd className="px-1 py-0.5 bg-slate-900 border border-slate-800 rounded">Ctrl+Enter</kbd> to log
                </span>
                <button
                  type="submit"
                  disabled={loggingAction || !actionCommand.trim() || !actionResult.trim()}
                  className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-semibold flex items-center gap-1.5 disabled:opacity-40 transition-colors cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Log Action</span>
                </button>
              </div>
            </form>
          </div>

          {/* Action Timeline List */}
          <div className="flex-1 p-3.5 overflow-y-auto space-y-3 max-h-[380px]">
            {actionsLoading ? (
              <div className="py-12 text-center text-slate-500 text-xs">
                <RefreshCw className="w-5 h-5 text-emerald-400 animate-spin mx-auto mb-2" />
                Loading audit trail...
              </div>
            ) : actions.length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-xs space-y-2">
                <Layers className="w-8 h-8 text-emerald-500/40 mx-auto" />
                <p>No operator actions recorded for this asset yet.</p>
                <p className="text-[11px] text-slate-600">
                  Use the form above to record test runs, manual probes, or verification notes.
                </p>
              </div>
            ) : (
              actions.map((act) => (
                <div
                  key={act.id}
                  className="p-3 rounded-lg bg-slate-900/80 border border-slate-800/90 hover:border-slate-700 transition-colors space-y-2"
                >
                  {/* Action Card Header */}
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      {renderToolBadge(act.tool)}
                      <span className="text-[10px] text-slate-500 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {new Date(act.created_at).toLocaleTimeString()}
                      </span>
                      {act.user_email && (
                        <span className="text-[10px] text-slate-500 flex items-center gap-1">
                          <User className="w-3 h-3" />
                          {act.user_email.split('@')[0]}
                        </span>
                      )}
                    </div>

                    {user?.role === 'admin' && (
                      <button
                        onClick={() => handleDeleteAction(act.id)}
                        title="Delete Action Entry (Admin)"
                        className="text-slate-500 hover:text-rose-400 transition-colors p-1"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    )}
                  </div>

                  {/* Command / Action */}
                  <div className="p-2 rounded bg-slate-950 border border-slate-800/80 font-mono text-xs text-cyan-300 break-all select-all">
                    $ {act.command_or_action}
                  </div>

                  {/* Outcome */}
                  <div className="text-xs text-slate-300 font-sans">
                    <strong className="text-slate-400 font-mono text-[11px]">Outcome: </strong>
                    {act.result_summary}
                  </div>

                  {/* Linked CVE Chips */}
                  {act.linked_cves && act.linked_cves.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap pt-1">
                      <span className="text-[10px] text-slate-500">CVEs:</span>
                      {act.linked_cves.map((cve, cIdx) => (
                        <button
                          key={cIdx}
                          onClick={() => handleCveChipClick(cve)}
                          className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-950/60 text-purple-300 border border-purple-800/60 hover:bg-purple-900/70 transition-colors flex items-center gap-1 cursor-pointer"
                        >
                          <span>{cve}</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </button>
                      ))}
                    </div>
                  )}

                  {/* Evidence Accordion */}
                  {act.evidence && (
                    <div className="pt-1">
                      <button
                        onClick={() =>
                          setExpandedEvidence(prev => ({
                            ...prev,
                            [act.id]: !prev[act.id],
                          }))
                        }
                        className="text-[10px] text-slate-400 hover:text-cyan-400 flex items-center gap-1 transition-colors cursor-pointer"
                      >
                        <span>{expandedEvidence[act.id] ? 'Hide Evidence' : 'View Raw Evidence'}</span>
                        <ChevronRight
                          className={`w-3 h-3 transition-transform ${
                            expandedEvidence[act.id] ? 'rotate-90' : ''
                          }`}
                        />
                      </button>

                      {expandedEvidence[act.id] && (
                        <pre className="mt-1.5 p-2 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-300 overflow-x-auto max-h-36 font-mono leading-relaxed">
                          {act.evidence}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* ── ZONE 4: BOTTOM STATS & VAPT PREVIEW BAR ── */}
      <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-400">
        <div className="flex items-center gap-4 flex-wrap">
          <div>
            Logged Actions:{' '}
            <span className="text-white font-bold">{actions.length}</span>
          </div>
          <div>•</div>
          <div>
            Active Target:{' '}
            <span className="text-cyan-400 font-semibold">{selectedAsset?.name || 'N/A'}</span>
          </div>
          <div>•</div>
          <div>
            Last Activity:{' '}
            <span className="text-slate-300">
              {actions[0]?.created_at
                ? new Date(actions[0].created_at).toLocaleTimeString()
                : 'None'}
            </span>
          </div>
        </div>

        {/* Phase R4 VAPT Preview Button */}
        <button
          onClick={() =>
            showToast('VAPT Assessment PDF report generation is scheduled for Phase R4.', 'info')
          }
          className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white flex items-center gap-2 transition-all cursor-pointer w-fit"
        >
          <FileText className="w-3.5 h-3.5 text-cyan-400" />
          <span>Generate VAPT Assessment Report</span>
          <span className="px-1.5 py-0.2 rounded text-[9px] bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold">
            PHASE R4 PREVIEW
          </span>
        </button>
      </div>

      {/* CVE Quick Detail Modal */}
      {modalCve && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-lg rounded-xl bg-slate-900 border border-slate-800 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-purple-400" />
                <h3 className="text-base font-bold text-white font-mono">{modalCve}</h3>
              </div>
              <button
                onClick={() => setModalCve(null)}
                className="text-slate-400 hover:text-white transition-colors"
              >
                ✕
              </button>
            </div>

            {modalCveLoading ? (
              <div className="py-8 text-center text-slate-400 font-mono text-xs">
                <RefreshCw className="w-6 h-6 text-purple-400 animate-spin mx-auto mb-2" />
                Fetching threat telemetry...
              </div>
            ) : (
              <div className="space-y-3 text-xs">
                <p className="text-slate-300 leading-relaxed font-sans">
                  {modalCveData?.summary || modalCveData?.title || 'Telemetry details loaded.'}
                </p>

                <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800 font-mono">
                  <div className="p-2 rounded bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block text-[10px]">CISA KEV Status</span>
                    <span className={modalCveData?.in_kev ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                      {modalCveData?.in_kev ? 'Weaponized in KEV' : 'Not in KEV'}
                    </span>
                  </div>
                  <div className="p-2 rounded bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block text-[10px]">FIRST EPSS Probability</span>
                    <span className="text-cyan-400 font-bold">
                      {modalCveData?.epss_score
                        ? `${(modalCveData.epss_score * 100).toFixed(2)}%`
                        : 'Telemetry pending'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-end gap-2 pt-4 border-t border-slate-800">
                  <Link
                    to={`/vulns?search=${modalCve}`}
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold flex items-center gap-1.5"
                  >
                    <span>View in Register</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                  <button
                    onClick={() => setModalCve(null)}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono"
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
