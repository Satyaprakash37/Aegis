import React, { useState, useEffect, useRef } from 'react';
import api from '../api/client';
import { 
  Bot, 
  Send, 
  Trash2, 
  Sparkles, 
  Terminal, 
  ShieldCheck, 
  AlertTriangle, 
  ExternalLink,
  ChevronDown,
  Loader2,
  Database,
  Search,
  CheckCircle2
} from 'lucide-react';

export default function CopilotTest() {
  const [assets, setAssets] = useState([]);
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [suggestions, setSuggestions] = useState([]);
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [error, setError] = useState('');
  const messagesEndRef = useRef(null);

  // 1. Fetch Assets on mount
  useEffect(() => {
    const fetchAssets = async () => {
      try {
        const res = await api.get('/api/assets');
        const assetList = res.data?.data || res.data?.items || (Array.isArray(res.data) ? res.data : []);
        setAssets(assetList);
        if (assetList.length > 0) {
          // Prefer lab-wordpress or first asset
          const defaultAsset = assetList.find(a => a.name === 'lab-wordpress') || assetList[0];
          setSelectedAssetId(defaultAsset.id.toString());
        }
      } catch (err) {
        console.error('Failed to fetch assets', err);
        setError('Failed to load assets inventory.');
      }
    };
    fetchAssets();
  }, []);

  // 2. When selectedAssetId changes, fetch history and suggestions
  useEffect(() => {
    if (!selectedAssetId) return;

    const current = assets.find(a => a.id.toString() === selectedAssetId.toString());
    setSelectedAsset(current || null);

    const loadAssetContext = async () => {
      setLoadingHistory(true);
      setError('');
      try {
        // Fetch Suggestions
        const sugRes = await api.get(`/api/copilot/suggestions/${selectedAssetId}`);
        setSuggestions(sugRes.data?.suggestions || []);

        // Fetch History
        const histRes = await api.get(`/api/copilot/history/${selectedAssetId}`);
        setMessages(histRes.data || []);
      } catch (err) {
        if (err.response?.status === 503) {
          setError(err.response.data?.detail || 'Copilot not configured - set GEMINI_API_KEY');
        } else {
          console.error('Failed to load asset copilot context', err);
        }
      } finally {
        setLoadingHistory(false);
      }
    };

    loadAssetContext();
  }, [selectedAssetId, assets]);

  // Scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleSendMessage = async (msgToSend = null) => {
    const text = (msgToSend !== null ? msgToSend : inputMessage).trim();
    if (!text || !selectedAssetId || loading) return;

    setInputMessage('');
    setError('');
    setLoading(true);

    // Optimistic user message append
    const tempUserMsg = {
      id: Date.now(),
      role: 'user',
      content: text,
      created_at: new Date().toISOString(),
      tools_used: []
    };
    setMessages(prev => [...prev, tempUserMsg]);

    try {
      const res = await api.post('/api/copilot/chat', {
        asset_id: parseInt(selectedAssetId),
        message: text
      });

      const assistantMsg = {
        id: Date.now() + 1,
        role: 'assistant',
        content: res.data.reply,
        tools_used: res.data.tools_used || [],
        created_at: new Date().toISOString()
      };
      setMessages(prev => [...prev, assistantMsg]);
    } catch (err) {
      console.error('Copilot chat error', err);
      const errDetail = err.response?.data?.detail || err.message || 'Error executing request.';
      setError(errDetail);
      // Append error message from assistant
      setMessages(prev => [
        ...prev,
        {
          id: Date.now() + 1,
          role: 'assistant',
          content: `⚠️ **Copilot System Error**: ${errDetail}`,
          tools_used: [],
          created_at: new Date().toISOString()
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleClearHistory = async () => {
    if (!selectedAssetId) return;
    try {
      await api.delete(`/api/copilot/history/${selectedAssetId}`);
      setMessages([]);
    } catch (err) {
      console.error('Failed to clear history', err);
      setError('Failed to clear conversation history.');
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600/30 to-blue-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.2)]">
              <Bot className="w-6 h-6 text-cyan-300" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                AI Operations Copilot
                <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                  v2.0 Phase R1
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Defensive reasoning engine powered by Gemini function calling with direct KEV & EPSS telemetry.
              </p>
            </div>
          </div>
        </div>

        {/* Asset Selection Controls */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-900/80 border border-slate-800 rounded-lg px-3 py-1.5 shadow-sm">
            <span className="text-xs text-slate-400 font-mono">Target:</span>
            <select
              value={selectedAssetId}
              onChange={(e) => setSelectedAssetId(e.target.value)}
              className="bg-transparent text-sm font-medium text-slate-200 outline-none cursor-pointer pr-4"
            >
              {assets.map((a) => (
                <option key={a.id} value={a.id} className="bg-slate-900 text-slate-200">
                  #{a.id} - {a.name} ({a.ip_address})
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={handleClearHistory}
            title="Clear Conversation History"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-red-400 bg-slate-900/80 hover:bg-red-500/10 border border-slate-800 hover:border-red-500/30 rounded-lg transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Clear
          </button>
        </div>
      </div>

      {/* Target Asset Telemetry Banner */}
      {selectedAsset && (
        <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-white">{selectedAsset.name}</span>
                <span className="text-xs font-mono text-slate-400">({selectedAsset.ip_address})</span>
                {selectedAsset.is_lab && (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    LAB ASSET
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3 text-xs text-slate-400 mt-0.5">
                <span>Type: <strong className="text-slate-300 font-normal">{selectedAsset.asset_type}</strong></span>
                <span>•</span>
                <span>Env: <strong className="text-slate-300 font-normal">{selectedAsset.environment}</strong></span>
                <span>•</span>
                <span>Criticality: <strong className="text-amber-400 font-normal">{selectedAsset.criticality}/5</strong></span>
              </div>
            </div>
          </div>
          <div className="text-xs text-slate-500 flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4 text-cyan-400" />
            <span>Telemetry Context Synchronized</span>
          </div>
        </div>
      )}

      {/* Suggested Prompts Bar */}
      {suggestions.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 font-medium">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span>Suggested Analyst Questions:</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {suggestions.map((sug, idx) => (
              <button
                key={idx}
                onClick={() => handleSendMessage(sug)}
                disabled={loading}
                className="text-xs px-3 py-1.5 rounded-lg bg-slate-900/90 hover:bg-cyan-500/15 border border-slate-800 hover:border-cyan-500/40 text-slate-300 hover:text-cyan-300 transition-all text-left shadow-sm disabled:opacity-50"
              >
                {sug}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Main Chat Conversation Container */}
      <div className="bg-[#0c1322] border border-slate-800/80 rounded-2xl flex flex-col h-[520px] shadow-2xl overflow-hidden">
        {/* Messages Scroll Area */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {loadingHistory ? (
            <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-2">
              <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
              <span className="text-xs">Loading conversation history...</span>
            </div>
          ) : messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center p-6 text-slate-500">
              <Bot className="w-12 h-12 text-slate-700 mb-3" />
              <h3 className="text-sm font-semibold text-slate-300 mb-1">Copilot Ready</h3>
              <p className="text-xs max-w-md text-slate-400 mb-4">
                Ask a question about {selectedAsset?.name || 'this target'} or choose one of the suggested prompts above to begin defensive analysis.
              </p>
            </div>
          ) : (
            messages.map((msg, index) => {
              const isUser = msg.role === 'user';
              return (
                <div
                  key={msg.id || index}
                  className={`flex flex-col ${isUser ? 'items-end' : 'items-start'} space-y-1.5`}
                >
                  {/* Sender label */}
                  <span className="text-[10px] font-mono text-slate-500 px-1">
                    {isUser ? 'OPERATOR' : 'AEGIS COPILOT'}
                  </span>

                  {/* Message Bubble */}
                  <div
                    className={`max-w-[85%] rounded-2xl px-4 py-3 text-sm leading-relaxed ${
                      isUser
                        ? 'bg-cyan-600/20 text-cyan-50 border border-cyan-500/30 rounded-tr-sm shadow-md'
                        : 'bg-slate-900/90 text-slate-200 border border-slate-800 rounded-tl-sm shadow-md'
                    }`}
                  >
                    <div className="whitespace-pre-wrap font-sans text-xs md:text-sm">
                      {msg.content}
                    </div>

                    {/* Tools Used Indicator */}
                    {!isUser && msg.tools_used && msg.tools_used.length > 0 && (
                      <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex flex-wrap items-center gap-1.5">
                        <span className="text-[10px] font-mono text-slate-500 flex items-center gap-1 mr-1">
                          <Terminal className="w-3 h-3 text-cyan-400" />
                          tools:
                        </span>
                        {msg.tools_used.map((t, tidx) => (
                          <span
                            key={tidx}
                            title={t.summary || t.tool}
                            className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800/90 text-cyan-300 border border-cyan-500/20 hover:border-cyan-500/40 transition-colors"
                          >
                            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                            {t.tool}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              );
            })
          )}

          {/* Thinking / Loading State */}
          {loading && (
            <div className="flex flex-col items-start space-y-1.5">
              <span className="text-[10px] font-mono text-slate-500 px-1">AEGIS COPILOT</span>
              <div className="bg-slate-900/90 border border-slate-800 rounded-2xl rounded-tl-sm px-4 py-3 text-sm flex items-center gap-3 text-slate-400">
                <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
                <span className="text-xs font-mono">
                  Copilot querying defensive telemetry and correlating findings...
                </span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar */}
        <div className="border-t border-slate-800/80 bg-slate-950/70 p-3.5">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              placeholder={`Ask Copilot about ${selectedAsset?.name || 'this target'} findings, CISA KEV, or next steps...`}
              disabled={loading || !selectedAssetId}
              className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-xs md:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 transition-colors disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={loading || !inputMessage.trim() || !selectedAssetId}
              className="px-4 py-2.5 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 hover:border-cyan-500/60 transition-all flex items-center gap-1.5 text-xs font-medium disabled:opacity-40 disabled:cursor-not-allowed shadow-[0_0_15px_rgba(6,182,212,0.15)]"
            >
              {loading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <>
                  <Send className="w-4 h-4" />
                  <span>Send</span>
                </>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
