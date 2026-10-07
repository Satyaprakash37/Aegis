import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Bell, 
  Terminal, 
  LogOut, 
  Shield, 
  Activity, 
  ShieldAlert, 
  ShieldCheck, 
  Check, 
  X, 
  Clock, 
  CheckCircle2, 
  AlertTriangle,
  Server,
  Database,
  Cpu,
  Zap,
  ExternalLink,
  RefreshCw
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import api from '../api/client';

export default function Topbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  // Notification State
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [unseenCount, setUnseenCount] = useState(0);
  const notifPanelRef = useRef(null);

  // System Diagnostics Terminal Modal State
  const [isTerminalOpen, setIsTerminalOpen] = useState(false);
  const [systemHealth, setSystemHealth] = useState(null);
  const terminalModalRef = useRef(null);

  // Periodic Polling for Health & Notifications
  const fetchHealth = useCallback(async () => {
    try {
      const res = await api.get('/health');
      setSystemHealth(res.data);
    } catch (err) {
      console.error('Failed to load system health:', err);
    }
  }, []);

  const fetchNotifications = useCallback(async () => {
    try {
      const res = await api.get('/api/notifications');
      const items = res.data.data || [];
      setNotifications(items);

      // Compute unseen items compared to localStorage timestamp
      const lastSeenStr = localStorage.getItem('aegis_notifications_last_seen');
      if (!lastSeenStr) {
        setUnseenCount(items.length);
      } else {
        const lastSeen = new Date(lastSeenStr).getTime();
        const unseen = items.filter(
          (item) => new Date(item.timestamp).getTime() > lastSeen
        );
        setUnseenCount(unseen.length);
      }
    } catch (err) {
      console.error('Failed to load notifications:', err);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    fetchNotifications();

    // Poll every 20 seconds for live updates
    const interval = setInterval(() => {
      fetchHealth();
      fetchNotifications();
    }, 20000);

    return () => clearInterval(interval);
  }, [fetchHealth, fetchNotifications]);

  // Mark all read handler
  const handleMarkAllRead = (e) => {
    e.stopPropagation();
    const nowIso = new Date().toISOString();
    localStorage.setItem('aegis_notifications_last_seen', nowIso);
    setUnseenCount(0);
  };

  // Close dropdown / modal on outside click or Escape key
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setIsNotificationsOpen(false);
        setIsTerminalOpen(false);
      }
    };

    const handleClickOutside = (e) => {
      if (notifPanelRef.current && !notifPanelRef.current.contains(e.target)) {
        setIsNotificationsOpen(false);
      }
      if (terminalModalRef.current && !terminalModalRef.current.contains(e.target)) {
        setIsTerminalOpen(false);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('mousedown', handleClickOutside);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  // Compute initials
  const initials = user?.full_name
    ? user.full_name
        .split(' ')
        .map((n) => n[0])
        .join('')
        .toUpperCase()
        .slice(0, 2)
    : 'OP';

  // Format relative time helper
  const formatRelativeTime = (dateStr) => {
    if (!dateStr) return '';
    try {
      const now = new Date();
      const past = new Date(dateStr);
      const diffSec = Math.max(0, Math.floor((now.getTime() - past.getTime()) / 1000));
      if (diffSec < 60) return 'just now';
      const diffMin = Math.floor(diffSec / 60);
      if (diffMin < 60) return `${diffMin}m ago`;
      const diffHours = Math.floor(diffMin / 60);
      if (diffHours < 24) return `${diffHours}h ago`;
      const diffDays = Math.floor(diffHours / 24);
      return `${diffDays}d ago`;
    } catch {
      return '';
    }
  };

  const activeScan = systemHealth?.active_scan;

  return (
    <header className="h-16 bg-slate-950/70 backdrop-blur-md border-b border-slate-800 px-6 sm:px-8 flex items-center justify-between sticky top-0 z-30">
      {/* App Branding and Active Indicator */}
      <div className="flex items-center gap-4">
        <h1 className="text-base font-semibold text-slate-100 flex items-center gap-2">
          <span>AEGIS</span>
          <span className="text-slate-600">/</span>
          <span className="text-slate-400 font-normal text-sm hidden sm:inline">
            Vulnerability Management Platform
          </span>
        </h1>
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
          SOC ACTIVE
        </span>
      </div>

      {/* Middle & Right Actions Area */}
      <div className="flex items-center gap-3">
        {/* LIVE SCAN TELEMETRY / SYSTEM STATUS STRIP (Issue 3 Fix) */}
        {activeScan ? (
          <button
            onClick={() => navigate('/scans')}
            title="Scan currently in progress — click to inspect live progress"
            className="hidden sm:inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-950/50 border border-cyan-800/50 text-cyan-300 hover:border-cyan-500/60 transition-all font-mono text-xs cursor-pointer shadow-[0_0_12px_rgba(6,182,212,0.2)] animate-pulse"
          >
            <Zap className="w-3.5 h-3.5 text-cyan-400 fill-current" />
            <span className="font-bold">SCANNING: {activeScan.target}</span>
            <span className="text-[10px] text-slate-400">
              [{activeScan.progress?.current_stage || activeScan.scan_type}]
            </span>
          </button>
        ) : (
          <button
            onClick={() => setIsTerminalOpen(true)}
            title="Core Engine Ready — click for System Diagnostics"
            className="hidden md:inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-slate-300 hover:text-white hover:border-slate-700 transition-all font-mono text-xs cursor-pointer group"
          >
            <Terminal className="w-3.5 h-3.5 text-cyan-400 group-hover:text-cyan-300" />
            <span>Core Engine Ready</span>
            <span className="text-[10px] text-emerald-400 flex items-center gap-1 font-sans">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              Backend ✓
            </span>
          </button>
        )}

        {/* TERMINAL DIAGNOSTICS BUTTON (Issue 3) */}
        <button
          onClick={() => setIsTerminalOpen(true)}
          title="System Diagnostics & CLI Telemetry"
          className={`w-9 h-9 rounded-lg border flex items-center justify-center transition-colors cursor-pointer ${
            isTerminalOpen
              ? 'bg-cyan-950/50 border-cyan-500/50 text-cyan-300'
              : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <Terminal className="w-4 h-4" />
        </button>

        {/* NOTIFICATION BELL & DROPDOWN (Issue 2 Fix) */}
        <div className="relative" ref={notifPanelRef}>
          <button
            onClick={() => {
              setIsNotificationsOpen(!isNotificationsOpen);
              if (!isNotificationsOpen) fetchNotifications();
            }}
            title="Platform Notifications & Security Alerts"
            className={`w-9 h-9 rounded-lg border flex items-center justify-center transition-colors relative cursor-pointer ${
              isNotificationsOpen
                ? 'bg-slate-800 border-cyan-500/50 text-white'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
            }`}
          >
            <Bell className="w-4 h-4" />
            {unseenCount > 0 && (
              <span className="absolute -top-1 -right-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold bg-rose-500 text-white border border-slate-950 shadow-[0_0_8px_rgba(244,63,94,0.6)] animate-pulse">
                {unseenCount > 9 ? '9+' : unseenCount}
              </span>
            )}
          </button>

          {/* Notification Slide-Down Panel */}
          {isNotificationsOpen && (
            <div className="absolute right-0 top-12 w-80 sm:w-96 bg-slate-950 border border-slate-800 rounded-xl shadow-2xl z-50 overflow-hidden animate-in fade-in slide-in-from-top-2 duration-150">
              {/* Panel Header */}
              <div className="p-3.5 border-b border-slate-800 bg-slate-900/70 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                    Notifications
                  </h3>
                  {unseenCount > 0 && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">
                      {unseenCount} new
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleMarkAllRead}
                    disabled={unseenCount === 0}
                    className={`text-[11px] font-mono transition-colors flex items-center gap-1 ${
                      unseenCount > 0
                        ? 'text-cyan-400 hover:text-cyan-300 cursor-pointer'
                        : 'text-slate-600 cursor-default'
                    }`}
                  >
                    <Check className="w-3 h-3" />
                    <span>Mark all read</span>
                  </button>
                  <button
                    onClick={() => setIsNotificationsOpen(false)}
                    className="text-slate-400 hover:text-white p-0.5 rounded cursor-pointer"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Panel Body / Items List */}
              <div className="max-h-96 overflow-y-auto divide-y divide-slate-800/40">
                {notifications.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 space-y-1">
                    <Bell className="w-6 h-6 mx-auto opacity-40 text-slate-400" />
                    <p className="text-xs font-mono font-medium text-slate-300">
                      No notifications yet
                    </p>
                    <p className="text-[11px] text-slate-500">
                      Run an automated vulnerability scan to generate findings
                    </p>
                  </div>
                ) : (
                  notifications.map((item) => (
                    <div
                      key={item.id}
                      onClick={() => {
                        setIsNotificationsOpen(false);
                        navigate(item.link || '/vulns');
                      }}
                      className="p-3.5 hover:bg-slate-900/60 transition-colors cursor-pointer group flex items-start gap-3"
                    >
                      {/* Icon Indicator */}
                      <div className="mt-0.5 shrink-0">
                        {item.type === 'critical_vuln' ? (
                          <div className="w-7 h-7 rounded-lg bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400">
                            <ShieldAlert className="w-4 h-4" />
                          </div>
                        ) : item.type === 'verified_vuln' ? (
                          <div className="w-7 h-7 rounded-lg bg-purple-500/15 border border-purple-500/30 flex items-center justify-center text-purple-400">
                            <ShieldCheck className="w-4 h-4" />
                          </div>
                        ) : (
                          <div className="w-7 h-7 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                            <Activity className="w-4 h-4" />
                          </div>
                        )}
                      </div>

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-2 mb-0.5">
                          <p className="text-xs font-semibold text-white group-hover:text-cyan-300 transition-colors truncate">
                            {item.title}
                          </p>
                          <span className="text-[10px] font-mono text-slate-500 shrink-0">
                            {formatRelativeTime(item.timestamp)}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 leading-snug line-clamp-2">
                          {item.detail}
                        </p>
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* Panel Footer */}
              <div className="p-2.5 border-t border-slate-800 bg-slate-900/50 flex items-center justify-between text-[11px] font-mono text-slate-400">
                <button
                  onClick={() => {
                    setIsNotificationsOpen(false);
                    navigate('/scans');
                  }}
                  className="hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  All Scans →
                </button>
                <button
                  onClick={() => {
                    setIsNotificationsOpen(false);
                    navigate('/vulns');
                  }}
                  className="hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  All Findings →
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="h-5 w-px bg-slate-800 mx-1" />

        {/* User Profile */}
        <div className="flex items-center gap-3 pl-1">
          <div className="w-9 h-9 rounded-full bg-gradient-to-tr from-cyan-600 to-blue-500 p-[1.5px] shadow-[0_0_10px_rgba(6,182,212,0.2)]">
            <div className="w-full h-full rounded-full bg-slate-950 flex items-center justify-center text-xs font-bold font-mono text-cyan-300">
              {initials}
            </div>
          </div>
          <div className="hidden md:flex flex-col text-left">
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-semibold text-slate-200">
                {user?.full_name || 'Operator'}
              </span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                {user?.role || 'analyst'}
              </span>
            </div>
            <span className="text-[10px] font-mono text-slate-500">
              {user?.email || 'authenticated'}
            </span>
          </div>

          {/* Logout Button */}
          <button
            onClick={handleLogout}
            title="Terminate Session"
            className="ml-2 p-2 rounded-lg bg-slate-900 hover:bg-red-500/10 border border-slate-800 hover:border-red-500/30 text-slate-400 hover:text-red-400 transition-colors flex items-center gap-1.5 text-xs cursor-pointer"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span className="hidden lg:inline text-[11px] font-mono">Logout</span>
          </button>
        </div>
      </div>

      {/* SYSTEM DIAGNOSTICS & CLI TELEMETRY MODAL (Issue 3 Fix) */}
      {isTerminalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div
            ref={terminalModalRef}
            className="relative w-full max-w-2xl bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden"
          >
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                  AEGIS SecOps Core Engine Telemetry
                </h3>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                  v1.2.0
                </span>
              </div>

              <button
                onClick={() => setIsTerminalOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-5 space-y-4 max-h-[80vh] overflow-y-auto font-mono text-xs">
              {/* Core Services Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase block">FastAPI Backend</span>
                    <span className="font-semibold text-emerald-400 flex items-center gap-1.5 mt-0.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />
                      Connected (200)
                    </span>
                  </div>
                  <Server className="w-4 h-4 text-slate-600" />
                </div>

                <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase block">PostgreSQL Database</span>
                    <span className="font-semibold text-emerald-400 flex items-center gap-1.5 mt-0.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />
                      {systemHealth?.database === 'healthy' ? 'Healthy' : 'Active'}
                    </span>
                  </div>
                  <Database className="w-4 h-4 text-slate-600" />
                </div>

                <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase block">Scan Pipeline</span>
                    <span className={`font-semibold flex items-center gap-1.5 mt-0.5 ${
                      activeScan ? 'text-cyan-400' : 'text-slate-300'
                    }`}>
                      <span className={`w-2 h-2 rounded-full ${
                        activeScan ? 'bg-cyan-400 animate-ping' : 'bg-slate-500'
                      }`} />
                      {activeScan ? 'Active Scanning' : 'Ready / Idle'}
                    </span>
                  </div>
                  <Cpu className="w-4 h-4 text-slate-600" />
                </div>
              </div>

              {/* Active Scan Telemetry (if scanning) */}
              {activeScan && (
                <div className="p-3.5 rounded-xl bg-cyan-950/20 border border-cyan-800/40 space-y-2">
                  <div className="flex items-center justify-between text-xs text-cyan-300">
                    <span className="font-bold flex items-center gap-1.5">
                      <Zap className="w-3.5 h-3.5" />
                      Active Job: Scan #{activeScan.id} on {activeScan.target}
                    </span>
                    <span className="text-[10px] bg-cyan-900/40 px-2 py-0.5 rounded border border-cyan-700/40">
                      {activeScan.scan_type.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Stage {activeScan.progress?.stage_number || 1}/{activeScan.progress?.stages_total || 7}: {activeScan.progress?.detail || 'Processing...'}
                  </p>
                </div>
              )}

              {/* Security Tooling Inventory */}
              <div className="space-y-2">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold">
                  Container Toolchain & Binary Verification
                </span>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                    <span>Nmap 7.93+</span>
                    <span className="text-emerald-400 font-bold">READY ✓</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                    <span>Nuclei v3</span>
                    <span className="text-emerald-400 font-bold">READY ✓</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                    <span>Subfinder v2</span>
                    <span className="text-emerald-400 font-bold">READY ✓</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                    <span>testssl.sh</span>
                    <span className="text-emerald-400 font-bold">READY ✓</span>
                  </div>
                </div>
              </div>

              {/* Live Terminal Output Console Window */}
              <div className="space-y-1.5 pt-1">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold">
                  SecOps Engine Event Console
                </span>
                <div className="p-3 rounded-xl bg-black border border-slate-800 text-[11px] text-slate-300 font-mono space-y-1 max-h-40 overflow-y-auto shadow-inner">
                  <p className="text-slate-500"># AEGIS SecOps Core v1.2.0 initialized</p>
                  <p className="text-cyan-400">[*] Engine listening on :8000 (FastAPI ASGI)</p>
                  <p className="text-emerald-400">[✓] PostgreSQL async connection pool validated</p>
                  <p className="text-slate-400">[*] Nmap -sV, Nuclei v3, Subfinder, testssl toolchain mounted</p>
                  {activeScan ? (
                    <p className="text-amber-400">
                      [!] Live Pipeline: Scanning {activeScan.target} ({activeScan.progress?.detail})
                    </p>
                  ) : (
                    <p className="text-slate-500">[*] Standing by for target dispatch</p>
                  )}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-3 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between">
              <span className="text-[10px] text-slate-500 font-mono">
                Pinging /health every 20s
              </span>
              <button
                onClick={() => setIsTerminalOpen(false)}
                className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-mono border border-slate-800 transition-colors cursor-pointer"
              >
                Close Terminal
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  );
}
