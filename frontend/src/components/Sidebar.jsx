import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { 
  Shield, 
  LayoutDashboard, 
  Server, 
  ShieldAlert, 
  Activity, 
  FileText,
  Cpu
} from 'lucide-react';

export default function Sidebar() {
  const location = useLocation();
  const navigate = useNavigate();

  const navItems = [
    { id: 'dashboard', path: '/', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'assets', path: '/assets', label: 'Assets', icon: Server },
    { id: 'vulnerabilities', path: '/vulns', label: 'Vulnerabilities', icon: ShieldAlert },
    { id: 'scans', path: '/scans', label: 'Scans', icon: Activity },
    { id: 'reports', path: '/reports', label: 'Reports', icon: FileText },
  ];

  return (
    <aside className="w-64 bg-slate-950/80 backdrop-blur-md border-r border-slate-800 flex flex-col h-screen select-none shrink-0">
      {/* Brand Header */}
      <div 
        onClick={() => navigate('/')}
        className="h-16 flex items-center px-6 gap-3 border-b border-slate-800/80 bg-slate-950 cursor-pointer"
      >
        <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
          <Shield className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <span className="font-bold text-lg tracking-wider text-white">AEGIS</span>
          <span className="text-[10px] block uppercase font-mono tracking-widest text-cyan-400 font-semibold -mt-1">
            SecOps Core
          </span>
        </div>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 px-3 py-6 space-y-1.5 overflow-y-auto">
        <div className="px-3 pb-2 text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-500">
          Navigation
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = location.pathname === item.path || 
            (item.id === 'vulnerabilities' && location.pathname.startsWith('/vuln'));
          return (
            <button
              key={item.id}
              onClick={() => navigate(item.path)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 group relative cursor-pointer ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-[0_0_12px_rgba(6,182,212,0.12)]'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
              }`}
            >
              {isActive && (
                <span className="absolute left-0 top-1.5 bottom-1.5 w-1 bg-cyan-400 rounded-r shadow-[0_0_8px_#22d3ee]" />
              )}
              <Icon
                className={`w-4 h-4 transition-transform group-hover:scale-110 ${
                  isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-200'
                }`}
              />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Bottom Telemetry Footer */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-950/60">
        <div className="rounded-lg bg-slate-900/90 border border-slate-800 p-3 text-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-slate-400 font-mono text-[11px] flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" /> Engine
            </span>
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              v1.0.0
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1 border-t border-slate-800">
            <span>Framework</span>
            <span className="text-slate-400">FastAPI + React</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
