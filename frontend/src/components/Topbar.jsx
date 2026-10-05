import React from 'react';
import { Bell, ShieldCheck, Terminal, User } from 'lucide-react';

export default function Topbar() {
  return (
    <header className="h-16 bg-slate-950/70 backdrop-blur-md border-b border-slate-800 px-8 flex items-center justify-between sticky top-0 z-20">
      {/* App Name and Status */}
      <div className="flex items-center gap-4">
        <h1 className="text-base font-semibold text-slate-100 flex items-center gap-2">
          <span>AEGIS</span>
          <span className="text-slate-600">/</span>
          <span className="text-slate-400 font-normal text-sm">Vulnerability Management Platform</span>
        </h1>
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
          SOC ACTIVE
        </span>
      </div>

      {/* Right Action Icons & Avatar */}
      <div className="flex items-center gap-4">
        <button
          title="Terminal Logs"
          className="w-9 h-9 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700 flex items-center justify-center transition-colors"
        >
          <Terminal className="w-4 h-4" />
        </button>

        <button
          title="Alerts"
          className="w-9 h-9 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700 flex items-center justify-center transition-colors relative"
        >
          <Bell className="w-4 h-4" />
          <span className="absolute top-2 right-2 w-1.5 h-1.5 bg-cyan-400 rounded-full" />
        </button>

        <div className="h-5 w-px bg-slate-800 mx-1" />

        {/* User Profile / Avatar */}
        <div className="flex items-center gap-3 pl-1">
          <div className="w-9 h-9 rounded-full bg-gradient-to-tr from-cyan-600 to-blue-500 p-[1.5px] shadow-[0_0_10px_rgba(6,182,212,0.2)]">
            <div className="w-full h-full rounded-full bg-slate-950 flex items-center justify-center text-xs font-bold font-mono text-cyan-300">
              AG
            </div>
          </div>
          <div className="hidden md:flex flex-col text-left">
            <span className="text-xs font-semibold text-slate-200">Security Analyst</span>
            <span className="text-[10px] font-mono text-slate-500">secops@aegis.internal</span>
          </div>
        </div>
      </div>
    </header>
  );
}
