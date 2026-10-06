import React, { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, ArrowLeft, Terminal, Radar } from 'lucide-react';

export default function NotFound() {
  useEffect(() => {
    document.title = 'AEGIS | 404 Not Found';
  }, []);

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-slate-950 p-6 text-slate-100 font-sans relative overflow-hidden">
      {/* Background ambient grid/glow */}
      <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-40 pointer-events-none" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="max-w-md w-full bg-slate-900/80 border border-slate-800 rounded-2xl p-8 shadow-2xl backdrop-blur-xl relative z-10 text-center">
        <div className="inline-flex p-4 bg-cyan-500/10 border border-cyan-500/20 rounded-2xl text-cyan-400 mb-6 shadow-inner">
          <ShieldAlert className="w-12 h-12 stroke-[1.5]" />
        </div>

        <div className="inline-block px-2.5 py-1 mb-3 rounded-full bg-slate-800 border border-slate-700 text-xs font-mono text-cyan-400 font-semibold tracking-wider">
          HTTP 404 // ROUTE_UNRESOLVED
        </div>

        <h1 className="text-3xl font-extrabold tracking-tight text-white mb-2">
          Sector Not Found
        </h1>
        <p className="text-sm text-slate-400 mb-8 leading-relaxed">
          The requested coordinate or security resource does not exist within the current AEGIS defense perimeter.
        </p>

        <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80 font-mono text-xs text-left mb-8 space-y-1">
          <div className="flex items-center gap-2 text-slate-500">
            <Terminal className="w-3.5 h-3.5 text-cyan-500" />
            <span>aegis-core://dns-lookup</span>
          </div>
          <div className="text-rose-400 pl-5">
            Error: ENOENT - Target path unrouted
          </div>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <Link
            to="/"
            className="flex-1 flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-all shadow-lg shadow-cyan-950/60"
          >
            <ArrowLeft className="w-4 h-4" />
            Return to Base
          </Link>
          <Link
            to="/vulns"
            className="flex-1 flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-medium text-sm transition-colors"
          >
            <Radar className="w-4 h-4" />
            Threat Register
          </Link>
        </div>
      </div>
    </div>
  );
}
