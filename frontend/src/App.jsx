import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Login from './pages/Login';
import Register from './pages/Register';
import { AuthProvider, useAuth } from './context/AuthContext';
import { 
  ShieldCheck, 
  Activity, 
  Layers, 
  CheckCircle2, 
  Lock,
  Loader2
} from 'lucide-react';

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen w-full flex flex-col items-center justify-center bg-slate-900 text-slate-100 font-mono">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mb-4" />
        <span className="text-xs uppercase tracking-widest text-slate-400">Verifying Security Credentials...</span>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

function DashboardShell() {
  const [currentNav, setCurrentNav] = useState('dashboard');
  const [backendHealth, setBackendHealth] = useState(null);

  useEffect(() => {
    fetch('/health')
      .then((res) => res.json())
      .then((data) => setBackendHealth(data))
      .catch(() => {
        setBackendHealth({ status: 'offline' });
      });
  }, []);

  return (
    <div className="flex h-screen w-full bg-slate-900 text-slate-100 overflow-hidden font-sans">
      <Sidebar currentNav={currentNav} setCurrentNav={setCurrentNav} />

      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Topbar />

        <main className="flex-1 overflow-y-auto p-8 bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950">
          <div className="max-w-6xl mx-auto space-y-6">
            
            {/* Header banner */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-6 backdrop-blur shadow-lg relative overflow-hidden">
              <div className="absolute -top-24 -right-24 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
              
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
                <div>
                  <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-mono mb-3">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                    PHASE 2 AUTHENTICATION ACTIVE
                  </div>
                  <h2 className="text-2xl font-bold tracking-tight text-white">
                    Dashboard coming in Phase 5
                  </h2>
                  <p className="text-sm text-slate-400 mt-1 max-w-xl">
                    JWT Session & Role-Based Access Control verified. Network asset inventory and Nmap scanner engines will be activated in upcoming phases.
                  </p>
                </div>

                <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
                  <div className="px-4 py-2.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs font-mono">
                    <span className="text-slate-400">System Status:</span>{' '}
                    <span className="text-emerald-400 font-semibold uppercase">
                      {backendHealth?.status === 'ok' ? 'HEALTHY' : 'READY'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Platform Metrics / Readiness Overview */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
              <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-5 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between pb-3">
                  <span className="text-xs font-mono uppercase text-slate-400">Security Core</span>
                  <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
                    <Lock className="w-4 h-4" />
                  </div>
                </div>
                <div className="text-xl font-bold text-white font-mono">JWT Bearer (HS256)</div>
                <p className="text-xs text-slate-400 mt-2">
                  Stateless authenticated session handling with bcrypt password protection.
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-5 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between pb-3">
                  <span className="text-xs font-mono uppercase text-slate-400">Asset Management</span>
                  <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
                    <Layers className="w-4 h-4" />
                  </div>
                </div>
                <div className="text-xl font-bold text-white font-mono">Phase 3: Inventory</div>
                <p className="text-xs text-slate-400 mt-2">
                  Full CRUD network asset repository and classification scheduled next.
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-5 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between pb-3">
                  <span className="text-xs font-mono uppercase text-slate-400">Threat Intelligence</span>
                  <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400">
                    <Activity className="w-4 h-4" />
                  </div>
                </div>
                <div className="text-xl font-bold text-white font-mono">Phase 4: Nmap & NVD</div>
                <p className="text-xs text-slate-400 mt-2">
                  Automated host scanning and CVE vulnerability lookup pipeline.
                </p>
              </div>
            </div>

            {/* Execution Roadmap Sequence */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-6">
              <h3 className="text-sm font-semibold text-white uppercase tracking-wider font-mono mb-4 flex items-center gap-2">
                <span>Platform Roadmap Sequence</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-lg bg-emerald-500/5 border border-emerald-500/30">
                  <div className="flex items-center justify-between text-xs font-mono mb-1">
                    <span className="text-emerald-400 font-bold">Phase 0</span>
                    <span className="text-emerald-400 flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Complete
                    </span>
                  </div>
                  <h4 className="text-sm font-semibold text-slate-200">Project Foundation</h4>
                  <p className="text-xs text-slate-400 mt-1">Docker Compose, FastAPI, React Shell</p>
                </div>

                <div className="p-4 rounded-lg bg-emerald-500/5 border border-emerald-500/30">
                  <div className="flex items-center justify-between text-xs font-mono mb-1">
                    <span className="text-emerald-400 font-bold">Phase 1</span>
                    <span className="text-emerald-400 flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Complete
                    </span>
                  </div>
                  <h4 className="text-sm font-semibold text-slate-200">Database Models</h4>
                  <p className="text-xs text-slate-400 mt-1">SQLAlchemy schemas & Alembic migrations</p>
                </div>

                <div className="p-4 rounded-lg bg-cyan-500/5 border border-cyan-500/30">
                  <div className="flex items-center justify-between text-xs font-mono mb-1">
                    <span className="text-cyan-400 font-bold">Phase 2</span>
                    <span className="text-cyan-400 flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Active
                    </span>
                  </div>
                  <h4 className="text-sm font-semibold text-slate-200">Authentication</h4>
                  <p className="text-xs text-slate-400 mt-1">JWT Bearer tokens & role security</p>
                </div>

                <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
                  <div className="flex items-center justify-between text-xs font-mono mb-1">
                    <span className="text-slate-400 font-bold">Phase 3</span>
                    <span className="text-slate-500">Upcoming</span>
                  </div>
                  <h4 className="text-sm font-semibold text-slate-200">Asset Inventory</h4>
                  <p className="text-xs text-slate-400 mt-1">CRUD operations & network mapping</p>
                </div>
              </div>
            </div>

          </div>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <DashboardShell />
              </ProtectedRoute>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
