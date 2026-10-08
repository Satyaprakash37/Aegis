import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet, useLocation } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Assets from './pages/Assets';
import Scans from './pages/Scans';
import Vulnerabilities from './pages/Vulnerabilities';
import Reports from './pages/Reports';
import NotFound from './pages/NotFound';
import ErrorBoundary from './components/ErrorBoundary';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Loader2 } from 'lucide-react';

function PageTitleUpdater() {
  const location = useLocation();

  useEffect(() => {
    const titles = {
      '/': 'AEGIS | Security Operations Dashboard',
      '/assets': 'AEGIS | Asset Inventory',
      '/scans': 'AEGIS | Vulnerability Scanners',
      '/vulns': 'AEGIS | Vulnerability Register',
      '/vulnerabilities': 'AEGIS | Vulnerability Register',
      '/reports': 'AEGIS | Compliance & Audit Reports',
      '/login': 'AEGIS | Authentication Portal',
      '/register': 'AEGIS | Analyst Registration',
    };

    document.title = titles[location.pathname] || 'AEGIS | Vulnerability Management Platform';
  }, [location]);

  return null;
}

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen w-full flex flex-col items-center justify-center bg-[#0b1220] text-slate-100 font-mono">
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

function AppLayout() {
  return (
    <div className="flex h-screen w-full bg-[#0b1220] text-slate-100 overflow-hidden font-sans">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Topbar />
        <main className="flex-1 overflow-y-auto p-8 bg-gradient-to-b from-[#0f172a] via-[#0b1220] to-[#080d18]">
          <div className="max-w-6xl mx-auto">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <PageTitleUpdater />
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <AppLayout />
                </ProtectedRoute>
              }
            >
              <Route index element={<Dashboard />} />
              <Route path="assets" element={<Assets />} />
              <Route path="scans" element={<Scans />} />
              <Route path="vulns" element={<Vulnerabilities />} />
              <Route path="vulnerabilities" element={<Vulnerabilities />} />
              <Route path="reports" element={<Reports />} />
            </Route>
            <Route path="/404" element={<NotFound />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
