import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Assets from './pages/Assets';
import Scans from './pages/Scans';
import Vulnerabilities from './pages/Vulnerabilities';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Loader2 } from 'lucide-react';

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

function AppLayout() {
  return (
    <div className="flex h-screen w-full bg-slate-900 text-slate-100 overflow-hidden font-sans">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Topbar />
        <main className="flex-1 overflow-y-auto p-8 bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950">
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
    <BrowserRouter>
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
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
