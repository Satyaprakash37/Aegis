import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, AlertCircle, ArrowRight, Loader2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!email || !password) {
      setError('Please provide both email and password.');
      return;
    }

    setSubmitting(true);
    try {
      await login(email, password);
      navigate('/');
    } catch (err) {
      if (err.response) {
        if (err.response.status === 401) {
          setError('Invalid credentials. Please verify your email and password.');
        } else if (err.response.data && err.response.data.detail) {
          setError(err.response.data.detail);
        } else {
          setError('Authentication failed. Please verify credentials.');
        }
      } else {
        setError('Network error: Unable to reach AEGIS authentication gateway.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-slate-900 text-slate-100 px-4 relative overflow-hidden">
      {/* Background Ambience */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md bg-slate-950/80 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-2xl p-8 relative z-10">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.2)] mb-4">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white font-mono">AEGIS SEC-OPS</h1>
          <p className="text-xs text-slate-400 mt-1 uppercase tracking-widest font-mono">
            Vulnerability Management Access Gateway
          </p>
        </div>

        {/* Error Notification */}
        {error && (
          <div className="mb-6 p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-start gap-2.5 animate-in fade-in duration-200">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-mono font-medium text-slate-300 uppercase tracking-wider mb-2">
              Operator Email
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@aegis.internal"
                className="w-full pl-10 pr-4 py-2.5 bg-slate-900 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all font-sans"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono font-medium text-slate-300 uppercase tracking-wider mb-2">
              Security Key / Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-10 pr-4 py-2.5 bg-slate-900 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all font-sans"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full mt-2 py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition-all duration-150 flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(6,182,212,0.3)] disabled:opacity-60 disabled:cursor-not-allowed cursor-pointer"
          >
            {submitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Authenticating...</span>
              </>
            ) : (
              <>
                <span>Sign In to Terminal</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        {/* Footer Link */}
        <div className="mt-8 text-center pt-5 border-t border-slate-800/80">
          <p className="text-xs text-slate-400">
            Unregistered analyst?{' '}
            <Link
              to="/register"
              className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
            >
              Create Account
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
