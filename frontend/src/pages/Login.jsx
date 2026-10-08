import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { 
  Shield, 
  Lock, 
  Mail, 
  AlertCircle, 
  ArrowRight, 
  Loader2, 
  Clock, 
  Check, 
  Info 
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

export default function Login() {
  const [searchParams] = useSearchParams();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState({ email: '', password: '' });
  const [submitting, setSubmitting] = useState(false);

  // Lockout state with countdown
  const [lockoutUntil, setLockoutUntil] = useState(null);
  const [remainingLockoutSecs, setRemainingLockoutSecs] = useState(0);

  const { login } = useAuth();
  const navigate = useNavigate();

  // Pre-fill email from URL query if provided (e.g. from registration redirect)
  useEffect(() => {
    const queryEmail = searchParams.get('email');
    if (queryEmail) {
      setEmail(queryEmail.trim().toLowerCase());
    }
  }, [searchParams]);

  // Lockout timer ticking
  useEffect(() => {
    if (!lockoutUntil) {
      setRemainingLockoutSecs(0);
      return;
    }

    const updateTimer = () => {
      const diffSecs = Math.max(0, Math.ceil((lockoutUntil - Date.now()) / 1000));
      setRemainingLockoutSecs(diffSecs);
      if (diffSecs <= 0) {
        setLockoutUntil(null);
        setError('');
      }
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [lockoutUntil]);

  const formatCountdown = (secs) => {
    const mins = Math.floor(secs / 60);
    const s = secs % 60;
    if (mins > 0) {
      return `${mins}m ${s < 10 ? '0' : ''}${s}s`;
    }
    return `${s}s`;
  };

  const cleanedEmail = email.trim().toLowerCase();
  const isEmailFilled = cleanedEmail.length > 0;
  const isEmailFormatValid = EMAIL_REGEX.test(cleanedEmail);
  const isLockedOut = remainingLockoutSecs > 0;

  const isFormValid = isEmailFilled && isEmailFormatValid && password.length > 0 && !isLockedOut;

  const handleEmailChange = (val) => {
    setEmail(val.trim());
    if (fieldErrors.email) setFieldErrors((prev) => ({ ...prev, email: '' }));
  };

  const handlePasswordChange = (val) => {
    setPassword(val);
    if (fieldErrors.password) setFieldErrors((prev) => ({ ...prev, password: '' }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setFieldErrors({ email: '', password: '' });

    if (isLockedOut) {
      return;
    }

    if (!cleanedEmail || !password) {
      setError('Please provide both operator email and password.');
      return;
    }

    if (!isEmailFormatValid) {
      setFieldErrors((prev) => ({ ...prev, email: 'Please enter a valid email format.' }));
      return;
    }

    setSubmitting(true);
    try {
      await login(cleanedEmail, password);
      navigate('/');
    } catch (err) {
      if (err.response) {
        const status = err.response.status;
        const resData = err.response.data;
        const detailMsg = typeof resData?.detail === 'string' ? resData.detail : '';

        if (status === 403) {
          // Account lockout
          const minMatch = detailMsg.match(/in (\d+) minute/i);
          const minutes = minMatch ? parseInt(minMatch[1], 10) : 15;
          setLockoutUntil(Date.now() + minutes * 60 * 1000);
          setError(detailMsg || 'Account temporarily locked due to consecutive failed attempts.');
        } else if (status === 401) {
          // Bad credentials with remaining attempts
          setError(detailMsg || 'Invalid credentials. Please verify your email and password.');
        } else if (status === 429) {
          setError('Too many login attempts. For security reasons, please wait a moment before trying again.');
        } else if (status === 422 && Array.isArray(resData?.detail)) {
          const newErrors = { email: '', password: '' };
          resData.detail.forEach((item) => {
            const loc = item.loc || [];
            if (loc.includes('username') || loc.includes('email')) {
              newErrors.email = item.msg?.replace(/^Value error,\s*/i, '');
            } else if (loc.includes('password')) {
              newErrors.password = item.msg?.replace(/^Value error,\s*/i, '');
            }
          });
          setFieldErrors(newErrors);
        } else {
          setError(detailMsg || 'Authentication failed. Please verify credentials.');
        }
      } else {
        setError('Network error: Unable to reach AEGIS authentication gateway.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-[#0b1220] text-slate-100 px-4 py-10 relative overflow-hidden">
      {/* Background Ambience */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md bg-[#111a2e]/90 backdrop-blur-xl border border-white/10 rounded-2xl shadow-2xl p-6 sm:p-8 relative z-10">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-6">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.2)] mb-3">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white font-mono">AEGIS SEC-OPS</h1>
          <p className="text-xs text-slate-400 mt-1 uppercase tracking-widest font-mono">
            Vulnerability Management Access Gateway
          </p>
        </div>

        {/* Lockout Notification Card */}
        {isLockedOut ? (
          <div className="mb-5 p-4 rounded-xl bg-rose-500/15 border border-rose-500/40 text-rose-300 text-xs space-y-2.5 animate-in fade-in duration-200">
            <div className="flex items-center gap-2 font-bold text-rose-400 font-mono">
              <Lock className="w-4 h-4 text-rose-400 shrink-0" />
              <span>ACCOUNT TEMPORARILY LOCKED</span>
            </div>
            <p className="text-slate-300 font-sans leading-relaxed">
              Too many consecutive failed login attempts detected. For security protection, authentication is temporarily locked.
            </p>
            <div className="flex items-center gap-2 font-mono text-white text-xs bg-slate-950/70 px-3 py-2 rounded-lg border border-rose-500/30">
              <Clock className="w-4 h-4 text-rose-400 shrink-0 animate-spin" />
              <span>Retry permitted in: <strong className="text-rose-400">{formatCountdown(remainingLockoutSecs)}</strong></span>
            </div>
          </div>
        ) : error ? (
          <div className="mb-5 p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-start gap-2.5 animate-in fade-in duration-200">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
            <span>{error}</span>
          </div>
        ) : null}

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Operator Email */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-xs font-mono font-medium text-slate-300 uppercase tracking-wider">
                Operator Email *
              </label>
              {isEmailFilled && (
                <div className="flex items-center gap-1 text-[11px] font-mono">
                  {isEmailFormatValid ? (
                    <span className="text-emerald-400 flex items-center gap-1">
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span>Valid</span>
                    </span>
                  ) : (
                    <span className="text-amber-400">Invalid format</span>
                  )}
                </div>
              )}
            </div>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
              <input
                type="email"
                required
                disabled={isLockedOut}
                value={email}
                onChange={(e) => handleEmailChange(e.target.value)}
                placeholder="analyst@aegis.internal"
                className={`w-full pl-10 pr-4 py-2.5 bg-slate-900 border rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none transition-all font-sans disabled:opacity-60 disabled:cursor-not-allowed ${
                  fieldErrors.email || (isEmailFilled && !isEmailFormatValid)
                    ? 'border-red-500/80 focus:border-red-500 focus:ring-1 focus:ring-red-500/50'
                    : isEmailFormatValid
                    ? 'border-emerald-500/50 focus:border-emerald-400 focus:ring-1 focus:ring-emerald-400/50'
                    : 'border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500'
                }`}
              />
            </div>
            {fieldErrors.email && (
              <p className="mt-1.5 text-xs text-red-400 flex items-center gap-1 font-mono">
                <AlertCircle className="w-3 h-3 text-red-400 shrink-0" />
                <span>{fieldErrors.email}</span>
              </p>
            )}
            {isEmailFilled && !isEmailFormatValid && !fieldErrors.email && (
              <p className="mt-1.5 text-xs text-amber-400 flex items-center gap-1 font-mono">
                <Info className="w-3 h-3 text-amber-400 shrink-0" />
                <span>Format: analyst@domain.com</span>
              </p>
            )}
          </div>

          {/* Security Key / Password */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-xs font-mono font-medium text-slate-300 uppercase tracking-wider">
                Security Key / Password *
              </label>
            </div>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
              <input
                type="password"
                required
                disabled={isLockedOut}
                value={password}
                onChange={(e) => handlePasswordChange(e.target.value)}
                placeholder="••••••••••••"
                className={`w-full pl-10 pr-4 py-2.5 bg-slate-900 border rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none transition-all font-sans disabled:opacity-60 disabled:cursor-not-allowed ${
                  fieldErrors.password
                    ? 'border-red-500/80 focus:border-red-500 focus:ring-1 focus:ring-red-500/50'
                    : 'border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500'
                }`}
              />
            </div>
            {fieldErrors.password && (
              <p className="mt-1.5 text-xs text-red-400 flex items-center gap-1 font-mono">
                <AlertCircle className="w-3 h-3 text-red-400 shrink-0" />
                <span>{fieldErrors.password}</span>
              </p>
            )}
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={submitting || !isFormValid}
            aria-disabled={submitting || !isFormValid}
            title={
              isLockedOut
                ? `Account temporarily locked (${formatCountdown(remainingLockoutSecs)} remaining)`
                : !isFormValid
                ? 'Please enter valid credentials'
                : 'Sign In'
            }
            className="w-full mt-3 py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition-all duration-150 flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(6,182,212,0.3)] disabled:opacity-40 disabled:hover:bg-cyan-500 disabled:shadow-none disabled:cursor-not-allowed cursor-pointer"
          >
            {submitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Authenticating...</span>
              </>
            ) : isLockedOut ? (
              <>
                <Lock className="w-4 h-4" />
                <span>Locked ({formatCountdown(remainingLockoutSecs)})</span>
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
        <div className="mt-6 text-center pt-5 border-t border-slate-800/80">
          <p className="text-xs text-slate-400">
            Unregistered analyst?{' '}
            <Link
              to="/register"
              className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors font-mono"
            >
              Enroll Operator
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
