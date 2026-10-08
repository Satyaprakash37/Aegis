import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { 
  Shield, 
  Lock, 
  Mail, 
  User, 
  AlertCircle, 
  ArrowRight, 
  Loader2, 
  CheckCircle2, 
  Check, 
  X, 
  Info,
  ExternalLink
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

// Common disposable email domains (~20 common services)
const DISPOSABLE_EMAIL_DOMAINS = new Set([
  '10minutemail.com',
  'tempmail.com',
  'guerrillamail.com',
  'mailinator.com',
  'throwawaymail.com',
  'sharklasers.com',
  'yopmail.com',
  'dispostable.com',
  'getairmail.com',
  'mohmal.com',
  'trashmail.com',
  'temp-mail.org',
  'fakeinbox.com',
  'maildrop.cc',
  'inboxkitten.com',
  'mytemp.email',
  'burnermail.io',
  'trashmail.net',
  'dropmail.me',
  'nada.ltd',
]);

const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

export default function Register() {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  // Field-level server & validation errors
  const [fieldErrors, setFieldErrors] = useState({
    fullName: '',
    email: '',
    password: '',
    confirmPassword: '',
  });

  const [generalError, setGeneralError] = useState('');
  const [showAlreadyRegisteredHint, setShowAlreadyRegisteredHint] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const { register } = useAuth();
  const navigate = useNavigate();

  // --- Real-Time Field Computations ---
  const cleanedEmail = email.trim().toLowerCase();
  const isEmailFilled = cleanedEmail.length > 0;
  const isEmailFormatValid = EMAIL_REGEX.test(cleanedEmail);
  const emailDomain = cleanedEmail.includes('@') ? cleanedEmail.split('@')[1] : '';
  const isDisposableDomain = DISPOSABLE_EMAIL_DOMAINS.has(emailDomain);
  const isEmailValid = isEmailFormatValid && !isDisposableDomain;

  // Password rules
  const hasMinLength = password.length >= 12;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]/.test(password);

  const cleanHandle = cleanedEmail.split('@')[0]?.replace(/[^a-z0-9]/g, '') || '';
  const hasEmailInPassword = cleanHandle.length >= 3 && password.toLowerCase().includes(cleanHandle);

  const isPasswordValid = hasMinLength && hasUpper && hasLower && hasDigit && hasSpecial && !hasEmailInPassword;

  // Confirm password
  const isConfirmFilled = confirmPassword.length > 0;
  const isPasswordsMatch = isConfirmFilled && password === confirmPassword;
  const isPasswordsMismatch = isConfirmFilled && password !== confirmPassword;

  // Form validity
  const isFormValid = fullName.trim().length > 0 && isEmailValid && isPasswordValid && isPasswordsMatch;

  // Reason tooltip for disabled submit button
  const getDisabledReason = () => {
    if (!fullName.trim()) return 'Please enter your full name.';
    if (!isEmailFilled) return 'Please enter an operator email address.';
    if (!isEmailFormatValid) return 'Please enter a valid email format (e.g. analyst@company.com).';
    if (isDisposableDomain) return 'Disposable email domains are not allowed.';
    if (!hasMinLength) return 'Password must contain at least 12 characters.';
    if (!hasUpper || !hasLower || !hasDigit || !hasSpecial) return 'Password must satisfy all complexity requirements.';
    if (hasEmailInPassword) return 'Password cannot contain your email username handle.';
    if (!isConfirmFilled) return 'Please confirm your password.';
    if (isPasswordsMismatch) return 'Passwords do not match.';
    return '';
  };

  const handleFullNameChange = (val) => {
    setFullName(val);
    if (fieldErrors.fullName) setFieldErrors((prev) => ({ ...prev, fullName: '' }));
  };

  const handleEmailChange = (val) => {
    setEmail(val.trim());
    setShowAlreadyRegisteredHint(false);
    if (fieldErrors.email) setFieldErrors((prev) => ({ ...prev, email: '' }));
  };

  const handlePasswordChange = (val) => {
    setPassword(val);
    if (fieldErrors.password) setFieldErrors((prev) => ({ ...prev, password: '' }));
  };

  const handleConfirmPasswordChange = (val) => {
    setConfirmPassword(val);
    if (fieldErrors.confirmPassword) setFieldErrors((prev) => ({ ...prev, confirmPassword: '' }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setGeneralError('');
    setShowAlreadyRegisteredHint(false);
    setFieldErrors({ fullName: '', email: '', password: '', confirmPassword: '' });

    if (!isFormValid) {
      return;
    }

    setSubmitting(true);
    try {
      await register(fullName.trim(), cleanedEmail, password);
      navigate('/');
    } catch (err) {
      if (err.response) {
        const status = err.response.status;
        const resData = err.response.data;

        if (status === 422 && Array.isArray(resData?.detail)) {
          // Pydantic validation error breakdown
          const newFieldErrors = { fullName: '', email: '', password: '', confirmPassword: '' };
          resData.detail.forEach((item) => {
            const loc = item.loc || [];
            const rawMsg = item.msg || '';
            const cleanMsg = rawMsg.replace(/^Value error,\s*/i, '');

            if (loc.includes('email')) {
              newFieldErrors.email = cleanMsg;
            } else if (loc.includes('password')) {
              newFieldErrors.password = cleanMsg;
            } else if (loc.includes('full_name')) {
              newFieldErrors.fullName = cleanMsg;
            }
          });
          setFieldErrors(newFieldErrors);
        } else if (status === 400 || status === 409) {
          // Anti-enumeration registration failure (likely already existing account)
          setShowAlreadyRegisteredHint(true);
          setFieldErrors((prev) => ({
            ...prev,
            email: 'Unable to register this email. If you already have an account, please sign in.',
          }));
        } else if (status === 429) {
          setGeneralError('Too many registration attempts. For security reasons, please wait a few minutes before trying again.');
        } else {
          setGeneralError(typeof resData?.detail === 'string' ? resData.detail : 'Registration failed. Please check your inputs and try again.');
        }
      } else {
        setGeneralError('Network error: Unable to contact the AEGIS registration service.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-[#0b1220] text-slate-100 px-4 py-10 relative overflow-hidden">
      {/* Background Ambience */}
      <div className="absolute -top-40 -right-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-lg bg-[#111a2e]/90 backdrop-blur-xl border border-white/10 rounded-2xl shadow-2xl p-6 sm:p-8 relative z-10">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-6">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.2)] mb-3">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white font-mono">ENROLL OPERATOR</h1>
          <p className="text-xs text-slate-400 mt-1 uppercase tracking-widest font-mono">
            AEGIS Security Role Provisioning
          </p>
        </div>

        {/* First user alert info */}
        <div className="mb-5 p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-cyan-400" />
          <span>First user registered is auto-assigned Security Administrator role.</span>
        </div>

        {/* General Error Banner */}
        {generalError && (
          <div className="mb-5 p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-start gap-2.5 animate-in fade-in duration-200">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
            <span>{generalError}</span>
          </div>
        )}

        {/* Safe Anti-Enumeration UX Hint for Existing Email */}
        {showAlreadyRegisteredHint && (
          <div className="mb-5 p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs space-y-2.5 animate-in fade-in duration-200">
            <div className="flex items-center gap-2 font-semibold text-amber-300 font-mono">
              <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
              <span>REGISTRATION NOTICE</span>
            </div>
            <p className="text-slate-300 leading-relaxed font-sans">
              Registration could not be completed with this email. If you already have an account enrolled in AEGIS, please sign in instead.
            </p>
            <div className="pt-1 flex items-center justify-between">
              <Link
                to={`/login?email=${encodeURIComponent(cleanedEmail)}`}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs transition-colors cursor-pointer"
              >
                <span>Sign In to Existing Account</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
              <button
                type="button"
                onClick={() => setShowAlreadyRegisteredHint(false)}
                className="text-[11px] font-mono text-slate-400 hover:text-white transition-colors"
              >
                Dismiss
              </button>
            </div>
          </div>
        )}

        {/* Register Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Full Name */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-xs font-mono font-medium text-slate-300 uppercase tracking-wider">
                Full Name *
              </label>
              {fullName.trim().length > 0 && (
                <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
                  <Check className="w-3 h-3 text-emerald-400" />
                  <span>Valid</span>
                </span>
              )}
            </div>
            <div className="relative">
              <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
              <input
                type="text"
                required
                value={fullName}
                onChange={(e) => handleFullNameChange(e.target.value)}
                placeholder="Jane Doe"
                className={`w-full pl-10 pr-4 py-2.5 bg-slate-900 border rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none transition-all font-sans ${
                  fieldErrors.fullName
                    ? 'border-red-500/80 focus:border-red-500 focus:ring-1 focus:ring-red-500/50'
                    : fullName.trim().length > 0
                    ? 'border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500'
                    : 'border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500'
                }`}
              />
            </div>
            {fieldErrors.fullName && (
              <p className="mt-1.5 text-xs text-red-400 flex items-center gap-1 font-mono">
                <AlertCircle className="w-3 h-3 text-red-400 shrink-0" />
                <span>{fieldErrors.fullName}</span>
              </p>
            )}
          </div>

          {/* Operator Email */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-xs font-mono font-medium text-slate-300 uppercase tracking-wider">
                Operator Email *
              </label>
              {isEmailFilled && (
                <div className="flex items-center gap-1 text-[11px] font-mono">
                  {isEmailValid ? (
                    <span className="text-emerald-400 flex items-center gap-1">
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span>Valid Email</span>
                    </span>
                  ) : isDisposableDomain ? (
                    <span className="text-red-400 flex items-center gap-1">
                      <X className="w-3 h-3 text-red-400" />
                      <span>Disposable Disallowed</span>
                    </span>
                  ) : (
                    <span className="text-amber-400 flex items-center gap-1">
                      <span>Invalid Format</span>
                    </span>
                  )}
                </div>
              )}
            </div>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => handleEmailChange(e.target.value)}
                placeholder="operator@aegis.internal"
                className={`w-full pl-10 pr-4 py-2.5 bg-slate-900 border rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none transition-all font-sans ${
                  fieldErrors.email || (isEmailFilled && !isEmailValid)
                    ? 'border-red-500/80 focus:border-red-500 focus:ring-1 focus:ring-red-500/50'
                    : isEmailValid
                    ? 'border-emerald-500/50 focus:border-emerald-400 focus:ring-1 focus:ring-emerald-400/50'
                    : 'border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500'
                }`}
              />
            </div>
            {/* Field error or format validation notice */}
            {fieldErrors.email ? (
              <p className="mt-1.5 text-xs text-red-400 flex items-center gap-1 font-mono">
                <AlertCircle className="w-3 h-3 text-red-400 shrink-0" />
                <span>{fieldErrors.email}</span>
              </p>
            ) : isEmailFilled && !isEmailFormatValid ? (
              <p className="mt-1.5 text-xs text-amber-400/90 flex items-center gap-1 font-mono">
                <Info className="w-3 h-3 text-amber-400 shrink-0" />
                <span>Please enter a valid RFC-compliant email (e.g. name@domain.com)</span>
              </p>
            ) : isEmailFilled && isDisposableDomain ? (
              <p className="mt-1.5 text-xs text-red-400 flex items-center gap-1 font-mono">
                <AlertCircle className="w-3 h-3 text-red-400 shrink-0" />
                <span>Disposable email domain ({emailDomain}) is blocked. Use a permanent email.</span>
              </p>
            ) : null}
          </div>

          {/* Password with LIVE Requirement Checklist */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-xs font-mono font-medium text-slate-300 uppercase tracking-wider">
                Password *
              </label>
              {password.length > 0 && (
                <span className={`text-[11px] font-mono flex items-center gap-1 ${isPasswordValid ? 'text-emerald-400' : 'text-slate-400'}`}>
                  {isPasswordValid ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span>Requirements Satisfied</span>
                    </>
                  ) : (
                    <span>{hasMinLength ? 'Complexity Pending' : `${password.length}/12 chars`}</span>
                  )}
                </span>
              )}
            </div>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => handlePasswordChange(e.target.value)}
                placeholder="••••••••••••"
                className={`w-full pl-10 pr-4 py-2.5 bg-slate-900 border rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none transition-all font-sans ${
                  fieldErrors.password
                    ? 'border-red-500/80 focus:border-red-500 focus:ring-1 focus:ring-red-500/50'
                    : isPasswordValid
                    ? 'border-emerald-500/50 focus:border-emerald-400 focus:ring-1 focus:ring-emerald-400/50'
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

            {/* LIVE Password Checklist Card */}
            <div className="mt-2.5 p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1.5">
              <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold mb-1 flex items-center justify-between">
                <span>Security Requirements</span>
                <span className={isPasswordValid ? 'text-emerald-400 font-bold' : 'text-slate-500'}>
                  {[hasMinLength, hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length}/5 Met
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 text-[11px] font-mono">
                {/* 12+ chars */}
                <div className={`flex items-center gap-1.5 transition-colors ${hasMinLength ? 'text-emerald-400' : 'text-slate-400'}`}>
                  {hasMinLength ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  ) : (
                    <X className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                  )}
                  <span>12+ characters ({password.length}/12)</span>
                </div>

                {/* Uppercase */}
                <div className={`flex items-center gap-1.5 transition-colors ${hasUpper ? 'text-emerald-400' : 'text-slate-400'}`}>
                  {hasUpper ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  ) : (
                    <X className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                  )}
                  <span>Uppercase letter (A-Z)</span>
                </div>

                {/* Lowercase */}
                <div className={`flex items-center gap-1.5 transition-colors ${hasLower ? 'text-emerald-400' : 'text-slate-400'}`}>
                  {hasLower ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  ) : (
                    <X className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                  )}
                  <span>Lowercase letter (a-z)</span>
                </div>

                {/* Digit */}
                <div className={`flex items-center gap-1.5 transition-colors ${hasDigit ? 'text-emerald-400' : 'text-slate-400'}`}>
                  {hasDigit ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  ) : (
                    <X className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                  )}
                  <span>Numeric digit (0-9)</span>
                </div>

                {/* Special symbol */}
                <div className={`flex items-center gap-1.5 transition-colors ${hasSpecial ? 'text-emerald-400' : 'text-slate-400'}`}>
                  {hasSpecial ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  ) : (
                    <X className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                  )}
                  <span>Special symbol (!@#$...)</span>
                </div>

                {/* No email handle in password */}
                {hasEmailInPassword && (
                  <div className="flex items-center gap-1.5 text-red-400 col-span-2">
                    <X className="w-3.5 h-3.5 text-red-400 shrink-0" />
                    <span>Must not contain email handle ({cleanHandle})</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Confirm Password */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-xs font-mono font-medium text-slate-300 uppercase tracking-wider">
                Confirm Password *
              </label>
              {isConfirmFilled && (
                <div className="flex items-center gap-1 text-[11px] font-mono">
                  {isPasswordsMatch ? (
                    <span className="text-emerald-400 flex items-center gap-1">
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span>Passwords Match</span>
                    </span>
                  ) : (
                    <span className="text-rose-400 flex items-center gap-1">
                      <X className="w-3 h-3 text-rose-400" />
                      <span>Mismatch</span>
                    </span>
                  )}
                </div>
              )}
            </div>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
              <input
                type="password"
                required
                value={confirmPassword}
                onChange={(e) => handleConfirmPasswordChange(e.target.value)}
                placeholder="••••••••••••"
                className={`w-full pl-10 pr-4 py-2.5 bg-slate-900 border rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none transition-all font-sans ${
                  fieldErrors.confirmPassword || isPasswordsMismatch
                    ? 'border-red-500/80 focus:border-red-500 focus:ring-1 focus:ring-red-500/50'
                    : isPasswordsMatch
                    ? 'border-emerald-500/50 focus:border-emerald-400 focus:ring-1 focus:ring-emerald-400/50'
                    : 'border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500'
                }`}
              />
            </div>
            {isPasswordsMismatch && (
              <p className="mt-1.5 text-xs text-rose-400 flex items-center gap-1 font-mono">
                <AlertCircle className="w-3 h-3 text-rose-400 shrink-0" />
                <span>Passwords do not match. Please verify your password confirmation.</span>
              </p>
            )}
            {fieldErrors.confirmPassword && (
              <p className="mt-1.5 text-xs text-red-400 flex items-center gap-1 font-mono">
                <AlertCircle className="w-3 h-3 text-red-400 shrink-0" />
                <span>{fieldErrors.confirmPassword}</span>
              </p>
            )}
          </div>

          {/* Submit Button with Disabled Reason Tooltip */}
          <div className="pt-2">
            <button
              type="submit"
              disabled={submitting || !isFormValid}
              aria-disabled={submitting || !isFormValid}
              title={!isFormValid ? getDisabledReason() : 'Complete Registration'}
              className="w-full py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition-all duration-150 flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(6,182,212,0.3)] disabled:opacity-40 disabled:hover:bg-cyan-500 disabled:shadow-none disabled:cursor-not-allowed cursor-pointer"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Enrolling Account...</span>
                </>
              ) : (
                <>
                  <span>Complete Registration</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
            {!isFormValid && (
              <p className="mt-2 text-center text-[11px] font-mono text-slate-400">
                {getDisabledReason()}
              </p>
            )}
          </div>
        </form>

        {/* Footer Link */}
        <div className="mt-6 text-center pt-5 border-t border-slate-800/80">
          <p className="text-xs text-slate-400">
            Already registered?{' '}
            <Link
              to="/login"
              className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors font-mono"
            >
              Sign In
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
