import React, { useState, useEffect } from 'react';
import { X, Server, Globe, Database, Network, Loader2, AlertCircle } from 'lucide-react';

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

export default function AssetModal({ isOpen, onClose, onSubmit, initialData = null }) {
  const [formData, setFormData] = useState({
    name: '',
    ip_address: '',
    hostname: '',
    asset_type: 'server',
    environment: 'production',
    criticality: 3,
    owner: 'SecOps Team',
    description: '',
  });

  const [errors, setErrors] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [apiError, setApiError] = useState('');

  const isEdit = !!initialData;

  useEffect(() => {
    if (initialData) {
      setFormData({
        name: initialData.name || '',
        ip_address: initialData.ip_address || '',
        hostname: initialData.hostname || '',
        asset_type: initialData.asset_type || 'server',
        environment: initialData.environment || 'production',
        criticality: initialData.criticality || 3,
        owner: initialData.owner || 'SecOps Team',
        description: initialData.description || '',
      });
    } else {
      setFormData({
        name: '',
        ip_address: '',
        hostname: '',
        asset_type: 'server',
        environment: 'production',
        criticality: 3,
        owner: 'SecOps Team',
        description: '',
      });
    }
    setErrors({});
    setApiError('');
  }, [initialData, isOpen]);

  if (!isOpen) return null;

  const validate = () => {
    const errs = {};
    if (!formData.name.trim()) {
      errs.name = 'Asset name is required.';
    }
    if (!formData.ip_address.trim()) {
      errs.ip_address = 'IP address is required.';
    } else if (!IPV4_REGEX.test(formData.ip_address.trim())) {
      errs.ip_address = 'Must be a valid IPv4 address (e.g. 192.168.1.10).';
    }
    if (!formData.criticality || formData.criticality < 1 || formData.criticality > 5) {
      errs.criticality = 'Criticality must be between 1 and 5.';
    }
    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setApiError('');

    if (!validate()) return;

    setSubmitting(true);
    try {
      await onSubmit({
        ...formData,
        criticality: parseInt(formData.criticality, 10),
      });
      onClose();
    } catch (err) {
      if (err.response?.status === 409) {
        setApiError(err.response.data?.detail || 'An asset with this IP address already exists.');
      } else if (err.response?.status === 403) {
        setApiError('Forbidden: Only analyst or admin accounts can perform this action.');
      } else if (err.response?.data?.detail) {
        setApiError(
          typeof err.response.data.detail === 'string'
            ? err.response.data.detail
            : 'Validation error: Please review input fields.'
        );
      } else {
        setApiError('Failed to save asset. Please try again.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="w-full max-w-xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden font-sans">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div>
            <h3 className="text-base font-semibold text-white font-mono flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              {isEdit ? 'Edit Network Asset' : 'Register New Asset'}
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              {isEdit ? `Updating asset specifications` : `Add an infrastructure target to the inventory`}
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4 max-h-[80vh] overflow-y-auto">
          {apiError && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-2.5">
              <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
              <span>{apiError}</span>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Asset Name */}
            <div>
              <label className="block text-xs font-mono text-slate-300 uppercase tracking-wider mb-1.5">
                Asset Name *
              </label>
              <input
                type="text"
                required
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="e.g. prod-db-primary"
                className={`w-full px-3 py-2 bg-slate-950 border rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors ${
                  errors.name ? 'border-red-500/50' : 'border-slate-800'
                }`}
              />
              {errors.name && <p className="text-[11px] text-red-400 mt-1">{errors.name}</p>}
            </div>

            {/* IP Address */}
            <div>
              <label className="block text-xs font-mono text-slate-300 uppercase tracking-wider mb-1.5">
                IPv4 Address *
              </label>
              <input
                type="text"
                required
                value={formData.ip_address}
                onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
                placeholder="10.0.4.15"
                className={`w-full px-3 py-2 bg-slate-950 border rounded-lg text-sm text-white font-mono placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors ${
                  errors.ip_address ? 'border-red-500/50' : 'border-slate-800'
                }`}
              />
              {errors.ip_address && (
                <p className="text-[11px] text-red-400 mt-1">{errors.ip_address}</p>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Hostname */}
            <div>
              <label className="block text-xs font-mono text-slate-300 uppercase tracking-wider mb-1.5">
                Hostname (optional)
              </label>
              <input
                type="text"
                value={formData.hostname}
                onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
                placeholder="db01.corp.internal"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>

            {/* Owner */}
            <div>
              <label className="block text-xs font-mono text-slate-300 uppercase tracking-wider mb-1.5">
                Asset Owner
              </label>
              <input
                type="text"
                value={formData.owner}
                onChange={(e) => setFormData({ ...formData, owner: e.target.value })}
                placeholder="SecOps Team"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {/* Asset Type */}
            <div>
              <label className="block text-xs font-mono text-slate-300 uppercase tracking-wider mb-1.5">
                Asset Type
              </label>
              <select
                value={formData.asset_type}
                onChange={(e) => setFormData({ ...formData, asset_type: e.target.value })}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
              >
                <option value="server">Server</option>
                <option value="web">Web Application</option>
                <option value="db">Database</option>
                <option value="network">Network Device</option>
              </select>
            </div>

            {/* Environment */}
            <div>
              <label className="block text-xs font-mono text-slate-300 uppercase tracking-wider mb-1.5">
                Environment
              </label>
              <select
                value={formData.environment}
                onChange={(e) => setFormData({ ...formData, environment: e.target.value })}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
              >
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="dev">Development</option>
              </select>
            </div>

            {/* Criticality Rating */}
            <div>
              <label className="block text-xs font-mono text-slate-300 uppercase tracking-wider mb-1.5">
                Criticality (1-5)
              </label>
              <select
                value={formData.criticality}
                onChange={(e) => setFormData({ ...formData, criticality: parseInt(e.target.value, 10) })}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
              >
                <option value={5}>5 - Critical</option>
                <option value={4}>4 - High</option>
                <option value={3}>3 - Medium</option>
                <option value={2}>2 - Low</option>
                <option value={1}>1 - Minimal</option>
              </select>
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="block text-xs font-mono text-slate-300 uppercase tracking-wider mb-1.5">
              Description (optional)
            </label>
            <textarea
              rows={3}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Primary PostgreSQL cluster host storing transactional data."
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>

          {/* Footer buttons */}
          <div className="pt-4 border-t border-slate-800 flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg border border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800 text-xs font-mono transition-colors cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono transition-all flex items-center gap-2 shadow-[0_0_12px_rgba(6,182,212,0.25)] disabled:opacity-50 cursor-pointer"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Saving...</span>
                </>
              ) : (
                <span>{isEdit ? 'Save Changes' : 'Register Asset'}</span>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
