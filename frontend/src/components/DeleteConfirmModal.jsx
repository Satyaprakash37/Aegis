import React from 'react';
import { AlertTriangle, X, Loader2 } from 'lucide-react';

export default function DeleteConfirmModal({ isOpen, onClose, onConfirm, asset, loading }) {
  if (!isOpen || !asset) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden font-sans">
        <div className="p-6">
          <div className="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 mb-4 shadow-[0_0_15px_rgba(244,63,94,0.15)]">
            <AlertTriangle className="w-6 h-6" />
          </div>

          <h3 className="text-lg font-semibold text-white font-mono">
            Decommission Asset?
          </h3>
          <p className="text-xs text-slate-400 mt-2 leading-relaxed">
            Are you sure you want to delete <span className="text-white font-medium">{asset.name}</span> (<span className="text-cyan-400 font-mono">{asset.ip_address}</span>)? All associated scans and vulnerability mappings will be permanently removed.
          </p>

          <div className="mt-6 flex items-center justify-end gap-3">
            <button
              onClick={onClose}
              disabled={loading}
              className="px-4 py-2 rounded-lg border border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800 text-xs font-mono transition-colors cursor-pointer"
            >
              Cancel
            </button>
            <button
              onClick={onConfirm}
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-rose-500 hover:bg-rose-600 text-white font-semibold text-xs font-mono transition-all flex items-center gap-2 shadow-[0_0_12px_rgba(244,63,94,0.3)] disabled:opacity-50 cursor-pointer"
            >
              {loading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Deleting...</span>
                </>
              ) : (
                <span>Confirm Decommission</span>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
