import React from 'react';
import { CheckCircle2, AlertCircle, X } from 'lucide-react';

export default function Toast({ toast, onClose }) {
  if (!toast) return null;

  const isSuccess = toast.type === 'success';

  return (
    <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-xl bg-slate-950/90 border backdrop-blur-md shadow-2xl transition-all animate-in slide-in-from-bottom-5 duration-200 font-sans max-w-md">
      {isSuccess ? (
        <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
      ) : (
        <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
      )}
      <div className="text-xs">
        <p className="font-semibold text-slate-200">
          {isSuccess ? 'Success' : 'Error'}
        </p>
        <p className="text-slate-400 mt-0.5">{toast.message}</p>
      </div>
      <button
        onClick={onClose}
        className="ml-auto text-slate-500 hover:text-slate-300 p-1 rounded transition-colors cursor-pointer"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}
