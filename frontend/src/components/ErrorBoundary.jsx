import React from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('AEGIS UI Runtime Exception caught by ErrorBoundary:', error, errorInfo);
    this.setState({ errorInfo });
  }

  handleReload = () => {
    window.location.reload();
  };

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.href = '/';
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen w-full flex items-center justify-center bg-slate-950 p-6 text-slate-100 font-sans">
          <div className="max-w-lg w-full bg-slate-900/90 border border-rose-500/30 rounded-xl p-8 shadow-2xl backdrop-blur-xl relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-rose-500 via-amber-500 to-rose-500" />
            
            <div className="flex items-center gap-3 mb-6">
              <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400">
                <AlertTriangle className="w-8 h-8" />
              </div>
              <div>
                <h1 className="text-xl font-bold tracking-tight text-white">System Fault Intercepted</h1>
                <p className="text-xs text-rose-400 font-mono tracking-wide">AEGIS_UI_RUNTIME_CRASH</p>
              </div>
            </div>

            <p className="text-sm text-slate-400 mb-6 leading-relaxed">
              An unhandled rendering fault occurred within the current security console view. The incident details have been logged to the browser terminal.
            </p>

            {this.state.error && (
              <div className="mb-6 p-3 bg-slate-950/70 rounded-lg border border-slate-800 font-mono text-xs text-slate-400 overflow-x-auto max-h-36">
                <span className="text-rose-400 font-semibold">{this.state.error.toString()}</span>
              </div>
            )}

            <div className="flex items-center gap-3 pt-2">
              <button
                onClick={this.handleReload}
                className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-colors shadow-lg shadow-cyan-950/50"
              >
                <RefreshCw className="w-4 h-4" />
                Reload Console
              </button>
              <button
                onClick={this.handleReset}
                className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-medium text-sm transition-colors"
              >
                <Home className="w-4 h-4" />
                Return to Base
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
