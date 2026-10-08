import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  ArrowLeft,
  FileText, 
  FileSpreadsheet, 
  Layers, 
  Download, 
  RefreshCw, 
  Loader2, 
  AlertCircle, 
  CheckCircle2, 
  ShieldAlert, 
  Calendar, 
  User as UserIcon, 
  HardDrive,
  Sparkles
} from 'lucide-react';
import api from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ReportTypeBadge, ReportFormatBadge } from '../components/Badge';

export default function Reports() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [downloadingId, setDownloadingId] = useState(null);
  const [toast, setToast] = useState(null);

  // Form State
  const [selectedType, setSelectedType] = useState('executive');
  const [selectedFormat, setSelectedFormat] = useState('pdf');

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const fetchReports = async () => {
    try {
      setLoading(true);
      const res = await api.get('/api/reports');
      setReports(res.data?.data || []);
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to load reports history', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  // Sync format with type selection
  const handleTypeSelect = (type) => {
    setSelectedType(type);
    if (type === 'compliance') {
      setSelectedFormat('excel');
    } else {
      setSelectedFormat('pdf');
    }
  };

  const handleGenerate = async () => {
    try {
      setGenerating(true);
      const res = await api.post('/api/reports/generate', {
        report_type: selectedType,
        format: selectedFormat,
      });

      showToast(`Report '${res.data.filename}' generated successfully!`, 'success');
      // Refresh history
      await fetchReports();
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to generate report', 'error');
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (report) => {
    try {
      setDownloadingId(report.id);
      const res = await api.get(`/api/reports/${report.id}/download`, {
        responseType: 'blob',
      });

      const mediaType = report.format === 'pdf' 
        ? 'application/pdf' 
        : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

      const blob = new Blob([res.data], { type: mediaType });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;

      // Extract filename from response headers or fallback
      const dateStr = new Date().toISOString().slice(0, 10);
      const ext = report.format === 'pdf' ? 'pdf' : 'xlsx';
      link.download = report.filename || `aegis_${report.report_type}_${dateStr}.${ext}`;

      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      showToast(`Downloaded ${link.download}`, 'success');
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to download report file', 'error');
    } finally {
      setDownloadingId(null);
    }
  };

  const formatFileSize = (bytes) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  const reportTemplates = [
    {
      id: 'executive',
      title: 'Executive Risk Briefing',
      format: 'pdf',
      formatLabel: 'PDF Document',
      icon: FileText,
      accent: 'from-purple-500/20 to-purple-950/40 border-purple-500/40 text-purple-400',
      badgeColor: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
      description: 'Strategic plain-language summary for leadership. Includes risk posture statement, key metrics table, top 10 riskiest vulnerabilities, and strategic remediation recommendations.',
      highlights: ['C-Suite Risk Posture', 'Top 10 Exposure Vectors', 'Strategic Recommendations'],
    },
    {
      id: 'detailed',
      title: 'Detailed Technical Audit',
      format: 'pdf',
      formatLabel: 'PDF Document',
      icon: Layers,
      accent: 'from-cyan-500/20 to-cyan-950/40 border-cyan-500/40 text-cyan-400',
      badgeColor: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
      description: 'Comprehensive engineering audit. Includes complete asset inventory, scan history, and all vulnerability dossiers grouped by host with CVSS 60% + Asset Criticality 40% breakdown.',
      highlights: ['Full Asset Inventory', 'All CVE Dossiers Grouped by Host', 'Remediation Playbooks'],
    },
    {
      id: 'compliance',
      title: 'Compliance Audit Matrix',
      format: 'excel',
      formatLabel: 'Excel Spreadsheet',
      icon: FileSpreadsheet,
      accent: 'from-emerald-500/20 to-emerald-950/40 border-emerald-500/40 text-emerald-400',
      badgeColor: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      description: 'Multi-sheet workbook designed for security auditors. Features frozen header rows, auto-filters, severity color-coded cells, SLA timelines, and full exportable dataset.',
      highlights: ['3 Formatted Worksheets', 'Auto-Filters & Frozen Panes', 'Severity SLA Timelines'],
    },
  ];

  const canGenerate = user?.role === 'admin' || user?.role === 'analyst';

  return (
    <div className="space-y-8">
      {/* Toast Notification */}
      {toast && (
        <div className={`fixed top-4 right-4 z-50 flex items-center gap-2.5 px-4 py-3 rounded-lg border text-xs font-mono shadow-xl transition-all animate-in fade-in slide-in-from-top-2 ${
          toast.type === 'error'
            ? 'bg-rose-950/90 border-rose-500/50 text-rose-300'
            : 'bg-slate-900/95 border-emerald-500/50 text-emerald-300'
        }`}>
          {toast.type === 'error' ? (
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          ) : (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          )}
          <span>{toast.message}</span>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <button
            onClick={() => navigate(-1)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700/60 bg-slate-800/80 hover:bg-slate-750 hover:border-cyan-500/40 text-slate-300 hover:text-white text-xs font-mono transition-all shadow-sm cursor-pointer shrink-0"
            title="Go back"
          >
            <ArrowLeft className="w-4 h-4 text-cyan-400" />
            <span>Back</span>
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white tracking-wide font-sans">
                Security Reports & Compliance Export
              </h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                PDF & Excel Engine
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 font-sans">
              Generate executive briefings, technical vulnerability audits, and regulatory compliance spreadsheets
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchReports}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 font-mono transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh Archive</span>
          </button>
        </div>
      </div>

      {/* Section 1: Report Generation Builder Card */}
      <div className="p-6 rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md shadow-xl relative overflow-hidden">
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
              Generate New Report
            </h2>
          </div>
          {!canGenerate && (
            <span className="text-xs font-mono text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2.5 py-1 rounded">
              Viewer role: Read-only access
            </span>
          )}
        </div>

        {/* 3 Report Type Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          {reportTemplates.map((template) => {
            const Icon = template.icon;
            const isSelected = selectedType === template.id;

            return (
              <div
                key={template.id}
                onClick={() => handleTypeSelect(template.id)}
                className={`p-5 rounded-xl border transition-all cursor-pointer relative flex flex-col justify-between ${
                  isSelected
                    ? `bg-gradient-to-b ${template.accent} shadow-[0_0_20px_rgba(6,182,212,0.15)]`
                    : 'bg-slate-900/50 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900/80'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className={`p-2 rounded-lg ${template.badgeColor}`}>
                      <Icon className="w-5 h-5" />
                    </div>
                    <span className={`text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded border ${template.badgeColor}`}>
                      {template.formatLabel}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-white mb-2 font-sans">
                    {template.title}
                  </h3>
                  <p className="text-xs text-slate-400 leading-relaxed font-sans mb-4">
                    {template.description}
                  </p>
                </div>

                <div className="pt-3 border-t border-slate-800/60 space-y-1">
                  {template.highlights.map((h, i) => (
                    <div key={i} className="flex items-center gap-1.5 text-[11px] text-slate-300 font-mono">
                      <span className="w-1 h-1 rounded-full bg-cyan-400" />
                      <span>{h}</span>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        {/* Format Selector & Action Controls */}
        <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex flex-col sm:flex-row sm:items-center gap-4 text-xs font-mono">
            <span className="text-slate-400">Export Format:</span>
            <div className="flex items-center gap-4">
              <label className={`flex items-center gap-2 cursor-pointer ${
                selectedType === 'compliance' ? 'opacity-40 cursor-not-allowed text-slate-600' : 'text-slate-200'
              }`}>
                <input
                  type="radio"
                  name="format"
                  value="pdf"
                  checked={selectedFormat === 'pdf'}
                  onChange={() => setSelectedFormat('pdf')}
                  disabled={selectedType === 'compliance'}
                  className="text-cyan-500 focus:ring-0 focus:ring-offset-0 bg-slate-800 border-slate-700"
                />
                <span>PDF Document (.pdf)</span>
              </label>

              <label className={`flex items-center gap-2 cursor-pointer ${
                selectedType !== 'compliance' ? 'opacity-40 cursor-not-allowed text-slate-600' : 'text-slate-200'
              }`}>
                <input
                  type="radio"
                  name="format"
                  value="excel"
                  checked={selectedFormat === 'excel'}
                  onChange={() => setSelectedFormat('excel')}
                  disabled={selectedType !== 'compliance'}
                  className="text-cyan-500 focus:ring-0 focus:ring-offset-0 bg-slate-800 border-slate-700"
                />
                <span>Excel Spreadsheet (.xlsx)</span>
              </label>
            </div>
          </div>

          <button
            onClick={handleGenerate}
            disabled={generating || !canGenerate}
            className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono font-semibold text-xs transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {generating ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Generating Report...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4" />
                <span>Generate Report</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Section 2: Historical Reports Repository Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/70 backdrop-blur-md overflow-hidden">
        <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <HardDrive className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
              Generated Reports Archive
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {reports.length} Archived Document{reports.length === 1 ? '' : 's'}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead>
              <tr className="border-b border-slate-800/80 bg-slate-950 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                <th className="py-3 px-4">Document / Type</th>
                <th className="py-3 px-4">Format</th>
                <th className="py-3 px-4">Generated By</th>
                <th className="py-3 px-4">File Size</th>
                <th className="py-3 px-4">Created Date</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40">
              {loading ? (
                Array.from({ length: 3 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="py-4 px-4"><div className="h-4 w-32 bg-slate-800 rounded" /></td>
                    <td className="py-4 px-4"><div className="h-4 w-16 bg-slate-800 rounded" /></td>
                    <td className="py-4 px-4"><div className="h-4 w-28 bg-slate-800 rounded" /></td>
                    <td className="py-4 px-4"><div className="h-4 w-16 bg-slate-800 rounded" /></td>
                    <td className="py-4 px-4"><div className="h-4 w-28 bg-slate-800 rounded" /></td>
                    <td className="py-4 px-4 text-right"><div className="h-7 w-20 bg-slate-800 rounded ml-auto" /></td>
                  </tr>
                ))
              ) : reports.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    <FileText className="w-10 h-10 mx-auto mb-2 text-slate-600 opacity-50" />
                    <p className="font-medium text-slate-400">No reports generated yet</p>
                    <p className="text-xs text-slate-600 mt-0.5">
                      Select a report template above and click "Generate Report" to build an export.
                    </p>
                  </td>
                </tr>
              ) : (
                reports.map((report) => (
                  <tr
                    key={report.id}
                    className="hover:bg-slate-900/40 transition-colors group"
                  >
                    {/* Type and filename */}
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2.5">
                        <ReportTypeBadge type={report.report_type} />
                        <span className="font-mono text-slate-300 group-hover:text-cyan-300 transition-colors">
                          {report.filename || `Report #${report.id}`}
                        </span>
                      </div>
                    </td>

                    {/* Format */}
                    <td className="py-3.5 px-4">
                      <ReportFormatBadge format={report.format} />
                    </td>

                    {/* Generated By */}
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-1.5 text-slate-300 font-sans">
                        <UserIcon className="w-3.5 h-3.5 text-slate-500" />
                        <span>{report.generated_by_name || 'System Operator'}</span>
                      </div>
                    </td>

                    {/* File Size */}
                    <td className="py-3.5 px-4 font-mono text-slate-400">
                      {formatFileSize(report.file_size_bytes)}
                    </td>

                    {/* Created Date */}
                    <td className="py-3.5 px-4 font-mono text-slate-400">
                      <div className="flex items-center gap-1.5">
                        <Calendar className="w-3.5 h-3.5 text-slate-500" />
                        <span>{new Date(report.created_at).toLocaleString()}</span>
                      </div>
                    </td>

                    {/* Action */}
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => handleDownload(report)}
                        disabled={downloadingId === report.id}
                        title="Download file to local system"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-cyan-500/10 hover:border-cyan-500/30 text-slate-300 hover:text-cyan-400 border border-slate-800 text-xs font-mono transition-all cursor-pointer disabled:opacity-50"
                      >
                        {downloadingId === report.id ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                        ) : (
                          <Download className="w-3.5 h-3.5 text-cyan-400" />
                        )}
                        <span>Download</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
