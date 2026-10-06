import React, { useState, useEffect, useCallback } from 'react';
import { 
  Server, 
  Globe, 
  Database, 
  Network, 
  Plus, 
  Search, 
  Edit2, 
  Trash2, 
  ChevronLeft, 
  ChevronRight, 
  RefreshCw,
  ShieldAlert,
  SlidersHorizontal,
  X
} from 'lucide-react';
import api from '../api/client';
import { CriticalityBadge, EnvironmentBadge } from '../components/Badge';
import AssetModal from '../components/AssetModal';
import DeleteConfirmModal from '../components/DeleteConfirmModal';
import Toast from '../components/Toast';

export default function Assets() {
  const [assets, setAssets] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(10);
  const [loading, setLoading] = useState(true);

  // Filters & Search
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [assetType, setAssetType] = useState('');
  const [environment, setEnvironment] = useState('');
  const [criticality, setCriticality] = useState('');

  // Modals state
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState(null);
  const [deletingAsset, setDeletingAsset] = useState(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  // Toast
  const [toast, setToast] = useState(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => {
      setToast(null);
    }, 4000);
  };

  // Debounce search input by 300ms
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [search]);

  // Fetch assets list from API
  const fetchAssets = useCallback(async () => {
    setLoading(true);
    try {
      const params = {
        page,
        page_size: pageSize,
      };
      if (debouncedSearch) params.search = debouncedSearch;
      if (assetType) params.asset_type = assetType;
      if (environment) params.environment = environment;
      if (criticality) params.criticality = criticality;

      const response = await api.get('/api/assets', { params });
      setAssets(response.data.data || []);
      setTotal(response.data.total || 0);
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to load assets', 'error');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, debouncedSearch, assetType, environment, criticality]);

  useEffect(() => {
    fetchAssets();
  }, [fetchAssets]);

  // Handle Add Asset
  const handleAddAsset = async (formData) => {
    const res = await api.post('/api/assets', formData);
    showToast(`Asset '${res.data.name}' registered successfully!`);
    fetchAssets();
  };

  // Handle Edit Asset
  const handleEditAsset = async (formData) => {
    if (!editingAsset) return;
    const res = await api.put(`/api/assets/${editingAsset.id}`, formData);
    showToast(`Asset '${res.data.name}' updated successfully!`);
    setEditingAsset(null);
    fetchAssets();
  };

  // Handle Delete Asset
  const handleDeleteConfirm = async () => {
    if (!deletingAsset) return;
    setDeleteLoading(true);
    try {
      await api.delete(`/api/assets/${deletingAsset.id}`);
      showToast(`Asset '${deletingAsset.name}' decommissioned.`, 'success');
      setDeletingAsset(null);
      // If last item on page, go to prev page
      if (assets.length === 1 && page > 1) {
        setPage((p) => p - 1);
      } else {
        fetchAssets();
      }
    } catch (err) {
      showToast(
        err.response?.data?.detail || 'Failed to delete asset. Ensure you have administrator rights.',
        'error'
      );
    } finally {
      setDeleteLoading(false);
    }
  };

  // Render Type Icon
  const renderTypeIcon = (type) => {
    switch (type) {
      case 'server':
        return <Server className="w-4 h-4 text-cyan-400" />;
      case 'web':
        return <Globe className="w-4 h-4 text-emerald-400" />;
      case 'db':
        return <Database className="w-4 h-4 text-purple-400" />;
      case 'network':
        return <Network className="w-4 h-4 text-amber-400" />;
      default:
        return <Server className="w-4 h-4 text-slate-400" />;
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="space-y-6">
      <Toast toast={toast} onClose={() => setToast(null)} />

      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-bold tracking-tight text-white font-mono">
              Network Assets Inventory
            </h2>
            <span className="px-2 py-0.5 rounded-full text-xs font-mono font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              {total} {total === 1 ? 'Target' : 'Targets'}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Registered infrastructure nodes, endpoints, and services monitored by AEGIS
          </p>
        </div>

        <button
          onClick={() => setIsAddModalOpen(true)}
          className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono transition-all duration-150 shadow-[0_0_15px_rgba(6,182,212,0.25)] cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span>Add Asset</span>
        </button>
      </div>

      {/* Filters and Search Bar */}
      <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 backdrop-blur-md flex flex-col lg:flex-row items-stretch lg:items-center gap-3">
        {/* Search Input */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by asset name, IP, domain, or hostname..."
            className="w-full pl-10 pr-9 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors font-sans"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Dropdown Filters */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Asset Type */}
          <select
            value={assetType}
            onChange={(e) => {
              setAssetType(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
          >
            <option value="">All Types</option>
            <option value="server">Server</option>
            <option value="web">Web App</option>
            <option value="db">Database</option>
            <option value="network">Network Device</option>
          </select>

          {/* Environment */}
          <select
            value={environment}
            onChange={(e) => {
              setEnvironment(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
          >
            <option value="">All Environments</option>
            <option value="production">Production</option>
            <option value="staging">Staging</option>
            <option value="dev">Development</option>
          </select>

          {/* Criticality */}
          <select
            value={criticality}
            onChange={(e) => {
              setCriticality(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
          >
            <option value="">All Criticalities</option>
            <option value="5">5 - Critical</option>
            <option value="4">4 - High</option>
            <option value="3">3 - Medium</option>
            <option value="2">2 - Low</option>
            <option value="1">1 - Minimal</option>
          </select>

          <button
            onClick={fetchAssets}
            title="Refresh Table"
            className="p-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Main Table Container */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden shadow-xl backdrop-blur-md">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/90 text-slate-400 font-mono uppercase text-[11px] tracking-wider">
                <th className="py-3.5 px-4 font-semibold">Asset Details</th>
                <th className="py-3.5 px-4 font-semibold">Target / IP</th>
                <th className="py-3.5 px-4 font-semibold">Type</th>
                <th className="py-3.5 px-4 font-semibold">Environment</th>
                <th className="py-3.5 px-4 font-semibold">Criticality</th>
                <th className="py-3.5 px-4 font-semibold">Owner</th>
                <th className="py-3.5 px-4 font-semibold text-center">Vulns</th>
                <th className="py-3.5 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {loading ? (
                // Loading Skeleton
                Array.from({ length: 5 }).map((_, idx) => (
                  <tr key={idx} className="animate-pulse">
                    <td className="py-4 px-4">
                      <div className="h-4 bg-slate-800 rounded w-32 mb-1.5" />
                      <div className="h-3 bg-slate-800/60 rounded w-20" />
                    </td>
                    <td className="py-4 px-4"><div className="h-4 bg-slate-800 rounded w-24" /></td>
                    <td className="py-4 px-4"><div className="h-4 bg-slate-800 rounded w-16" /></td>
                    <td className="py-4 px-4"><div className="h-4 bg-slate-800 rounded w-20" /></td>
                    <td className="py-4 px-4"><div className="h-4 bg-slate-800 rounded w-20" /></td>
                    <td className="py-4 px-4"><div className="h-4 bg-slate-800 rounded w-24" /></td>
                    <td className="py-4 px-4 text-center"><div className="h-4 bg-slate-800 rounded w-8 mx-auto" /></td>
                    <td className="py-4 px-4 text-right"><div className="h-4 bg-slate-800 rounded w-16 ml-auto" /></td>
                  </tr>
                ))
              ) : assets.length === 0 ? (
                // Empty State
                <tr>
                  <td colSpan={8} className="py-16 text-center">
                    <div className="flex flex-col items-center justify-center max-w-sm mx-auto">
                      <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 mb-4 shadow-[0_0_20px_rgba(6,182,212,0.15)]">
                        <Server className="w-7 h-7" />
                      </div>
                      <h4 className="text-sm font-semibold text-white font-mono">
                        No network assets found
                      </h4>
                      <p className="text-xs text-slate-400 mt-1 mb-5">
                        {debouncedSearch || assetType || environment || criticality
                          ? 'No inventory assets match the selected filter criteria.'
                          : 'Get started by adding your first network asset target to enable vulnerability scanning.'}
                      </p>
                      <button
                        onClick={() => {
                          if (debouncedSearch || assetType || environment || criticality) {
                            setSearch('');
                            setAssetType('');
                            setEnvironment('');
                            setCriticality('');
                          } else {
                            setIsAddModalOpen(true);
                          }
                        }}
                        className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono transition-all flex items-center gap-1.5 shadow-[0_0_12px_rgba(6,182,212,0.2)] cursor-pointer"
                      >
                        {debouncedSearch || assetType || environment || criticality ? (
                          <span>Reset Filters</span>
                        ) : (
                          <>
                            <Plus className="w-3.5 h-3.5" />
                            <span>Add your first asset</span>
                          </>
                        )}
                      </button>
                    </div>
                  </td>
                </tr>
              ) : (
                // Asset Rows
                assets.map((asset) => (
                  <tr
                    key={asset.id}
                    className="hover:bg-slate-900/50 transition-colors group"
                  >
                    {/* Name & Hostname */}
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors">
                        {asset.name}
                      </div>
                      <div className="text-[11px] font-mono text-slate-500">
                        {asset.hostname || 'No hostname configured'}
                      </div>
                    </td>

                    {/* Target / IP Address */}
                    <td className="py-3.5 px-4">
                      {asset.target_type === 'domain' ? (
                        <div className="inline-flex flex-col">
                          <span className="font-mono text-xs px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-800/40 text-cyan-300 flex items-center gap-1.5 w-fit">
                            <span>🌐</span>
                            <span>{asset.ip_address}</span>
                          </span>
                          {asset.resolved_ip && (
                            <span className="text-[10px] font-mono text-slate-400 mt-0.5 pl-1">
                              ↳ {asset.resolved_ip}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-400 flex items-center gap-1.5 w-fit">
                          <span>🖥️</span>
                          <span>{asset.ip_address}</span>
                        </span>
                      )}
                    </td>

                    {/* Type */}
                    <td className="py-3.5 px-4">
                      <div className="inline-flex items-center gap-1.5 font-medium text-slate-300 capitalize">
                        {renderTypeIcon(asset.asset_type)}
                        <span>{asset.asset_type}</span>
                      </div>
                    </td>

                    {/* Environment */}
                    <td className="py-3.5 px-4">
                      <EnvironmentBadge env={asset.environment} />
                    </td>

                    {/* Criticality */}
                    <td className="py-3.5 px-4">
                      <CriticalityBadge level={asset.criticality} />
                    </td>

                    {/* Owner */}
                    <td className="py-3.5 px-4 text-slate-400">
                      {asset.owner || 'SecOps Team'}
                    </td>

                    {/* Vulnerabilities Count Placeholder */}
                    <td className="py-3.5 px-4 text-center">
                      <span className="inline-flex items-center justify-center px-2 py-0.5 rounded-full text-[11px] font-mono bg-slate-900 border border-slate-800 text-slate-400">
                        0
                      </span>
                    </td>

                    {/* Actions */}
                    <td className="py-3.5 px-4 text-right">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          onClick={() => setEditingAsset(asset)}
                          title="Edit Asset"
                          className="p-1.5 rounded-md hover:bg-slate-800 text-slate-400 hover:text-cyan-400 transition-colors cursor-pointer"
                        >
                          <Edit2 className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => setDeletingAsset(asset)}
                          title="Decommission Asset"
                          className="p-1.5 rounded-md hover:bg-rose-500/10 text-slate-400 hover:text-rose-400 transition-colors cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="p-4 border-t border-slate-800/80 bg-slate-950 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400 font-mono">
          <div>
            Showing{' '}
            <span className="text-white font-medium">
              {total === 0 ? 0 : (page - 1) * pageSize + 1}
            </span>{' '}
            to{' '}
            <span className="text-white font-medium">
              {Math.min(page * pageSize, total)}
            </span>{' '}
            of <span className="text-white font-medium">{total}</span> assets
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1 || loading}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors cursor-pointer flex items-center gap-1 px-2.5"
            >
              <ChevronLeft className="w-4 h-4" />
              <span>Previous</span>
            </button>

            <span className="px-3 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
              Page {page} of {totalPages}
            </span>

            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages || loading}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors cursor-pointer flex items-center gap-1 px-2.5"
            >
              <span>Next</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Add Asset Modal */}
      <AssetModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSubmit={handleAddAsset}
      />

      {/* Edit Asset Modal */}
      <AssetModal
        isOpen={!!editingAsset}
        initialData={editingAsset}
        onClose={() => setEditingAsset(null)}
        onSubmit={handleEditAsset}
      />

      {/* Delete Confirmation Modal */}
      <DeleteConfirmModal
        isOpen={!!deletingAsset}
        asset={deletingAsset}
        loading={deleteLoading}
        onClose={() => setDeletingAsset(null)}
        onConfirm={handleDeleteConfirm}
      />
    </div>
  );
}
