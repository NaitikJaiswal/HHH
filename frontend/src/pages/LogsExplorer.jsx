import React, { useState } from 'react';
import { 
  Search, Filter, ShieldCheck, AlertTriangle, Eye, Download, 
  Terminal, Hash, CheckCircle2, Copy, Check 
} from 'lucide-react';
import { MOCK_LOGS } from '../services/mockData';

export default function LogsExplorer({ onSelectLog }) {
  const [logs, setLogs] = useState(MOCK_LOGS);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedLevel, setSelectedLevel] = useState('ALL');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [copiedId, setCopiedId] = useState(null);

  const filteredLogs = logs.filter((log) => {
    const matchesSearch = 
      log.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.source.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.user.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.hash.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesLevel = selectedLevel === 'ALL' || log.level === selectedLevel;
    const matchesCategory = selectedCategory === 'ALL' || log.category === selectedCategory;

    return matchesSearch && matchesLevel && matchesCategory;
  });

  const handleCopyHash = (hash, id, e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(hash);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const exportLogsJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredLogs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `securelog_export_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center space-x-2">
            <Terminal className="h-5 w-5 text-cyan-400" />
            <span>Log Explorer & Hunt Console</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Search, filter, and inspect tamper-evident audit records across all ingest adapters.
          </p>
        </div>

        <button
          onClick={exportLogsJson}
          className="px-3.5 py-2 rounded-xl bg-cyber-card hover:bg-cyber-surface border border-cyber-border text-slate-200 text-xs font-mono flex items-center space-x-2 transition"
        >
          <Download className="h-4 w-4 text-cyan-400" />
          <span>Export JSON</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-2xl bg-cyber-card border border-cyber-border space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          {/* Search Input */}
          <div className="md:col-span-2 relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Hunt by keyword, host, user, IP, or SHA-256 hash..."
              className="w-full pl-9 pr-3 py-2 rounded-xl bg-cyber-bg border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
            />
          </div>

          {/* Level Filter */}
          <div>
            <select
              value={selectedLevel}
              onChange={(e) => setSelectedLevel(e.target.value)}
              className="w-full px-3 py-2 rounded-xl bg-cyber-bg border border-cyber-border text-xs text-slate-300 focus:outline-none focus:border-cyan-400 font-mono"
            >
              <option value="ALL">All Severities</option>
              <option value="INFO">INFO</option>
              <option value="WARN">WARN</option>
              <option value="ERROR">ERROR</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>
          </div>

          {/* Category Filter */}
          <div>
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full px-3 py-2 rounded-xl bg-cyber-bg border border-cyber-border text-xs text-slate-300 focus:outline-none focus:border-cyan-400 font-mono"
            >
              <option value="ALL">All Categories</option>
              <option value="AUTHENTICATION">Authentication</option>
              <option value="FILE_INTEGRITY">File Integrity</option>
              <option value="RATE_LIMIT">Rate Limit</option>
              <option value="MALWARE_DEFENSE">Malware Defense</option>
              <option value="INTEGRITY_GAP">Integrity Gaps</option>
            </select>
          </div>
        </div>

        <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 px-1 pt-1 border-t border-cyber-border/50">
          <span>Displaying {filteredLogs.length} matching events</span>
          <span className="text-cyan-400">All events cryptographically linked with SHA-256</span>
        </div>
      </div>

      {/* Logs Table */}
      <div className="bg-cyber-card rounded-2xl border border-cyber-border overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-cyber-bg/80 border-b border-cyber-border text-[11px] text-slate-400 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Seq</th>
                <th className="py-3 px-4">Level</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Source / Host</th>
                <th className="py-3 px-4">Action & Message</th>
                <th className="py-3 px-4">SHA-256 Event Hash</th>
                <th className="py-3 px-4 text-right">Proof</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border text-slate-300">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    No log events match your query.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr
                    key={log.id + log.sequence}
                    onClick={() => onSelectLog(log)}
                    className="hover:bg-cyber-surface/70 transition cursor-pointer"
                  >
                    <td className="py-3 px-4 font-bold text-slate-200">
                      #{log.sequence}
                    </td>

                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          log.level === 'CRITICAL'
                            ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                            : log.level === 'WARN'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : log.level === 'ERROR'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        }`}
                      >
                        {log.level}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap text-[11px]">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>

                    <td className="py-3 px-4 text-slate-300 whitespace-nowrap">
                      <div>{log.source}</div>
                      <div className="text-[10px] text-slate-500">{log.adapter}</div>
                    </td>

                    <td className="py-3 px-4 max-w-xs truncate">
                      <div className="font-semibold text-slate-200">{log.action}</div>
                      <div className="text-[11px] text-slate-400 truncate">{log.message}</div>
                    </td>

                    <td className="py-3 px-4 text-slate-400 font-mono text-[10px]">
                      <div className="flex items-center space-x-1.5">
                        <span className="truncate max-w-[120px]">{log.hash.slice(0, 16)}...</span>
                        <button
                          onClick={(e) => handleCopyHash(log.hash, log.id, e)}
                          title="Copy Full SHA-256 Hash"
                          className="text-slate-500 hover:text-cyan-400 transition"
                        >
                          {copiedId === log.id ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                        </button>
                      </div>
                    </td>

                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      {log.verified ? (
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-medium">
                          <CheckCircle2 className="h-3 w-3" />
                          <span>Signed</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] bg-amber-500/15 text-amber-400 border border-amber-500/30 font-medium">
                          <AlertTriangle className="h-3 w-3" />
                          <span>Gap</span>
                        </span>
                      )}
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
