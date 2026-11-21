import React from 'react';
import { 
  ShieldCheck, AlertTriangle, Activity, Database, ArrowUpRight, 
  Terminal, CheckCircle2, ShieldAlert, Cpu, Lock, FileCheck 
} from 'lucide-react';
import { INITIAL_METRICS, MOCK_LOGS, MOCK_COLLECTORS } from '../services/mockData';

export default function Dashboard({ setActiveTab, onSelectLog }) {
  const recentAlerts = MOCK_LOGS.filter(l => l.level === 'CRITICAL' || l.level === 'WARN' || !l.verified);

  return (
    <div className="space-y-6">
      {/* Top Banner / Hero */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-cyber-card via-cyber-surface to-cyber-card border border-cyber-border p-6 shadow-xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center space-x-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono mb-2">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
              </span>
              <span>IMMUTABLE EVIDENCE PIPELINE ACTIVE</span>
            </div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight">Security Operations Console</h1>
            <p className="text-xs text-slate-400 mt-1 max-w-xl">
              Cryptographically verified event stream, signed Merkle checkpoints, and gap detection across all edge log collectors.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={() => setActiveTab('integrity')}
              className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono shadow-lg shadow-cyan-500/20 transition flex items-center space-x-2"
            >
              <FileCheck className="h-4 w-4" />
              <span>Verify Evidence</span>
            </button>
            <button
              onClick={() => setActiveTab('logs')}
              className="px-4 py-2 rounded-xl bg-cyber-surface hover:bg-cyber-card border border-cyber-border text-slate-200 font-medium text-xs font-mono transition flex items-center space-x-2"
            >
              <Terminal className="h-4 w-4 text-cyan-400" />
              <span>Hunt Logs</span>
            </button>
          </div>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="p-5 rounded-2xl bg-cyber-card border border-cyber-border relative overflow-hidden group hover:border-cyan-500/40 transition">
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <span className="text-xs font-mono uppercase tracking-wider">Total Events (24h)</span>
            <Database className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white tracking-tight">
            {INITIAL_METRICS.totalLogs.toLocaleString()}
          </div>
          <div className="flex items-center space-x-1.5 mt-2 text-xs text-emerald-400 font-mono">
            <ArrowUpRight className="h-3.5 w-3.5" />
            <span>+{INITIAL_METRICS.ingestionRatePerSec} ev/sec ingestion</span>
          </div>
        </div>

        {/* Metric 2 */}
        <div className="p-5 rounded-2xl bg-cyber-card border border-cyber-border relative overflow-hidden group hover:border-emerald-500/40 transition">
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <span className="text-xs font-mono uppercase tracking-wider">Cryptographic Proof</span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 tracking-tight">
            {INITIAL_METRICS.verifiedIntegrity.toLocaleString()}
          </div>
          <div className="flex items-center space-x-1.5 mt-2 text-xs text-slate-400 font-mono">
            <span>99.99% SHA-256 Chain Match</span>
          </div>
        </div>

        {/* Metric 3 */}
        <div className="p-5 rounded-2xl bg-cyber-card border border-cyber-border relative overflow-hidden group hover:border-amber-500/40 transition">
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <span className="text-xs font-mono uppercase tracking-wider">Sequence Gaps</span>
            <AlertTriangle className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 tracking-tight">
            {INITIAL_METRICS.missingSequences} Missing
          </div>
          <div className="flex items-center space-x-1.5 mt-2 text-xs text-amber-400/80 font-mono">
            <span>Seq #148920 flagged by engine</span>
          </div>
        </div>

        {/* Metric 4 */}
        <div className="p-5 rounded-2xl bg-cyber-card border border-cyber-border relative overflow-hidden group hover:border-blue-500/40 transition">
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <span className="text-xs font-mono uppercase tracking-wider">Active Collectors</span>
            <Cpu className="h-4 w-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white tracking-tight">
            {MOCK_COLLECTORS.length} / {MOCK_COLLECTORS.length} Online
          </div>
          <div className="flex items-center space-x-1.5 mt-2 text-xs text-blue-400 font-mono">
            <span>Windows • Linux • Node API</span>
          </div>
        </div>
      </div>

      {/* Main Grid: Live Events Feed & Active Collectors */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Real-time Ingestion Stream */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Terminal className="h-4 w-4 text-cyan-400" />
              <h2 className="text-sm font-bold font-mono text-white uppercase tracking-wider">Real-time Verified Stream</h2>
            </div>
            <button
              onClick={() => setActiveTab('logs')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center space-x-1"
            >
              <span>View All Logs</span>
              <ArrowUpRight className="h-3.5 w-3.5" />
            </button>
          </div>

          <div className="bg-cyber-card rounded-2xl border border-cyber-border divide-y divide-cyber-border overflow-hidden">
            {MOCK_LOGS.slice(0, 5).map((log) => (
              <div
                key={log.id + log.sequence}
                onClick={() => onSelectLog(log)}
                className="p-4 hover:bg-cyber-surface/60 transition cursor-pointer flex items-center justify-between gap-4"
              >
                <div className="flex items-start space-x-3 min-w-0">
                  <span
                    className={`mt-0.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold shrink-0 ${
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

                  <div className="min-w-0">
                    <div className="flex items-center space-x-2 font-mono text-xs">
                      <span className="text-slate-200 font-semibold truncate">{log.action}</span>
                      <span className="text-slate-500">•</span>
                      <span className="text-slate-400">{log.source}</span>
                    </div>
                    <p className="text-xs text-slate-400 truncate mt-0.5">{log.message}</p>
                  </div>
                </div>

                <div className="text-right shrink-0 font-mono">
                  <div className="flex items-center justify-end space-x-1.5">
                    {log.verified ? (
                      <span className="text-[10px] text-emerald-400 flex items-center space-x-1 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
                        <CheckCircle2 className="h-3 w-3" />
                        <span>Signed</span>
                      </span>
                    ) : (
                      <span className="text-[10px] text-amber-400 flex items-center space-x-1 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20">
                        <AlertTriangle className="h-3 w-3" />
                        <span>Seq Gap</span>
                      </span>
                    )}
                  </div>
                  <span className="text-[10px] text-slate-500 block mt-1">#{log.sequence}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Col: High Priority Alerts & Collectors */}
        <div className="space-y-6">
          {/* Edge Collectors Status */}
          <div className="p-5 rounded-2xl bg-cyber-card border border-cyber-border space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-bold font-mono text-white uppercase tracking-wider flex items-center space-x-2">
                <Cpu className="h-4 w-4 text-cyan-400" />
                <span>Edge Agent Health</span>
              </h2>
              <button
                onClick={() => setActiveTab('agents')}
                className="text-[11px] text-cyan-400 hover:underline font-mono"
              >
                Manage
              </button>
            </div>

            <div className="space-y-3">
              {MOCK_COLLECTORS.map((collector) => (
                <div key={collector.id} className="p-3 rounded-xl bg-cyber-bg border border-cyber-border flex items-center justify-between">
                  <div>
                    <div className="text-xs font-semibold text-slate-200 font-mono">{collector.name}</div>
                    <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                      {collector.host} ({collector.ip})
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                      {collector.status}
                    </span>
                    <span className="block text-[9px] text-slate-500 font-mono mt-1">
                      Q: {collector.eventsQueued}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Tamper Alert Card */}
          <div className="p-5 rounded-2xl bg-gradient-to-br from-amber-500/10 to-red-500/10 border border-amber-500/30 space-y-3">
            <div className="flex items-center space-x-2 text-amber-400">
              <ShieldAlert className="h-5 w-5 shrink-0" />
              <h3 className="text-xs font-bold font-mono uppercase tracking-wider">Integrity Watchdog</h3>
            </div>
            <p className="text-xs text-slate-300">
              The evidence engine detected a sequence gap between logs <code className="text-amber-300">#148919</code> and <code className="text-amber-300">#148921</code>.
            </p>
            <button
              onClick={() => setActiveTab('integrity')}
              className="w-full py-2 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-xs font-mono font-medium transition"
            >
              Inspect Gap in Evidence Verifier →
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
