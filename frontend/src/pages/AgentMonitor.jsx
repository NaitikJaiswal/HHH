import React from 'react';
import { Cpu, Activity, Database, CheckCircle2, RefreshCw, HardDrive, Zap, Server } from 'lucide-react';
import { MOCK_COLLECTORS } from '../services/mockData';

export default function AgentMonitor() {
  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold font-mono text-white flex items-center space-x-2">
          <Cpu className="h-5 w-5 text-blue-400" />
          <span>Edge Collector Agents & Heartbeats</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Monitor operating system and application log collectors, heartbeat latency, and SQLite offline queues.
        </p>
      </div>

      {/* Grid of Agent Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {MOCK_COLLECTORS.map((collector) => (
          <div key={collector.id} className="p-5 rounded-2xl bg-cyber-card border border-cyber-border space-y-4 hover:border-cyan-500/40 transition">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded uppercase bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  {collector.platform}
                </span>
                <h3 className="text-sm font-bold font-mono text-white mt-1.5">{collector.name}</h3>
                <p className="text-xs text-slate-400 font-mono">{collector.host}</p>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                {collector.status}
              </span>
            </div>

            <div className="space-y-2 text-xs font-mono border-t border-b border-cyber-border py-3 text-slate-300">
              <div className="flex justify-between">
                <span className="text-slate-500">IP Address:</span>
                <span>{collector.ip}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Agent Version:</span>
                <span>v{collector.version}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Heartbeat:</span>
                <span className="text-emerald-400">Active (5s ago)</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Offline SQLite:</span>
                <span className={collector.eventsQueued > 0 ? 'text-amber-400' : 'text-slate-400'}>
                  {collector.eventsQueued} in queue
                </span>
              </div>
            </div>

            <div>
              <span className="text-[10px] font-mono uppercase text-slate-500 block mb-1.5">Active Adapters</span>
              <div className="flex flex-wrap gap-1.5">
                {collector.adapters.map((adapter) => (
                  <span key={adapter} className="px-2 py-0.5 rounded text-[10px] bg-cyber-bg text-cyan-300 border border-cyber-border font-mono">
                    {adapter}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
