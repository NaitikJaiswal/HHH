import React, { useState, useEffect } from 'react';
import { Cpu, Activity, Database, CheckCircle2, RefreshCw, HardDrive, Zap, Server, AlertCircle } from 'lucide-react';
import { sourcesApi } from '../services/api';
import { MOCK_COLLECTORS } from '../services/mockData';

export default function AgentMonitor() {
  const [collectors, setCollectors] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchSources = async () => {
    setLoading(true);
    try {
      const res = await sourcesApi.getSources();
      if (res && res.sources && res.sources.length > 0) {
        setCollectors(res.sources.map((src) => ({
          id: src.sourceId || src._id,
          name: src.name || src.sourceId,
          host: src.hostname || `${src.sourceId}.local`,
          platform: src.platform || 'Linux (systemd)',
          status: src.status || 'ACTIVE',
          ip: src.ipAddress || '127.0.0.1',
          version: '1.4.2',
          lastHeartbeat: src.lastHeartbeat ? new Date(src.lastHeartbeat).toLocaleTimeString() : 'Active',
          eventsQueued: src.queueDepth || 0,
          adapters: src.adapters || ['syslog', 'file_tail', 'auth_monitor'],
        })));
      } else {
        setCollectors(MOCK_COLLECTORS);
      }
    } catch (err) {
      console.warn('Sources API fallback to mock collectors:', err.message);
      setCollectors(MOCK_COLLECTORS);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSources();
    const interval = setInterval(fetchSources, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center space-x-2">
            <Cpu className="h-5 w-5 text-blue-400" />
            <span>Edge Collector Agents & Heartbeats</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Monitor operating system and application log collectors, heartbeat latency, and SQLite offline queues.
          </p>
        </div>

        <button
          onClick={fetchSources}
          disabled={loading}
          className="px-3 py-1.5 rounded-xl bg-cyber-card hover:bg-cyber-surface border border-cyber-border text-xs font-mono text-slate-300 flex items-center space-x-1.5 transition"
        >
          <RefreshCw className={`h-3.5 w-3.5 text-cyan-400 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Grid of Agent Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {collectors.map((collector) => (
          <div key={collector.id} className="p-5 rounded-2xl bg-cyber-card border border-cyber-border space-y-4 hover:border-cyan-500/40 transition">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded uppercase bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  {collector.platform}
                </span>
                <h3 className="text-sm font-bold font-mono text-white mt-1.5">{collector.name}</h3>
                <p className="text-xs text-slate-400 font-mono">{collector.host}</p>
              </div>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                collector.status === 'ACTIVE'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
              }`}>
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
                <span className="text-slate-500">Last Heartbeat:</span>
                <span className="text-emerald-400">{collector.lastHeartbeat}</span>
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
                {(collector.adapters || []).map((adapter) => (
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
