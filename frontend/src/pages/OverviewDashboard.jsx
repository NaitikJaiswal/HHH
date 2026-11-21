import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, AlertTriangle, Database, ArrowUpRight, 
  Terminal, CheckCircle2, ShieldAlert, Cpu, Lock, FileCheck, 
  Layers, HardDrive, Crosshair, Briefcase, RefreshCw, Activity, Search, Filter,
  Box, List, BarChart3, Clock, CheckCircle, XCircle, AlertCircle, Share2
} from 'lucide-react';
import ForensicNodeScene from '../components/ForensicNodeScene';
import { dashboardApi, fssApi } from '../services/api';

export default function OverviewDashboard({ 
  nodes, 
  links, 
  selectedNode, 
  onSelectNode, 
  setActiveTab 
}) {
  const [viewMode, setViewMode] = useState('3D'); // '3D' | 'LIST' | 'ANALYTICS'
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState('ALL');
  const [backendStats, setBackendStats] = useState(null);
  const [fssInfo, setFssInfo] = useState(null);
  const [liveActivity, setLiveActivity] = useState([]);

  useEffect(() => {
    async function loadBackendDashboard() {
      try {
        const [statsRes, actRes, fssRes] = await Promise.allSettled([
          dashboardApi.getStats(),
          dashboardApi.getActivity(10),
          fssApi.getStatus(),
        ]);
        if (statsRes.status === 'fulfilled' && statsRes.value) {
          setBackendStats(statsRes.value);
        }
        if (actRes.status === 'fulfilled' && actRes.value) {
          setLiveActivity(actRes.value);
        }
        if (fssRes.status === 'fulfilled' && fssRes.value) {
          setFssInfo(fssRes.value);
        }
      } catch (err) {
        console.warn('Dashboard telemetry fetch notice:', err.message);
      }
    }
    loadBackendDashboard();
    const interval = setInterval(loadBackendDashboard, 15000);
    return () => clearInterval(interval);
  }, []);

  // Operational Metrics
  const totalEvents = backendStats?.totalLogs ?? (nodes.filter(n => n.category === 'EVIDENCE').length);
  const verifiedEvents = backendStats ? (backendStats.totalLogs - (backendStats.criticalIncidents || 0)) : nodes.filter(n => n.category === 'EVIDENCE' && n.status === 'VERIFIED').length;
  const integrityFailures = backendStats?.criticalIncidents ?? nodes.filter(n => n.status === 'FAILED').length;
  const activeInvestigations = backendStats?.openIncidents ?? nodes.filter(n => n.category === 'INVESTIGATION').length;
  const blockchainAnchored = backendStats?.totalCheckpoints ?? nodes.filter(n => n.category === 'BLOCKCHAIN' || n.status === 'ANCHORED').length;

  const filterOptions = [
    { id: 'ALL', label: 'All Entities', count: nodes.length },
    { id: 'EVIDENCE', label: 'Evidence', count: nodes.filter(n => n.category === 'EVIDENCE').length },
    { id: 'HASH', label: 'Hashes', count: nodes.filter(n => n.category === 'HASH').length },
    { id: 'MERKLE', label: 'Merkle Roots', count: nodes.filter(n => n.category === 'MERKLE').length },
    { id: 'BLOCKCHAIN', label: 'Blockchain', count: nodes.filter(n => n.category === 'BLOCKCHAIN').length },
    { id: 'THREAT', label: 'Threats', count: nodes.filter(n => n.category === 'THREAT').length },
    { id: 'INVESTIGATION', label: 'Cases', count: nodes.filter(n => n.category === 'INVESTIGATION').length },
  ];

  const recentActivity = [
    { id: 1, type: 'ANCHOR', text: 'Merkle Root Batch #88 anchored to Ethereum Sepolia Block #7219402', time: '14m ago', status: 'ANCHORED' },
    { id: 2, type: 'INTEGRITY_FAIL', text: 'Integrity Violation on security_headers.conf (SHA-256 Mismatch)', time: '28m ago', status: 'FAILED' },
    { id: 3, type: 'HASH_VERIFIED', text: 'server_access.log SHA-256 verified against custody token manifest', time: '42m ago', status: 'VERIFIED' },
    { id: 4, type: 'INVESTIGATION', text: 'New evidence docket assigned to Case #2026-001 (Operation DarkVessel)', time: '1h ago', status: 'VERIFIED' },
  ];

  const filteredNodes = nodes.filter((n) => {
    const matchesFilter = activeFilter === 'ALL' || n.category === activeFilter;
    const matchesSearch = !searchQuery || 
      n.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
      n.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (n.hash && n.hash.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesFilter && matchesSearch;
  });

  return (
    <div className="space-y-6 font-sans">
      {/* 1. MAIN CONTENT HEADER: Page Heading & View Selector */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono">
        <div>
          <div className="text-[10px] text-platinum-500 uppercase tracking-widest flex items-center space-x-2">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Digital Forensics Command Center</span>
          </div>
          <h1 className="text-xl font-bold text-white tracking-tight mt-0.5">
            Forensic Intelligence
          </h1>
        </div>

        {/* View Selector (3D Spatial / List View / Analytics) */}
        <div className="flex items-center space-x-1 bg-[#101114] p-1 rounded-xl border border-white/10 text-xs">
          <button
            onClick={() => setViewMode('3D')}
            className={`px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition ${
              viewMode === '3D' ? 'bg-[#15171B] text-white border border-white/20 shadow-lg' : 'text-platinum-400 hover:text-white'
            }`}
          >
            <Box className="h-3.5 w-3.5" />
            <span>3D Spatial</span>
          </button>
          <button
            onClick={() => setViewMode('LIST')}
            className={`px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition ${
              viewMode === 'LIST' ? 'bg-[#15171B] text-white border border-white/20 shadow-lg' : 'text-platinum-400 hover:text-white'
            }`}
          >
            <List className="h-3.5 w-3.5" />
            <span>List View</span>
          </button>
          <button
            onClick={() => setViewMode('ANALYTICS')}
            className={`px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition ${
              viewMode === 'ANALYTICS' ? 'bg-[#15171B] text-white border border-white/20 shadow-lg' : 'text-platinum-400 hover:text-white'
            }`}
          >
            <BarChart3 className="h-3.5 w-3.5" />
            <span>Analytics</span>
          </button>
        </div>
      </div>

      {/* 2. COMPACT OPERATIONAL TELEMETRY METRICS */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 font-mono">
        <div className="p-4 rounded-xl bg-[#101114] border border-white/10 space-y-1 hover:border-white/20 transition">
          <div className="text-[10px] text-platinum-500 uppercase tracking-wider">Total Events</div>
          <div className="text-xl font-bold text-white tracking-tight">{totalEvents}</div>
          <div className="text-[10px] text-platinum-400">Recorded records</div>
        </div>

        <div className="p-4 rounded-xl bg-[#101114] border border-white/10 space-y-1 hover:border-white/20 transition">
          <div className="text-[10px] text-platinum-500 uppercase tracking-wider">Verified Records</div>
          <div className="text-xl font-bold text-white tracking-tight">{verifiedEvents}</div>
          <div className="text-[10px] text-emerald-400 flex items-center space-x-1">
            <CheckCircle2 className="h-3 w-3" />
            <span>FSS Epoch {fssInfo?.epoch ?? 0}</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#101114] border border-red-500/30 space-y-1 hover:border-red-500 transition">
          <div className="text-[10px] text-red-400 uppercase tracking-wider">Integrity Failures</div>
          <div className="text-xl font-bold text-red-400 tracking-tight">{integrityFailures}</div>
          <div className="text-[10px] text-red-400/80">
            {integrityFailures > 0 ? 'Tamper detected' : 'Zero compromises'}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#101114] border border-white/10 space-y-1 hover:border-white/20 transition">
          <div className="text-[10px] text-platinum-500 uppercase tracking-wider">Active Cases</div>
          <div className="text-xl font-bold text-white tracking-tight">{activeInvestigations}</div>
          <div className="text-[10px] text-platinum-400">Dossiers tracked</div>
        </div>

        <div className="p-4 rounded-xl bg-[#101114] border border-white/10 space-y-1 hover:border-white/20 transition col-span-2 md:col-span-1">
          <div className="text-[10px] text-platinum-500 uppercase tracking-wider">Blockchain Anchors</div>
          <div className="text-xl font-bold text-sky-400 tracking-tight">{blockchainAnchored}</div>
          <div className="text-[10px] text-sky-400">Quai Cyprus-1</div>
        </div>
      </div>

      {/* 3. CONTROLS TOOLBAR: Filter Pills & Search */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 font-mono text-xs">
        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5 overflow-x-auto pb-1 md:pb-0">
          {filterOptions.map((f) => (
            <button
              key={f.id}
              onClick={() => setActiveFilter(f.id)}
              className={`px-3 py-1.5 rounded-xl border transition flex items-center space-x-1.5 ${
                activeFilter === f.id
                  ? 'bg-white text-[#070809] border-white font-bold shadow-glow-platinum'
                  : 'bg-[#101114] border-white/10 text-platinum-400 hover:text-white hover:border-white/20'
              }`}
            >
              <span>{f.label}</span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded-full ${
                activeFilter === f.id ? 'bg-[#070809]/20 text-[#070809]' : 'bg-white/10 text-platinum-400'
              }`}>
                {f.count}
              </span>
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="relative w-full md:w-72 shrink-0">
          <Search className="absolute left-3.5 top-2.5 h-3.5 w-3.5 text-platinum-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search nodes by ID or name..."
            className="w-full pl-9 pr-3 py-2 rounded-xl bg-[#101114] border border-white/10 text-platinum-200 placeholder-platinum-600 focus:outline-none focus:border-white/30 text-xs"
          />
        </div>
      </div>

      {/* 4. PRIMARY VIEWPORT: 3D SPATIAL / LIST / ANALYTICS */}
      {viewMode === '3D' && (
        <ForensicNodeScene
          nodes={nodes}
          links={links}
          selectedNode={selectedNode}
          onSelectNode={onSelectNode}
          searchQuery={searchQuery}
          activeFilter={activeFilter}
        />
      )}

      {viewMode === 'LIST' && (
        <div className="bg-[#101114] border border-white/10 rounded-2xl overflow-hidden font-mono text-xs">
          <div className="p-4 border-b border-white/10 flex items-center justify-between">
            <div className="text-white font-bold">Forensic Registry Entities ({filteredNodes.length})</div>
            <div className="text-platinum-500 text-[11px]">Click row to open detailed docket</div>
          </div>
          <div className="divide-y divide-white/5">
            {filteredNodes.map((n) => (
              <div
                key={n.id}
                onClick={() => onSelectNode(n)}
                className="p-4 hover:bg-white/5 transition cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-3"
              >
                <div className="flex items-center space-x-3">
                  <span className={`h-2.5 w-2.5 rounded-full shrink-0 ${
                    n.status === 'FAILED' ? 'bg-red-500' :
                    n.status === 'SUSPICIOUS' ? 'bg-amber-400' : 'bg-emerald-400'
                  }`} />
                  <div>
                    <div className="text-white font-semibold flex items-center space-x-2">
                      <span>{n.name}</span>
                      <span className="text-[10px] text-platinum-500 px-1.5 py-0.5 rounded bg-white/10">{n.id}</span>
                    </div>
                    <div className="text-[10px] text-platinum-400">{n.subtitle || n.category}</div>
                  </div>
                </div>

                <div className="flex items-center space-x-4 text-[11px] text-platinum-400">
                  {n.hash && (
                    <div className="truncate max-w-xs text-platinum-500">
                      SHA: {n.hash.slice(0, 16)}...
                    </div>
                  )}
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    n.status === 'FAILED' ? 'bg-red-500/20 text-red-400' :
                    n.status === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-400' :
                    'bg-emerald-500/20 text-emerald-400'
                  }`}>
                    {n.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {viewMode === 'ANALYTICS' && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-mono text-xs">
          <div className="p-5 rounded-2xl bg-[#101114] border border-white/10 space-y-4">
            <div className="text-white font-bold flex items-center space-x-2">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              <span>Integrity Verification Ratio</span>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-platinum-400 text-[11px]">
                <span>Verified Clean</span>
                <span className="text-white">99.8%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-white/10 overflow-hidden">
                <div className="h-full bg-emerald-400 rounded-full" style={{ width: '99.8%' }} />
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-platinum-400 text-[11px]">
                <span>Tamper / Mismatch</span>
                <span className="text-red-400">0.2%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-white/10 overflow-hidden">
                <div className="h-full bg-red-400 rounded-full" style={{ width: '12%' }} />
              </div>
            </div>
          </div>

          <div className="p-5 rounded-2xl bg-[#101114] border border-white/10 space-y-4">
            <div className="text-white font-bold flex items-center space-x-2">
              <Database className="h-4 w-4 text-sky-400" />
              <span>Blockchain Anchor Finality</span>
            </div>
            <div className="space-y-2 text-[11px] text-platinum-400">
              <div className="flex justify-between">
                <span>Ethereum Sepolia Network</span>
                <span className="text-white">Block #7219402</span>
              </div>
              <div className="flex justify-between">
                <span>Consortium Besu Ledger</span>
                <span className="text-white">Block #44190</span>
              </div>
              <div className="flex justify-between">
                <span>Merkle Batch Finality</span>
                <span className="text-emerald-400">Confirmed (100%)</span>
              </div>
            </div>
          </div>

          <div className="p-5 rounded-2xl bg-[#101114] border border-white/10 space-y-4">
            <div className="text-white font-bold flex items-center space-x-2">
              <Crosshair className="h-4 w-4 text-amber-400" />
              <span>Active Threat Vectors</span>
            </div>
            <div className="space-y-2 text-[11px] text-platinum-400">
              <div className="flex justify-between">
                <span>T1562.001 Impair Defenses</span>
                <span className="text-red-400">1 Critical</span>
              </div>
              <div className="flex justify-between">
                <span>T1003.001 Credential Dump</span>
                <span className="text-amber-400">1 High</span>
              </div>
              <div className="flex justify-between">
                <span>Chain of Custody Breaches</span>
                <span className="text-emerald-400">0 Detected</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 5. SELECTED NODE INFORMATION PANEL STRIP */}
      {selectedNode ? (
        <div className="p-4 rounded-xl bg-[#101114] border border-white/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs animate-fadeIn shadow-2xl">
          <div className="flex items-center space-x-3">
            <span className="h-3 w-3 rounded-full bg-white shadow-glow-platinum shrink-0" />
            <div>
              <div className="text-white font-bold">{selectedNode.name} [{selectedNode.id}]</div>
              <div className="text-[10px] text-platinum-400">
                {selectedNode.category} • Status: <span className="text-white">{selectedNode.status}</span> • {selectedNode.source || selectedNode.network || 'Enclave Core'}
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-2 shrink-0">
            <button
              onClick={() => onSelectNode(selectedNode)}
              className="px-3 py-1.5 rounded-lg bg-white text-[#070809] font-bold text-xs shadow-glow-platinum hover:bg-platinum-200 transition"
            >
              Open Full Docket →
            </button>
            <button
              onClick={() => onSelectNode(null)}
              className="px-2.5 py-1.5 rounded-lg bg-[#15171B] border border-white/10 text-platinum-400 hover:text-white transition"
            >
              Deselect
            </button>
          </div>
        </div>
      ) : (
        <div className="p-3.5 rounded-xl bg-[#101114]/80 border border-white/5 flex items-center justify-between font-mono text-xs text-platinum-500">
          <span>Click any 3D node or double-click to fly in and inspect its complete forensic docket.</span>
          <span className="text-platinum-400 hidden sm:block">{nodes.length} Nodes Synchronized</span>
        </div>
      )}

      {/* 6. SUPPORTING SECTIONS BELOW 3D SCENE */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Evidence Activity Timeline & Blockchain Anchoring */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between font-mono">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <Activity className="h-4 w-4 text-white" />
              <span>Evidence Activity Timeline</span>
            </h2>
            <button
              onClick={() => setActiveTab('audit')}
              className="text-[11px] text-platinum-400 hover:text-white flex items-center space-x-1"
            >
              <span>View Audit Trail</span>
              <ArrowUpRight className="h-3 w-3" />
            </button>
          </div>

          <div className="bg-[#101114] border border-white/10 rounded-2xl divide-y divide-white/5 overflow-hidden font-mono text-xs">
            {recentActivity.map((act) => (
              <div key={act.id} className="p-3.5 hover:bg-white/5 transition flex items-center justify-between gap-4">
                <div className="flex items-center space-x-3 min-w-0">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                    act.status === 'FAILED' ? 'bg-red-500/15 text-red-400 border border-red-500/30' :
                    act.status === 'ANCHORED' ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30' :
                    'bg-white/10 text-white border border-white/20'
                  }`}>
                    {act.type}
                  </span>
                  <p className="text-platinum-300 truncate">{act.text}</p>
                </div>
                <span className="text-[10px] text-platinum-500 shrink-0">{act.time}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Right Col: Threat Sentinel Alerts */}
        <div className="space-y-4">
          <div className="flex items-center justify-between font-mono">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <Crosshair className="h-4 w-4 text-amber-400" />
              <span>Threat Sentinel Alerts</span>
            </h2>
            <button
              onClick={() => setActiveTab('threats')}
              className="text-[11px] text-amber-400 hover:underline"
            >
              Hunt Matrix
            </button>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {nodes.filter(n => n.category === 'THREAT').map((threat) => (
              <div 
                key={threat.id}
                onClick={() => onSelectNode(threat)}
                className="p-4 rounded-xl bg-[#101114] border border-white/10 hover:border-white/30 transition cursor-pointer space-y-2 shadow-lg"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-platinum-500">{threat.id}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    threat.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'
                  }`}>
                    {threat.severity}
                  </span>
                </div>
                <div className="text-white font-semibold">{threat.name}</div>
                <div className="text-[10px] text-platinum-400">{threat.technique}</div>
                <div className="text-[10px] text-platinum-500 flex justify-between pt-1 border-t border-white/5">
                  <span>Target: {threat.targetEvidence || 'System Stream'}</span>
                  <span>{new Date(threat.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
