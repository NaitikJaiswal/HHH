import React, { useState } from 'react';
import { 
  ShieldCheck, AlertTriangle, Database, ArrowUpRight, 
  Terminal, CheckCircle2, ShieldAlert, Cpu, Lock, FileCheck, 
  Layers, HardDrive, Crosshair, Briefcase, RefreshCw, Activity, Search, Filter 
} from 'lucide-react';
import ForensicNodeScene from '../components/ForensicNodeScene';

export default function OverviewDashboard({ 
  nodes, 
  links, 
  selectedNode, 
  onSelectNode, 
  setActiveTab 
}) {
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState('ALL');

  // Operational Metrics
  const totalEvidence = nodes.filter(n => n.category === 'EVIDENCE').length;
  const verifiedEvidence = nodes.filter(n => n.category === 'EVIDENCE' && n.status === 'VERIFIED').length;
  const integrityFailures = nodes.filter(n => n.status === 'FAILED').length;
  const activeInvestigations = nodes.filter(n => n.category === 'INVESTIGATION').length;
  const blockchainAnchored = nodes.filter(n => n.category === 'BLOCKCHAIN' || n.status === 'ANCHORED').length;

  const recentActivity = [
    { id: 1, type: 'ANCHOR', text: 'Merkle Root Batch #88 anchored to Ethereum Sepolia #7219402', time: '14m ago', status: 'ANCHORED' },
    { id: 2, type: 'INTEGRITY_FAIL', text: 'Integrity Violation on security_headers.conf (Mismatch)', time: '28m ago', status: 'FAILED' },
    { id: 3, type: 'HASH_VERIFIED', text: 'RAM Dump SVR-01 SHA-256 verified against custody token', time: '42m ago', status: 'VERIFIED' },
    { id: 4, type: 'INVESTIGATION', text: 'New evidence docket assigned to Case #2026-08 (DarkVessel)', time: '1h ago', status: 'VERIFIED' },
  ];

  return (
    <div className="space-y-6 font-sans">
      {/* 1. ABOVE VISUALIZATION: Top Telemetry Metric KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 font-mono">
        <div className="p-4 rounded-xl glass-panel space-y-1 group hover:border-white/20 transition">
          <div className="text-[10px] text-platinum-500 uppercase tracking-wider">Total Evidence</div>
          <div className="text-xl font-bold text-white tracking-tight">{totalEvidence + 1416}</div>
          <div className="text-[10px] text-platinum-400">Recorded files</div>
        </div>

        <div className="p-4 rounded-xl glass-panel space-y-1 group hover:border-white/20 transition">
          <div className="text-[10px] text-platinum-500 uppercase tracking-wider">Verified Records</div>
          <div className="text-xl font-bold text-white tracking-tight">{verifiedEvidence + 1414}</div>
          <div className="text-[10px] text-white flex items-center space-x-1">
            <CheckCircle2 className="h-3 w-3" />
            <span>99.9% Verified</span>
          </div>
        </div>

        <div className="p-4 rounded-xl glass-panel space-y-1 border-status-critical/30 group hover:border-status-critical transition">
          <div className="text-[10px] text-status-critical uppercase tracking-wider">Integrity Failures</div>
          <div className="text-xl font-bold text-status-critical tracking-tight">{integrityFailures}</div>
          <div className="text-[10px] text-status-critical/80">Tamper detected</div>
        </div>

        <div className="p-4 rounded-xl glass-panel space-y-1 group hover:border-white/20 transition">
          <div className="text-[10px] text-platinum-500 uppercase tracking-wider">Active Investigations</div>
          <div className="text-xl font-bold text-white tracking-tight">{activeInvestigations + 2}</div>
          <div className="text-[10px] text-platinum-400">Dossiers tracked</div>
        </div>

        <div className="p-4 rounded-xl glass-panel space-y-1 group hover:border-white/20 transition col-span-2 md:col-span-1">
          <div className="text-[10px] text-platinum-500 uppercase tracking-wider">Blockchain Anchored</div>
          <div className="text-xl font-bold text-sky-400 tracking-tight">{blockchainAnchored + 840}</div>
          <div className="text-[10px] text-sky-400">Sepolia EVM</div>
        </div>
      </div>

      {/* 2. ABOVE VIEWPORT: Controls Toolbar (Search, Filter, Actions) */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 font-mono text-xs">
        {/* Search Node */}
        <div className="relative w-full md:w-80">
          <Search className="absolute left-3.5 top-2.5 h-3.5 w-3.5 text-platinum-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search 3D nodes by ID, name, hash..."
            className="w-full pl-9 pr-3 py-2 rounded-xl bg-graphite-900/80 border border-white/10 text-platinum-200 placeholder-platinum-600 focus:outline-none focus:border-white/30 text-xs"
          />
        </div>

        {/* Filter Dropdown */}
        <div className="flex items-center space-x-2">
          <Filter className="h-3.5 w-3.5 text-platinum-400" />
          <select
            value={activeFilter}
            onChange={(e) => setActiveFilter(e.target.value)}
            className="px-3 py-2 rounded-xl bg-graphite-900/80 border border-white/10 text-platinum-200 focus:outline-none focus:border-white/30 text-xs"
          >
            <option value="ALL">All Forensic Nodes</option>
            <option value="EVIDENCE">Evidence Nodes</option>
            <option value="HASH">Hash Nodes</option>
            <option value="MERKLE">Merkle Nodes</option>
            <option value="BLOCKCHAIN">Blockchain Nodes</option>
            <option value="THREAT">Threat Nodes</option>
            <option value="INVESTIGATION">Investigation Cases</option>
            <option value="VERIFIED">Status: Verified</option>
            <option value="SUSPICIOUS">Status: Suspicious</option>
            <option value="FAILED">Status: Failed Integrity</option>
          </select>
        </div>
      </div>

      {/* 3. PRIMARY VIEWPORT: 3D Forensic Node System */}
      <ForensicNodeScene
        nodes={nodes}
        links={links}
        selectedNode={selectedNode}
        onSelectNode={onSelectNode}
        searchQuery={searchQuery}
        activeFilter={activeFilter}
      />

      {/* 4. BELOW VIEWPORT: Selected Node Information Strip */}
      {selectedNode ? (
        <div className="p-4 rounded-xl glass-panel border border-white/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs animate-fadeIn">
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
              className="px-3 py-1.5 rounded-lg bg-white text-obsidian-950 font-bold text-xs shadow-glow-platinum hover:bg-platinum-200 transition"
            >
              Open Full Docket →
            </button>
            <button
              onClick={() => onSelectNode(null)}
              className="px-2.5 py-1.5 rounded-lg glass-panel-subtle text-platinum-400 hover:text-white transition"
            >
              Deselect
            </button>
          </div>
        </div>
      ) : (
        <div className="p-3.5 rounded-xl glass-panel-subtle flex items-center justify-between font-mono text-xs text-platinum-500">
          <span>Click any 3D node or double-click to fly in and inspect its complete forensic docket.</span>
          <span className="text-platinum-400 hidden sm:block">18 Nodes Active</span>
        </div>
      )}

      {/* 5. Supporting Sections: Activity Stream & Threat Intelligence */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Activity Feed & Integrity Summary */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between font-mono">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <Activity className="h-4 w-4 text-white" />
              <span>Verification Activity Timeline</span>
            </h2>
            <button
              onClick={() => setActiveTab('audit')}
              className="text-[11px] text-platinum-400 hover:text-white flex items-center space-x-1"
            >
              <span>View Audit Trail</span>
              <ArrowUpRight className="h-3 w-3" />
            </button>
          </div>

          <div className="glass-panel rounded-2xl divide-y divide-white/5 overflow-hidden font-mono text-xs">
            {recentActivity.map((act) => (
              <div key={act.id} className="p-3.5 hover:bg-white/5 transition flex items-center justify-between gap-4">
                <div className="flex items-center space-x-3 min-w-0">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                    act.status === 'FAILED' ? 'bg-status-critical/15 text-status-critical border border-status-critical/30' :
                    act.status === 'ANCHORED' ? 'bg-status-anchored/15 text-status-anchored border border-status-anchored/30' :
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

        {/* Right Col: Threat Intelligence Docket */}
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
                className="p-4 rounded-xl glass-panel border border-white/5 hover:border-white/20 transition cursor-pointer space-y-2"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-platinum-500">{threat.id}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    threat.severity === 'CRITICAL' ? 'bg-status-critical/20 text-status-critical' : 'bg-amber-500/20 text-amber-400'
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
