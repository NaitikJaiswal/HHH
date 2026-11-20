import React from 'react';
import { 
  ShieldCheck, AlertTriangle, Database, ArrowUpRight, 
  Terminal, CheckCircle2, ShieldAlert, Cpu, Lock, FileCheck, 
  Layers, HardDrive, Crosshair, Briefcase, RefreshCw, Activity 
} from 'lucide-react';
import ForensicConstellation3D from '../components/ForensicConstellation3D';

export default function OverviewDashboard({ 
  nodes, 
  links, 
  selectedNode, 
  onSelectNode, 
  setActiveTab 
}) {
  // Operational Metrics
  const totalEvidence = nodes.filter(n => n.category === 'EVIDENCE').length;
  const verifiedEvidence = nodes.filter(n => n.category === 'EVIDENCE' && n.status === 'VERIFIED').length;
  const integrityFailures = nodes.filter(n => n.status === 'FAILED').length;
  const activeInvestigations = nodes.filter(n => n.category === 'INVESTIGATION').length;
  const blockchainAnchored = nodes.filter(n => n.category === 'BLOCKCHAIN' || n.status === 'ANCHORED').length;
  const suspiciousEvents = nodes.filter(n => n.category === 'THREAT' || n.status === 'SUSPICIOUS').length;

  const recentActivity = [
    { id: 1, type: 'ANCHOR', text: 'Merkle Root Batch #88 anchored to Ethereum Sepolia #7219402', time: '14m ago', status: 'ANCHORED' },
    { id: 2, type: 'INTEGRITY_FAIL', text: 'Integrity Violation on security_headers.conf (Mismatch)', time: '28m ago', status: 'FAILED' },
    { id: 3, type: 'HASH_VERIFIED', text: 'RAM Dump SVR-01 SHA-256 verified against custody token', time: '42m ago', status: 'VERIFIED' },
    { id: 4, type: 'INVESTIGATION', text: 'New evidence docket assigned to Case #2026-08 (DarkVessel)', time: '1h ago', status: 'VERIFIED' },
  ];

  return (
    <div className="space-y-6 font-sans">
      {/* Cinematic 3D Forensic Constellation - Primary Centerpiece */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h1 className="text-xl font-bold font-mono text-white tracking-tight flex items-center space-x-2">
              <span>Forensic Constellation</span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-white/10 text-platinum-300 border border-white/15">
                3D SPATIAL ECOSYSTEM
              </span>
            </h1>
            <p className="text-xs text-platinum-400 mt-0.5">
              Interactive topology mapping evidence artifacts, cryptographic fingerprints, Merkle roots, blockchain anchors, and threat anomalies.
            </p>
          </div>

          <div className="flex items-center space-x-2 font-mono text-xs">
            <button
              onClick={() => setActiveTab('vault')}
              className="px-3 py-1.5 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold transition flex items-center space-x-1.5 shadow-glow-platinum"
            >
              <HardDrive className="h-3.5 w-3.5" />
              <span>Evidence Vault</span>
            </button>
            <button
              onClick={() => setActiveTab('hash')}
              className="px-3 py-1.5 rounded-xl glass-panel text-platinum-300 hover:text-white transition flex items-center space-x-1.5"
            >
              <ShieldCheck className="h-3.5 w-3.5 text-white" />
              <span>Verify Hashes</span>
            </button>
          </div>
        </div>

        {/* 3D Visualizer Canvas */}
        <ForensicConstellation3D
          nodes={nodes}
          links={links}
          selectedNode={selectedNode}
          onSelectNode={onSelectNode}
        />
      </div>

      {/* Compact Operational Telemetry Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 font-mono">
        {/* Metric 1 */}
        <div className="p-4 rounded-xl glass-panel space-y-1 group hover:border-white/20 transition">
          <div className="text-[10px] text-platinum-500 uppercase tracking-wider">Total Evidence</div>
          <div className="text-xl font-bold text-white tracking-tight">{totalEvidence + 1416}</div>
          <div className="text-[10px] text-platinum-400">Recorded files</div>
        </div>

        {/* Metric 2 */}
        <div className="p-4 rounded-xl glass-panel space-y-1 group hover:border-white/20 transition">
          <div className="text-[10px] text-platinum-500 uppercase tracking-wider">Cryptographic Proof</div>
          <div className="text-xl font-bold text-white tracking-tight">{verifiedEvidence + 1414}</div>
          <div className="text-[10px] text-white flex items-center space-x-1">
            <CheckCircle2 className="h-3 w-3" />
            <span>99.9% Verified</span>
          </div>
        </div>

        {/* Metric 3 */}
        <div className="p-4 rounded-xl glass-panel space-y-1 border-status-critical/30 group hover:border-status-critical transition">
          <div className="text-[10px] text-status-critical uppercase tracking-wider">Integrity Failures</div>
          <div className="text-xl font-bold text-status-critical tracking-tight">{integrityFailures}</div>
          <div className="text-[10px] text-status-critical/80">Tamper detected</div>
        </div>

        {/* Metric 4 */}
        <div className="p-4 rounded-xl glass-panel space-y-1 group hover:border-white/20 transition">
          <div className="text-[10px] text-platinum-500 uppercase tracking-wider">Investigations</div>
          <div className="text-xl font-bold text-white tracking-tight">{activeInvestigations + 2}</div>
          <div className="text-[10px] text-platinum-400">Active dossiers</div>
        </div>

        {/* Metric 5 */}
        <div className="p-4 rounded-xl glass-panel space-y-1 group hover:border-white/20 transition">
          <div className="text-[10px] text-platinum-500 uppercase tracking-wider">Blockchain Anchors</div>
          <div className="text-xl font-bold text-status-anchored tracking-tight">{blockchainAnchored + 840}</div>
          <div className="text-[10px] text-status-anchored">Sepolia EVM</div>
        </div>

        {/* Metric 6 */}
        <div className="p-4 rounded-xl glass-panel space-y-1 border-status-warning/30 group hover:border-status-warning transition">
          <div className="text-[10px] text-status-warning uppercase tracking-wider">Threat Anomalies</div>
          <div className="text-xl font-bold text-status-warning tracking-tight">{suspiciousEvents}</div>
          <div className="text-[10px] text-status-warning/80">Active triage</div>
        </div>
      </div>

      {/* Supporting Sections: Activity & Threat Intelligence */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Activity Feed & Integrity Summary */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between font-mono">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <Activity className="h-4 w-4 text-white" />
              <span>Cryptographic Activity Stream</span>
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

          {/* Integrity Distribution Overview */}
          <div className="p-4 rounded-2xl glass-panel space-y-3 font-mono text-xs">
            <div className="flex justify-between items-center text-platinum-400">
              <span className="text-[11px] uppercase">Cryptographic Integrity Ratio</span>
              <span className="text-white font-bold">99.98% Tamper-Evident</span>
            </div>
            <div className="h-2 w-full bg-graphite-900 rounded-full overflow-hidden flex">
              <div className="h-full bg-white shadow-glow-platinum" style={{ width: '99.8%' }} />
              <div className="h-full bg-status-critical shadow-glow-red" style={{ width: '0.2%' }} />
            </div>
            <div className="flex justify-between text-[10px] text-platinum-500">
              <span>Verified: 1418 Records</span>
              <span>Pending: 0</span>
              <span className="text-status-critical">Tamper Alerts: 2</span>
            </div>
          </div>
        </div>

        {/* Right Col: Threat Intelligence Docket */}
        <div className="space-y-4">
          <div className="flex items-center justify-between font-mono">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <Crosshair className="h-4 w-4 text-status-warning" />
              <span>Threat Intelligence</span>
            </h2>
            <button
              onClick={() => setActiveTab('threats')}
              className="text-[11px] text-status-warning hover:underline"
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
                    threat.severity === 'CRITICAL' ? 'bg-status-critical/20 text-status-critical' : 'bg-status-warning/20 text-status-warning'
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
