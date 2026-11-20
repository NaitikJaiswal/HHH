import React, { useState } from 'react';
import { 
  Crosshair, AlertTriangle, ShieldAlert, ArrowUpRight, 
  Terminal, Search, Filter, CheckCircle2, Clock 
} from 'lucide-react';

export default function ThreatHunting({ nodes, onSelectNode, setActiveTab }) {
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const threats = [
    {
      id: 'THR-701',
      title: 'Tamper Alert: NGINX Config Hash Mismatch',
      severity: 'CRITICAL',
      source: 'prod-k8s-ingress-02',
      technique: 'T1562.001 - Impair Defenses',
      timestamp: '2026-11-20T15:45:10Z',
      targetEvidence: 'EVD-9804 (security_headers.conf)',
      caseId: 'CASE-2026-09',
      indicators: ['10.0.2.88', 'root', 'SHA:e45b91...'],
      status: 'TRIAGED',
      notes: 'Unexpected modification to security headers configuration file. Hash differs from blockchain baseline.',
    },
    {
      id: 'THR-702',
      title: 'Audit Sequence Gap #148920 Omission',
      severity: 'SUSPICIOUS',
      source: 'Linux Auditd Collector',
      technique: 'T1070.006 - Indicator Removal on Host',
      timestamp: '2026-11-20T14:32:00Z',
      targetEvidence: 'EVD-9802 (auth_audit.log)',
      caseId: 'CASE-2026-08',
      indicators: ['Missing Seq #148920', 'auditd.service'],
      status: 'UNDER_INVESTIGATION',
      notes: 'Sequence jump from #148919 directly to #148921 indicates log tampering or deletion at the host layer.',
    },
    {
      id: 'THR-703',
      title: 'Memory Injection Signature in LSASS Address Space',
      severity: 'CRITICAL',
      source: 'CORP-WIN-DC01',
      technique: 'T1003.001 - OS Credential Dumping: LSASS Memory',
      timestamp: '2026-11-20T14:15:20Z',
      targetEvidence: 'EVD-9801 (memdump_srv01.raw)',
      caseId: 'CASE-2026-08',
      indicators: ['domain\\jdoe', 'svchost.exe injection', 'PID 784'],
      status: 'TRIAGED',
      notes: 'Memory dump reveals unauthorized MiniDumpWriteDump API invocation against LSASS process memory.',
    },
    {
      id: 'THR-704',
      title: 'Anomalous Encrypted DNS Tunneling Egress',
      severity: 'MEDIUM',
      source: 'Core Switch SW-04',
      technique: 'T1071.004 - Application Layer Protocol: DNS',
      timestamp: '2026-11-20T13:40:00Z',
      targetEvidence: 'EVD-9803 (exfil_traffic.pcap)',
      caseId: 'CASE-2026-09',
      indicators: ['192.168.1.104', 'exfil-node.onion.dns'],
      status: 'MONITORING',
      notes: 'High-entropy TXT record queries matching known DNS data exfiltration signature patterns.',
    },
  ];

  const filteredThreats = threats.filter((t) => {
    const matchesSev = selectedSeverity === 'ALL' || t.severity === selectedSeverity;
    const matchesSearch = 
      t.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.technique.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.source.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesSearch;
  });

  return (
    <div className="space-y-6 font-sans">
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold font-mono text-white flex items-center space-x-2">
          <Crosshair className="h-5 w-5 text-status-warning" />
          <span>Forensic Threat Hunting & Anomaly Matrix</span>
        </h1>
        <p className="text-xs text-platinum-400 mt-0.5">
          Correlate forensic anomalies, MITRE ATT&CK techniques, and evidence tampering indicators across active cases.
        </p>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-2xl glass-panel space-y-3 font-mono text-xs">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="md:col-span-2 relative">
            <Search className="absolute left-3.5 top-2.5 h-3.5 w-3.5 text-platinum-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Hunt anomalies by title, MITRE technique ID, or host..."
              className="w-full pl-9 pr-3 py-2 rounded-xl bg-graphite-900/60 border border-white/5 text-platinum-200 placeholder-platinum-600 focus:outline-none focus:border-white/30 text-xs"
            />
          </div>

          <div>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="w-full px-3 py-2 rounded-xl bg-graphite-900/60 border border-white/5 text-platinum-300 focus:outline-none focus:border-white/30 text-xs"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="SUSPICIOUS">SUSPICIOUS</option>
              <option value="MEDIUM">MEDIUM</option>
            </select>
          </div>
        </div>
      </div>

      {/* Threats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
        {filteredThreats.map((threat) => (
          <div
            key={threat.id}
            className="p-5 rounded-2xl glass-panel border border-white/5 hover:border-white/20 transition space-y-3"
          >
            <div className="flex items-start justify-between">
              <span className="text-[10px] text-platinum-500">{threat.id}</span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                threat.severity === 'CRITICAL' ? 'bg-status-critical/15 text-status-critical border border-status-critical/30 shadow-glow-red' :
                threat.severity === 'SUSPICIOUS' ? 'bg-status-warning/15 text-status-warning border border-status-warning/30 shadow-glow-amber' :
                'bg-white/10 text-platinum-300 border border-white/20'
              }`}>
                {threat.severity}
              </span>
            </div>

            <div>
              <h3 className="text-sm font-bold text-white">{threat.title}</h3>
              <p className="text-[11px] text-platinum-400 mt-0.5">{threat.technique}</p>
            </div>

            <p className="text-platinum-300 text-[11px] leading-relaxed bg-obsidian-950 p-3 rounded-xl border border-white/5">
              {threat.notes}
            </p>

            <div className="space-y-1.5 pt-1 text-[11px] text-platinum-400">
              <div className="flex justify-between">
                <span>Associated Evidence:</span>
                <span className="text-white font-semibold">{threat.targetEvidence}</span>
              </div>
              <div className="flex justify-between">
                <span>Case Docket:</span>
                <span className="text-status-anchored">{threat.caseId}</span>
              </div>
            </div>

            <div className="pt-2 border-t border-white/5 flex items-center justify-between">
              <span className="text-[10px] text-platinum-500">
                {new Date(threat.timestamp).toLocaleTimeString()}
              </span>
              <button
                onClick={() => setActiveTab('investigations')}
                className="text-[11px] text-white hover:underline flex items-center space-x-1"
              >
                <span>View Case Dossier</span>
                <ArrowUpRight className="h-3 w-3" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
