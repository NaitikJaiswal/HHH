import React, { useState } from 'react';
import { 
  Briefcase, Plus, User, Clock, Shield, AlertTriangle, 
  CheckCircle2, ArrowRight, FileText, Check 
} from 'lucide-react';

export default function Investigations({ onSelectNode, setActiveTab }) {
  const [selectedCase, setSelectedCase] = useState(null);
  const [showNewCaseModal, setShowNewCaseModal] = useState(false);

  const [cases, setCases] = useState([
    {
      id: 'CASE-2026-08',
      title: 'Operation DarkVessel',
      priority: 'P1-CRITICAL',
      status: 'ACTIVE',
      analyst: 'Agent A. Vance',
      team: 'Red Team Forensics',
      openedAt: '2026-11-20T13:00:00Z',
      description: 'Suspected domain credential harvesting and unauthorized LSASS memory injection detected across Windows Domain Controllers.',
      evidence: ['EVD-9801 (memdump_srv01.raw)', 'EVD-9802 (auth_audit.log)'],
      findings: [
        'Memory buffer indicates code injection via PID 784 into LSASS.',
        'Sequence gap #148920 indicates deliberate audit log deletion.',
      ],
      custody: [
        '2026-11-20 13:00: Case created by Agent A. Vance',
        '2026-11-20 14:12: EVD-9801 memory dump ingested & sealed',
        '2026-11-20 15:10: Checkpoint batch anchored to Ethereum Sepolia',
      ],
    },
    {
      id: 'CASE-2026-09',
      title: 'Incident CobaltBreeze',
      priority: 'P2-HIGH',
      status: 'UNDER_TRIAGE',
      analyst: 'Agent M. Chen',
      team: 'SOC Alpha',
      openedAt: '2026-11-20T14:50:00Z',
      description: 'Unauthorized configuration modification and high-entropy DNS query tunneling detected at edge ingress nodes.',
      evidence: ['EVD-9803 (exfil_traffic.pcap)', 'EVD-9804 (security_headers.conf)'],
      findings: [
        'NGINX config SHA-256 mismatch detected by integrity sentinel.',
        'Exfiltration PCAP capture indicates 890 MB traffic anomaly.',
      ],
      custody: [
        '2026-11-20 14:50: Incident triage initiated by Agent M. Chen',
        '2026-11-20 15:45: Tamper alert triggered on security_headers.conf',
      ],
    },
  ]);

  return (
    <div className="space-y-6 font-sans">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center space-x-2">
            <Briefcase className="h-5 w-5 text-white" />
            <span>Forensic Investigation Workspaces</span>
          </h1>
          <p className="text-xs text-platinum-400 mt-0.5">
            Manage multi-artifact investigations, forensic case dossiers, and evidentiary chain of custody.
          </p>
        </div>

        <button
          onClick={() => setShowNewCaseModal(true)}
          className="px-4 py-2 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs shadow-glow-platinum transition flex items-center space-x-2"
        >
          <Plus className="h-4 w-4" />
          <span>New Case Docket</span>
        </button>
      </div>

      {/* Cases List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
        {cases.map((c) => (
          <div
            key={c.id}
            onClick={() => setSelectedCase(c)}
            className="p-6 rounded-2xl glass-panel border border-white/5 hover:border-white/20 transition cursor-pointer space-y-4"
          >
            <div className="flex items-center justify-between">
              <span className="text-white font-bold">{c.id}</span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                c.priority === 'P1-CRITICAL' ? 'bg-status-critical/15 text-status-critical border border-status-critical/30' : 'bg-status-warning/15 text-status-warning border border-status-warning/30'
              }`}>
                {c.priority}
              </span>
            </div>

            <div>
              <h2 className="text-base font-bold text-white">{c.title}</h2>
              <p className="text-platinum-400 text-xs mt-1 leading-relaxed line-clamp-2">
                {c.description}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3 text-[11px] p-3 rounded-xl bg-obsidian-950 border border-white/5">
              <div>
                <span className="text-platinum-500 text-[10px] uppercase block">Lead Analyst</span>
                <span className="text-white font-semibold">{c.analyst}</span>
              </div>
              <div>
                <span className="text-platinum-500 text-[10px] uppercase block">Assigned Team</span>
                <span className="text-white font-semibold">{c.team}</span>
              </div>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-white/5 text-[11px] text-platinum-400">
              <span>{c.evidence.length} Sealed Artifacts</span>
              <span className="text-white flex items-center space-x-1">
                <span>Inspect Docket</span>
                <ArrowRight className="h-3 w-3" />
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Case Dossier Inspector Modal */}
      {selectedCase && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="w-full max-w-2xl glass-dropdown rounded-2xl p-6 border border-white/10 space-y-5 font-mono text-xs max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div>
                <span className="text-[10px] text-platinum-500 uppercase">{selectedCase.id}</span>
                <h3 className="text-base font-bold text-white">{selectedCase.title}</h3>
              </div>
              <button
                onClick={() => setSelectedCase(null)}
                className="text-platinum-500 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <span className="text-[10px] text-platinum-500 uppercase block mb-1">Executive Summary</span>
                <p className="text-platinum-300 text-xs leading-relaxed bg-obsidian-950 p-3 rounded-xl border border-white/5">
                  {selectedCase.description}
                </p>
              </div>

              <div>
                <span className="text-[10px] text-platinum-500 uppercase block mb-1.5">Sealed Evidence Artifacts</span>
                <div className="space-y-1.5">
                  {selectedCase.evidence.map((ev, idx) => (
                    <div key={idx} className="p-2.5 rounded-lg bg-graphite-900 text-white flex items-center justify-between">
                      <span>{ev}</span>
                      <span className="text-[10px] text-status-anchored">SEALED (SHA-256)</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <span className="text-[10px] text-platinum-500 uppercase block mb-1.5">Forensic Findings</span>
                <div className="space-y-1.5">
                  {selectedCase.findings.map((f, idx) => (
                    <div key={idx} className="p-2.5 rounded-lg bg-obsidian-950 border border-white/5 text-platinum-300">
                      • {f}
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <span className="text-[10px] text-platinum-500 uppercase block mb-1.5">Chain of Custody Events</span>
                <div className="space-y-1 text-[11px] text-platinum-400">
                  {selectedCase.custody.map((c, idx) => (
                    <div key={idx} className="p-2 rounded bg-graphite-900/60">
                      {c}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-white/10 flex justify-end">
              <button
                onClick={() => setSelectedCase(null)}
                className="px-4 py-2 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs"
              >
                Close Case Docket
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
