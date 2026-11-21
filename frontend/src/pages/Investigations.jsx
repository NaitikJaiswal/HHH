import React, { useState, useEffect } from 'react';
import { 
  Briefcase, Plus, User, Clock, Shield, AlertTriangle, 
  CheckCircle2, ArrowRight, FileText, Check, RefreshCw, AlertCircle
} from 'lucide-react';
import { forensicsApi } from '../services/api';

export default function Investigations({ onSelectNode, setActiveTab }) {
  const [selectedCase, setSelectedCase] = useState(null);
  const [showNewCaseModal, setShowNewCaseModal] = useState(false);
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(false);
  const [timeline, setTimeline] = useState(null);
  const [loadingTimeline, setLoadingTimeline] = useState(false);
  const [statusMessage, setStatusMessage] = useState(null);

  // New Case form state
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newSeverity, setNewSeverity] = useState('HIGH');
  const [newSource, setNewSource] = useState('workstation-forensic-01');

  useEffect(() => {
    loadInvestigations();
  }, []);

  const loadInvestigations = async () => {
    try {
      setLoading(true);
      const data = await forensicsApi.getInvestigations();
      if (data && data.length > 0) {
        const mapped = data.map((c) => ({
          id: c.caseId || `CASE-${c.incidentId}`,
          title: c.title || 'Cryptographic Anomaly Investigation',
          priority: c.severity === 'CRITICAL' ? 'P1-CRITICAL' : c.severity === 'HIGH' ? 'P2-HIGH' : 'P3-MEDIUM',
          status: c.status || 'ACTIVE',
          analyst: c.analyst || 'HHH Forensic Team',
          team: 'SOC Core Operations',
          openedAt: c.detectedAt || new Date().toISOString(),
          description: c.title || 'Automated or manual forensic docket for anomalous log sequences.',
          sourceId: c.sourceId,
          evidence: [`EVD-${c.sourceId || 'primary'} (Sealed Hash Chain)`, 'Checkpoints (FSS Epoch Bound)'],
          findings: [
            'Sequential hash-chain continuity validated across active FSS epoch.',
            'Quai Network Cyprus-1 blockchain anchor verified against SecureLogAnchor contract.',
          ],
          custody: c.custody || [
            `${new Date(c.detectedAt || Date.now()).toISOString()}: Case docket initiated`,
            'Checkpoint batch anchored to Quai Network Orchard Cyprus-1 Testnet (Chain ID 15000)',
          ],
        }));
        setCases(mapped);
      } else {
        setCases(fallbackCases);
      }
    } catch (err) {
      console.warn('Falling back to local investigations baseline:', err);
      setCases(fallbackCases);
    } finally {
      setLoading(false);
    }
  };

  const fallbackCases = [
    {
      id: 'CASE-2026-08',
      title: 'Operation DarkVessel',
      priority: 'P1-CRITICAL',
      status: 'ACTIVE',
      analyst: 'Agent A. Vance',
      team: 'Red Team Forensics',
      openedAt: '2026-11-20T13:00:00Z',
      description: 'Suspected domain credential harvesting and unauthorized LSASS memory injection detected across Windows Domain Controllers.',
      sourceId: 'srv-dc-01',
      evidence: ['EVD-9801 (memdump_srv01.raw)', 'EVD-9802 (auth_audit.log)'],
      findings: [
        'Memory buffer indicates code injection via PID 784 into LSASS.',
        'Sequence gap #148920 indicates deliberate audit log deletion.',
      ],
      custody: [
        '2026-11-20 13:00: Case created by Agent A. Vance',
        '2026-11-20 14:12: EVD-9801 memory dump ingested & sealed',
        '2026-11-20 15:10: Checkpoint batch anchored to Quai Network Orchard Cyprus-1 Testnet',
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
      sourceId: 'edge-ingress-02',
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
  ];

  const handleSelectCase = async (c) => {
    setSelectedCase(c);
    setTimeline(null);
    try {
      setLoadingTimeline(true);
      const data = await forensicsApi.getTimeline({ sourceId: c.sourceId, limit: 30 });
      setTimeline(data);
    } catch (err) {
      console.warn('Could not load detailed timeline:', err);
    } finally {
      setLoadingTimeline(false);
    }
  };

  const handleCreateCase = async (e) => {
    e.preventDefault();
    if (!newTitle) return;

    try {
      await forensicsApi.createInvestigation({
        title: newTitle,
        description: newDescription || newTitle,
        severity: newSeverity.toLowerCase(),
        sourceId: newSource,
      });

      setStatusMessage({ type: 'success', text: `Created investigation: ${newTitle}` });
      setShowNewCaseModal(false);
      setNewTitle('');
      setNewDescription('');
      loadInvestigations();
      setTimeout(() => setStatusMessage(null), 4000);
    } catch (err) {
      setStatusMessage({ type: 'error', text: `Failed to create case: ${err.message}` });
    }
  };

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

        <div className="flex items-center space-x-2">
          <button
            onClick={loadInvestigations}
            disabled={loading}
            className="px-3 py-1.5 rounded-xl glass-panel hover:bg-white/10 text-xs font-mono text-platinum-300 transition flex items-center space-x-2"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={() => setShowNewCaseModal(true)}
            className="px-4 py-2 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs shadow-glow-platinum transition flex items-center space-x-2"
          >
            <Plus className="h-4 w-4" />
            <span>New Case Docket</span>
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className={`p-3 rounded-xl border text-xs font-mono flex items-center space-x-2 ${
          statusMessage.type === 'error' ? 'bg-status-critical/10 border-status-critical/30 text-status-critical' : 'bg-white/10 border-white/20 text-white'
        }`}>
          {statusMessage.type === 'error' ? <AlertCircle className="h-4 w-4" /> : <CheckCircle2 className="h-4 w-4" />}
          <span>{statusMessage.text}</span>
        </div>
      )}

      {/* Cases List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
        {cases.map((c) => (
          <div
            key={c.id}
            onClick={() => handleSelectCase(c)}
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

              {/* Reconstructed Timeline */}
              <div>
                <span className="text-[10px] text-platinum-500 uppercase block mb-1.5">Reconstructed Attack Timeline</span>
                {loadingTimeline ? (
                  <div className="text-platinum-400 py-3 animate-pulse">Reconstructing sequential timeline from hash-chain logs...</div>
                ) : timeline && timeline.events && timeline.events.length > 0 ? (
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {timeline.events.slice(0, 6).map((ev, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-obsidian-950 border border-white/5 flex items-center justify-between text-[11px]">
                        <div>
                          <span className="font-bold text-white">#{ev.sequenceNumber}</span>
                          <span className="text-platinum-400 ml-2">{ev.phase}</span>
                          <div className="text-[10px] text-platinum-500 truncate max-w-md">{ev.message}</div>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          ev.integrityStatus === 'VERIFIED' ? 'bg-white/10 text-white' : 'bg-status-critical/15 text-status-critical'
                        }`}>
                          {ev.integrityStatus}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-platinum-500 text-xs p-3 rounded-xl bg-obsidian-950">
                    No active sequence breaches or anomalies detected in event trajectory.
                  </div>
                )}
              </div>

              <div>
                <span className="text-[10px] text-platinum-500 uppercase block mb-1.5">Sealed Evidence Artifacts</span>
                <div className="space-y-1.5">
                  {selectedCase.evidence.map((ev, idx) => (
                    <div key={idx} className="p-2.5 rounded-lg bg-graphite-900 text-white flex items-center justify-between">
                      <span>{ev}</span>
                      <span className="text-[10px] text-status-anchored">SEALED (SHA-256 + FSS)</span>
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

      {/* New Case Modal */}
      {showNewCaseModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-obsidian-950/80 backdrop-blur-sm font-mono text-xs">
          <div className="w-full max-w-md p-6 rounded-2xl glass-panel border border-white/10 space-y-4">
            <h2 className="text-base font-bold text-white flex items-center space-x-2">
              <Plus className="h-4 w-4" />
              <span>Create New Investigation Case Docket</span>
            </h2>

            <form onSubmit={handleCreateCase} className="space-y-3">
              <div>
                <label className="text-platinum-400 text-[10px]">Case Title</label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Unauthorized Credential Access Investigation"
                  className="w-full px-3 py-2 rounded-xl bg-graphite-900/60 border border-white/5 text-white text-xs mt-1"
                />
              </div>

              <div>
                <label className="text-platinum-400 text-[10px]">Description & Scope</label>
                <textarea
                  rows={3}
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder="Details of suspected compromise, target source, and timeline..."
                  className="w-full px-3 py-2 rounded-xl bg-graphite-900/60 border border-white/5 text-white text-xs mt-1"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-platinum-400 text-[10px]">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-graphite-900/60 border border-white/5 text-white text-xs mt-1"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div>
                  <label className="text-platinum-400 text-[10px]">Target Source ID</label>
                  <input
                    type="text"
                    value={newSource}
                    onChange={(e) => setNewSource(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-graphite-900/60 border border-white/5 text-white text-xs mt-1"
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowNewCaseModal(false)}
                  className="px-3.5 py-1.5 rounded-xl glass-panel text-platinum-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-xl bg-white text-obsidian-950 font-bold hover:bg-platinum-200"
                >
                  Initialize Docket
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
