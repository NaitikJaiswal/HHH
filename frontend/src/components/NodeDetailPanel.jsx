import React, { useState } from 'react';
import { 
  X, Shield, Hash, Database, GitCommit, Crosshair, 
  Briefcase, Copy, Check, ExternalLink, ArrowRight, CheckCircle2, 
  AlertTriangle, Clock, Server, FileText 
} from 'lucide-react';

export default function NodeDetailPanel({ node, onClose, onNavigateTab }) {
  const [copied, setCopied] = useState(false);

  if (!node) return null;

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getHeaderIcon = (category) => {
    switch (category) {
      case 'EVIDENCE': return <Shield className="h-5 w-5 text-red-400" />;
      case 'HASH': return <Hash className="h-5 w-5 text-slate-200" />;
      case 'MERKLE': return <GitCommit className="h-5 w-5 text-slate-400" />;
      case 'BLOCKCHAIN': return <Database className="h-5 w-5 text-sky-400" />;
      case 'THREAT': return <Crosshair className="h-5 w-5 text-amber-400" />;
      case 'INVESTIGATION': return <Briefcase className="h-5 w-5 text-slate-300" />;
      default: return <Shield className="h-5 w-5 text-slate-200" />;
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 w-full sm:w-[480px] bg-[#0A0D15]/95 backdrop-blur-2xl border-l border-white/10 z-50 p-6 flex flex-col justify-between shadow-2xl animate-slideInRight font-sans">
      <div className="space-y-6 overflow-y-auto pr-1">
        {/* Panel Header */}
        <div className="flex items-start justify-between">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-xl bg-white/10 border border-white/15 flex items-center justify-center shadow-glow-platinum">
              {getHeaderIcon(node.category)}
            </div>
            <div>
              <div className="text-[10px] font-mono uppercase tracking-widest text-platinum-500">
                {node.category} ENTITY
              </div>
              <h2 className="text-base font-bold font-mono text-white truncate max-w-[280px]">
                {node.name}
              </h2>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-platinum-500 hover:text-white hover:bg-white/10 transition"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Status Docket */}
        <div className="p-3.5 rounded-xl bg-graphite-900 border border-white/5 flex items-center justify-between font-mono text-xs">
          <div>
            <span className="text-[10px] text-platinum-500 uppercase block">NODE IDENTIFIER</span>
            <span className="text-white font-bold">{node.id}</span>
          </div>
          <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${
            node.status === 'VERIFIED' ? 'bg-white/15 text-white border border-white/30 shadow-glow-platinum' :
            node.status === 'ANCHORED' ? 'bg-sky-500/15 text-sky-300 border border-sky-500/30 shadow-glow-chrome' :
            node.status === 'SUSPICIOUS' ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30 shadow-glow-amber' :
            'bg-red-500/15 text-red-300 border border-red-500/30 shadow-glow-red'
          }`}>
            {node.status}
          </span>
        </div>

        {/* Dynamic Category Sections */}
        {/* A. EVIDENCE NODE */}
        {node.category === 'EVIDENCE' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Artifact Type</span>
                <span className="text-white font-semibold">{node.type}</span>
              </div>
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">File Size</span>
                <span className="text-white font-semibold">{node.size}</span>
              </div>
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Source Host</span>
                <span className="text-white font-semibold truncate block">{node.source}</span>
              </div>
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Upload Timestamp</span>
                <span className="text-white font-semibold">{new Date(node.timestamp).toLocaleTimeString()}</span>
              </div>
            </div>

            {node.hash && (
              <div className="space-y-1">
                <div className="flex items-center justify-between text-platinum-400">
                  <span className="text-[10px] uppercase">SHA-256 Digest</span>
                  <button onClick={() => handleCopy(node.hash)} className="text-[11px] hover:text-white flex items-center space-x-1">
                    {copied ? <Check className="h-3 w-3 text-white" /> : <Copy className="h-3 w-3" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <div className="p-2.5 rounded-xl bg-obsidian-950 border border-white/5 break-all text-[11px] text-white">
                  {node.hash}
                </div>
              </div>
            )}

            <div className="p-3 rounded-xl bg-obsidian-950 border border-white/5 space-y-1.5 text-[11px]">
              <div className="flex justify-between">
                <span className="text-platinum-500">Linked Investigation:</span>
                <span className="text-white">{node.caseId || 'CASE-2026-08'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-platinum-500">Merkle Batch Ref:</span>
                <span className="text-slate-300">{node.merkleRef || 'MRK-ROOT-88'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-platinum-500">Blockchain Anchor:</span>
                <span className="text-sky-400 truncate max-w-[200px]">{node.blockchainTx || 'Sepolia Block #7219402'}</span>
              </div>
            </div>
          </div>
        )}

        {/* B. HASH NODE */}
        {node.category === 'HASH' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Algorithm</span>
                <span className="text-white font-semibold">{node.algorithm || 'SHA-256'}</span>
              </div>
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Verification Status</span>
                <span className={node.status === 'VERIFIED' ? 'text-white font-semibold' : 'text-red-400 font-semibold'}>
                  {node.status === 'VERIFIED' ? 'PASSED (0 Tampering)' : 'FAILED (Mismatch)'}
                </span>
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-[10px] uppercase text-platinum-500 block">Computed Hash</span>
              <div className="p-2.5 rounded-xl bg-obsidian-950 border border-white/5 break-all text-[11px] text-white">
                {node.computedHash || node.hash}
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-[10px] uppercase text-platinum-500 block">Recorded Baseline Hash</span>
              <div className="p-2.5 rounded-xl bg-obsidian-950 border border-white/5 break-all text-[11px] text-platinum-300">
                {node.recordedHash || node.hash}
              </div>
            </div>
          </div>
        )}

        {/* C. THREAT NODE */}
        {node.category === 'THREAT' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Severity Level</span>
                <span className={node.severity === 'CRITICAL' ? 'text-red-400 font-bold' : 'text-amber-400 font-bold'}>
                  {node.severity}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">MITRE Technique</span>
                <span className="text-white font-semibold truncate block">{node.technique}</span>
              </div>
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Source Host</span>
                <span className="text-white font-semibold">{node.source}</span>
              </div>
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Target Artifact</span>
                <span className="text-white font-semibold">{node.targetEvidence || 'System Stream'}</span>
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] text-platinum-500 uppercase block">Forensic Analysis Notes</span>
              <p className="text-platinum-300 text-xs leading-relaxed bg-obsidian-950 p-3 rounded-xl border border-white/5">
                {node.description || 'Calculated hash differs from immutable blockchain-anchored manifest.'}
              </p>
            </div>
          </div>
        )}

        {/* D. MERKLE NODE */}
        {node.category === 'MERKLE' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Batch Size</span>
                <span className="text-white font-semibold">{node.batchSize || 400} Log Records</span>
              </div>
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Tree Depth</span>
                <span className="text-white font-semibold">{node.depth || 4} Levels</span>
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] text-platinum-500 uppercase block">Merkle Root Digest</span>
              <div className="p-2.5 rounded-xl bg-obsidian-950 border border-white/5 break-all text-[11px] text-sky-400 font-bold">
                {node.hash}
              </div>
            </div>
          </div>
        )}

        {/* E. BLOCKCHAIN NODE */}
        {node.category === 'BLOCKCHAIN' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Block Number</span>
                <span className="text-sky-400 font-bold">#{node.blockNumber}</span>
              </div>
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Gas Consumed</span>
                <span className="text-white font-semibold">{node.gasUsed || '42,108 Gwei'}</span>
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] text-platinum-500 uppercase block">On-Chain Transaction Hash</span>
              <div className="p-2.5 rounded-xl bg-obsidian-950 border border-white/5 break-all text-[11px] text-white">
                {node.txHash}
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] text-platinum-500 uppercase block">Smart Contract Address</span>
              <div className="p-2.5 rounded-xl bg-obsidian-950 border border-white/5 break-all text-[11px] text-platinum-400">
                {node.smartContract || '0x4f8287e07664B34eF2a3733A0B1c5f0f35492dE8'}
              </div>
            </div>
          </div>
        )}

        {/* F. INVESTIGATION NODE */}
        {node.category === 'INVESTIGATION' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Priority</span>
                <span className={node.priority === 'P1-CRITICAL' ? 'text-red-400 font-bold' : 'text-amber-400 font-bold'}>
                  {node.priority}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Lead Analyst</span>
                <span className="text-white font-semibold">{node.leadAnalyst}</span>
              </div>
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Assigned Unit</span>
                <span className="text-white font-semibold">{node.assignedTeam}</span>
              </div>
              <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
                <span className="text-platinum-500 text-[10px] uppercase block">Artifacts Linked</span>
                <span className="text-white font-semibold">{node.evidenceCount || 3} Files</span>
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] text-platinum-500 uppercase block">Case Dossier Brief</span>
              <p className="text-platinum-300 text-xs leading-relaxed bg-obsidian-950 p-3 rounded-xl border border-white/5">
                {node.description}
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Action Footer */}
      <div className="border-t border-white/10 pt-4 mt-4 font-mono">
        <button
          onClick={() => {
            onClose();
            if (node.category === 'EVIDENCE') onNavigateTab('vault');
            else if (node.category === 'HASH') onNavigateTab('hash');
            else if (node.category === 'MERKLE') onNavigateTab('merkle');
            else if (node.category === 'BLOCKCHAIN') onNavigateTab('ledger');
            else if (node.category === 'THREAT') onNavigateTab('threats');
            else if (node.category === 'INVESTIGATION') onNavigateTab('investigations');
          }}
          className="w-full py-2.5 px-4 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs flex items-center justify-center space-x-2 shadow-glow-platinum transition"
        >
          <span>Open Full Workspace</span>
          <ArrowRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
