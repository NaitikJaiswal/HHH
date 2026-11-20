import React from 'react';
import { 
  X, Shield, Hash, Database, GitCommit, Crosshair, 
  Briefcase, Copy, Check, ExternalLink, ArrowRight, CheckCircle2, AlertTriangle 
} from 'lucide-react';

export default function NodeDetailDrawer({ node, onClose, onNavigateTab }) {
  const [copied, setCopied] = React.useState(false);

  if (!node) return null;

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getCategoryIcon = (cat) => {
    switch (cat) {
      case 'EVIDENCE': return <Shield className="h-5 w-5 text-platinum-300" />;
      case 'HASH': return <Hash className="h-5 w-5 text-white" />;
      case 'MERKLE': return <GitCommit className="h-5 w-5 text-platinum-400" />;
      case 'BLOCKCHAIN': return <Database className="h-5 w-5 text-status-anchored" />;
      case 'THREAT': return <Crosshair className="h-5 w-5 text-status-warning" />;
      case 'INVESTIGATION': return <Briefcase className="h-5 w-5 text-white" />;
      default: return <Shield className="h-5 w-5 text-platinum-300" />;
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 w-full sm:w-[460px] bg-obsidian-900/95 backdrop-blur-2xl border-l border-white/10 z-50 p-6 flex flex-col justify-between shadow-2xl animate-slideInRight font-sans">
      <div className="space-y-6 overflow-y-auto pr-1">
        {/* Drawer Header */}
        <div className="flex items-start justify-between">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-xl bg-white/10 border border-white/15 flex items-center justify-center shadow-glow-platinum">
              {getCategoryIcon(node.category)}
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
            <span className="text-[10px] text-platinum-500 uppercase block">INTEGRITY VERIFICATION</span>
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

        {/* Cryptographic Hash Section */}
        {node.hash && (
          <div className="space-y-2 font-mono text-xs">
            <div className="flex items-center justify-between text-platinum-400">
              <span className="text-[10px] uppercase">SHA-256 Fingerprint</span>
              <button
                onClick={() => handleCopy(node.hash)}
                className="text-[11px] text-platinum-300 hover:text-white flex items-center space-x-1"
              >
                {copied ? <Check className="h-3 w-3 text-white" /> : <Copy className="h-3 w-3" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="p-3 rounded-xl bg-obsidian-950 border border-white/5 break-all text-[11px] text-platinum-300 font-mono">
              {node.hash}
            </div>
          </div>
        )}

        {/* Metadata Details Grid */}
        <div className="grid grid-cols-2 gap-3 font-mono text-xs">
          {node.type && (
            <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
              <span className="text-platinum-500 text-[10px] uppercase block">Type</span>
              <span className="text-white font-semibold">{node.type}</span>
            </div>
          )}
          {node.size && (
            <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
              <span className="text-platinum-500 text-[10px] uppercase block">Size</span>
              <span className="text-white font-semibold">{node.size}</span>
            </div>
          )}
          {node.source && (
            <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
              <span className="text-platinum-500 text-[10px] uppercase block">Host / Origin</span>
              <span className="text-white font-semibold truncate block">{node.source}</span>
            </div>
          )}
          {node.timestamp && (
            <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
              <span className="text-platinum-500 text-[10px] uppercase block">Acquisition Date</span>
              <span className="text-white font-semibold">{new Date(node.timestamp).toLocaleDateString()}</span>
            </div>
          )}
          {node.blockNumber && (
            <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5">
              <span className="text-platinum-500 text-[10px] uppercase block">Block Number</span>
              <span className="text-status-anchored font-bold">#{node.blockNumber}</span>
            </div>
          )}
          {node.txHash && (
            <div className="p-3 rounded-xl bg-graphite-900/60 border border-white/5 col-span-2">
              <span className="text-platinum-500 text-[10px] uppercase block">Tx Hash</span>
              <span className="text-platinum-300 break-all text-[10px]">{node.txHash}</span>
            </div>
          )}
        </div>

        {/* Chain of Custody / Notes */}
        {node.custody && (
          <div className="space-y-2 font-mono text-xs">
            <span className="text-[10px] uppercase text-platinum-500 block">Custody Traceability</span>
            <div className="p-3 rounded-xl bg-obsidian-950 border border-white/5 space-y-1.5">
              {node.custody.map((c, i) => (
                <div key={i} className="flex items-center space-x-2 text-[11px] text-platinum-300">
                  <span className="text-platinum-500">[{i + 1}]</span>
                  <span>{c}</span>
                </div>
              ))}
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
