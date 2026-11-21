import React, { useState } from 'react';
import { X, Copy, Check, ShieldCheck, AlertTriangle, Hash, Key } from 'lucide-react';

export default function LogDetailModal({ log, onClose }) {
  const [copied, setCopied] = useState(false);

  if (!log) return null;

  const handleCopyRaw = () => {
    navigator.clipboard.writeText(JSON.stringify(log, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-2xl bg-cyber-card border border-cyber-border rounded-2xl p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-cyber-surface transition"
        >
          <X className="h-5 w-5" />
        </button>

        {/* Header */}
        <div className="flex items-center space-x-3 mb-5">
          <div className="h-10 w-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
            <Hash className="h-5 w-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-lg font-bold text-white font-mono">{log.id}</h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                Seq #{log.sequence}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">{log.action}</p>
          </div>
        </div>

        {/* Cryptographic Proof Verification Block */}
        <div className="p-4 rounded-xl bg-cyber-bg border border-cyber-border mb-4 space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between">
            <span className="text-slate-400 uppercase text-[10px] tracking-wider">Cryptographic Proof</span>
            {log.verified ? (
              <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center space-x-1">
                <ShieldCheck className="h-3 w-3" />
                <span>SHA-256 Chain Verified</span>
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] bg-amber-500/15 text-amber-400 border border-amber-500/30 flex items-center space-x-1">
                <AlertTriangle className="h-3 w-3" />
                <span>Sequence Anomaly</span>
              </span>
            )}
          </div>

          <div>
            <span className="text-slate-500 block text-[10px]">EVENT RECORD SHA-256 HASH</span>
            <div className="text-cyan-300 break-all bg-cyber-card p-2 rounded border border-cyber-border mt-1">
              {log.hash}
            </div>
          </div>

          <div>
            <span className="text-slate-500 block text-[10px]">PREVIOUS RECORD HASH (CHAIN LINK)</span>
            <div className="text-slate-400 break-all bg-cyber-card p-2 rounded border border-cyber-border mt-1">
              {log.prevHash}
            </div>
          </div>

          <div>
            <span className="text-slate-500 block text-[10px]">ED25519 COLLECTOR SIGNATURE</span>
            <div className="text-slate-400 break-all bg-cyber-card p-2 rounded border border-cyber-border mt-1">
              {log.signature}
            </div>
          </div>
        </div>

        {/* Structured Metadata Grid */}
        <div className="grid grid-cols-2 gap-3 mb-4 font-mono text-xs">
          <div className="p-3 rounded-xl bg-cyber-bg border border-cyber-border">
            <span className="text-slate-500 block text-[10px]">SEVERITY LEVEL</span>
            <span className="font-bold text-white">{log.level}</span>
          </div>
          <div className="p-3 rounded-xl bg-cyber-bg border border-cyber-border">
            <span className="text-slate-500 block text-[10px]">CATEGORY</span>
            <span className="text-slate-200">{log.category}</span>
          </div>
          <div className="p-3 rounded-xl bg-cyber-bg border border-cyber-border">
            <span className="text-slate-500 block text-[10px]">SOURCE HOST</span>
            <span className="text-slate-200">{log.source}</span>
          </div>
          <div className="p-3 rounded-xl bg-cyber-bg border border-cyber-border">
            <span className="text-slate-500 block text-[10px]">AUTHENTICATED USER / IP</span>
            <span className="text-slate-200">{log.user} ({log.ip})</span>
          </div>
        </div>

        {/* Raw JSON */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Raw Canonical JSON Record</span>
            <button
              onClick={handleCopyRaw}
              className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
            >
              {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <pre className="p-3 rounded-xl bg-cyber-bg border border-cyber-border text-[11px] font-mono text-slate-300 overflow-x-auto">
            {JSON.stringify(log, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}
