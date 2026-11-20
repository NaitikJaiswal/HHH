import React, { useState } from 'react';
import { 
  ShieldCheck, AlertTriangle, CheckCircle2, Lock, FileCheck, 
  RefreshCw, Check, ArrowRight, Binary, ShieldAlert 
} from 'lucide-react';
import { MOCK_CHECKPOINTS, MOCK_LOGS } from '../services/mockData';

export default function IntegrityVerifier() {
  const [checkpoints, setCheckpoints] = useState(MOCK_CHECKPOINTS);
  const [selectedCheckpoint, setSelectedCheckpoint] = useState(MOCK_CHECKPOINTS[0]);
  const [verificationResult, setVerificationResult] = useState(null);
  const [verifying, setVerifying] = useState(false);

  // Interactive hash verification simulation
  const handleVerify = () => {
    setVerifying(true);
    setVerificationResult(null);

    setTimeout(() => {
      setVerifying(false);
      setVerificationResult({
        success: true,
        merkleCalculated: selectedCheckpoint.merkleRoot,
        merkleStored: selectedCheckpoint.merkleRoot,
        signatureStatus: 'VALID_ED25519',
        tamperingDetected: false,
        eventsVerifiedCount: selectedCheckpoint.eventCount,
      });
    }, 900);
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold font-mono text-white flex items-center space-x-2">
          <ShieldCheck className="h-5 w-5 text-emerald-400" />
          <span>Evidence & Hash Integrity Engine (Harden)</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Verify signed checkpoint bundles, Merkle trees, and cryptographic audit proofs.
        </p>
      </div>

      {/* Status Bar */}
      <div className="p-4 rounded-2xl bg-cyber-card border border-cyber-border grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
            <CheckCircle2 className="h-5 w-5 text-emerald-400" />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-mono">Merkle Trees Sealed</div>
            <div className="text-sm font-bold text-white font-mono">{checkpoints.length} Checkpoints Active</div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
            <Lock className="h-5 w-5 text-cyan-400" />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-mono">Signing Scheme</div>
            <div className="text-sm font-bold text-white font-mono">Ed25519 + SHA-256</div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center">
            <ShieldAlert className="h-5 w-5 text-amber-400" />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-mono">Gap Watchdog</div>
            <div className="text-sm font-bold text-amber-400 font-mono">1 Anomaly Tracked</div>
          </div>
        </div>
      </div>

      {/* Main Grid: Checkpoints List & Verifier Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Checkpoint List */}
        <div className="space-y-3">
          <h2 className="text-xs font-bold font-mono text-white uppercase tracking-wider">
            Signed Checkpoints
          </h2>
          <div className="space-y-2">
            {checkpoints.map((chk) => (
              <div
                key={chk.id}
                onClick={() => {
                  setSelectedCheckpoint(chk);
                  setVerificationResult(null);
                }}
                className={`p-4 rounded-xl border cursor-pointer transition ${
                  selectedCheckpoint.id === chk.id
                    ? 'bg-cyber-card border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                    : 'bg-cyber-bg border-cyber-border hover:bg-cyber-card'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-xs font-mono text-white">{chk.id}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    {chk.status}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 font-mono space-y-1">
                  <div className="flex justify-between">
                    <span>Range:</span>
                    <span className="text-slate-200">#{chk.startSeq} - #{chk.endSeq}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Events:</span>
                    <span className="text-slate-200">{chk.eventCount}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right 2 cols: Verification Inspector */}
        <div className="lg:col-span-2 space-y-4">
          <div className="p-6 rounded-2xl bg-cyber-card border border-cyber-border space-y-5">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold font-mono text-white flex items-center space-x-2">
                  <Binary className="h-4 w-4 text-cyan-400" />
                  <span>Checkpoint Verification: {selectedCheckpoint.id}</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Re-hash Merkle tree leaf nodes to verify zero tampering.
                </p>
              </div>

              <button
                onClick={handleVerify}
                disabled={verifying}
                className="px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-600 hover:from-emerald-400 hover:to-cyan-500 text-slate-950 font-bold text-xs font-mono shadow-lg shadow-emerald-500/20 transition flex items-center space-x-2 disabled:opacity-50"
              >
                <RefreshCw className={`h-4 w-4 ${verifying ? 'animate-spin' : ''}`} />
                <span>{verifying ? 'Hashing Leafs...' : 'Re-verify Proof'}</span>
              </button>
            </div>

            {/* Checkpoint Details */}
            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 rounded-xl bg-cyber-bg border border-cyber-border space-y-2">
                <div className="text-slate-400 text-[11px] uppercase">Merkle Root Hash</div>
                <div className="text-cyan-300 break-all text-[11px] font-mono bg-cyber-card p-2 rounded border border-cyber-border">
                  {selectedCheckpoint.merkleRoot}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-cyber-bg border border-cyber-border space-y-2">
                <div className="text-slate-400 text-[11px] uppercase">Ed25519 HSM Signature</div>
                <div className="text-slate-300 break-all text-[11px] font-mono bg-cyber-card p-2 rounded border border-cyber-border">
                  {selectedCheckpoint.signature}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-cyber-bg border border-cyber-border">
                  <span className="text-slate-500 block text-[10px]">KEY IDENTIFIER</span>
                  <span className="text-slate-200 font-semibold">{selectedCheckpoint.signingKeyId}</span>
                </div>
                <div className="p-3 rounded-xl bg-cyber-bg border border-cyber-border">
                  <span className="text-slate-500 block text-[10px]">VERIFIER NODE</span>
                  <span className="text-slate-200 font-semibold">{selectedCheckpoint.verifierNode}</span>
                </div>
              </div>
            </div>

            {/* Verification Result Output */}
            {verificationResult && (
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 space-y-2 animate-fadeIn">
                <div className="flex items-center space-x-2 text-emerald-400 font-mono text-xs font-bold">
                  <CheckCircle2 className="h-4 w-4" />
                  <span>CRYPTOGRAPHIC INTEGRITY CONFIRMED</span>
                </div>
                <p className="text-xs text-slate-300 font-mono">
                  All {verificationResult.eventsVerifiedCount} log records in sequence range verified against the stored Merkle root. No bits altered.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
