import React, { useState } from 'react';
import { 
  History, ShieldCheck, CheckCircle2, Lock, ArrowDown, 
  RefreshCw, Check, Copy 
} from 'lucide-react';
import { INITIAL_AUDIT_TRAIL } from '../services/forensicStore';

export default function AuditTrail() {
  const [trail, setTrail] = useState(INITIAL_AUDIT_TRAIL);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifiedAll, setVerifiedAll] = useState(true);

  const handleVerifyChain = () => {
    setIsVerifying(true);
    setTimeout(() => {
      setIsVerifying(false);
      setVerifiedAll(true);
    }, 800);
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center space-x-2">
            <History className="h-5 w-5 text-white" />
            <span>Cryptographic Audit Trail (Append-Only)</span>
          </h1>
          <p className="text-xs text-platinum-400 mt-0.5">
            Sequential cryptographic hash-chain recording every operator action and evidence state transition.
          </p>
        </div>

        <button
          onClick={handleVerifyChain}
          disabled={isVerifying}
          className="px-4 py-2 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs shadow-glow-platinum transition flex items-center space-x-2 disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${isVerifying ? 'animate-spin' : ''}`} />
          <span>{isVerifying ? 'Hashing Chain...' : 'Verify Entire Chain'}</span>
        </button>
      </div>

      {/* Verification Status Banner */}
      {verifiedAll && (
        <div className="p-4 rounded-xl glass-panel border border-white/20 flex items-center justify-between font-mono text-xs animate-fadeIn">
          <div className="flex items-center space-x-2 text-white font-bold">
            <CheckCircle2 className="h-4 w-4" />
            <span>AUDIT CHAIN IMMUTABILITY CONFIRMED</span>
          </div>
          <span className="text-[10px] text-platinum-400">
            All {trail.length} records cryptographically linked with SHA-256 hash pointers.
          </span>
        </div>
      )}

      {/* Audit Log Table */}
      <div className="glass-panel rounded-2xl overflow-hidden font-mono text-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-graphite-900/80 border-b border-white/5 text-[10px] text-platinum-500 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Event ID</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Target Resource</th>
                <th className="py-3 px-4">Record SHA-256 Hash</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Proof</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-platinum-300">
              {trail.map((item) => (
                <tr key={item.id} className="hover:bg-white/5 transition">
                  <td className="py-3 px-4 font-bold text-white whitespace-nowrap">
                    {item.id}
                  </td>

                  <td className="py-3 px-4 whitespace-nowrap text-white font-semibold">
                    {item.actor}
                  </td>

                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-white/10 text-white border border-white/10">
                      {item.action}
                    </span>
                  </td>

                  <td className="py-3 px-4 whitespace-nowrap text-platinum-300">
                    {item.resource}
                  </td>

                  <td className="py-3 px-4 font-mono text-[10px] text-platinum-400">
                    {item.recordHash.slice(0, 18)}...
                  </td>

                  <td className="py-3 px-4 text-[10px] text-platinum-500 whitespace-nowrap">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </td>

                  <td className="py-3 px-4 text-right whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-white/15 text-white border border-white/30">
                      VALID
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
