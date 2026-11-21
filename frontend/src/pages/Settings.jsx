import React, { useState, useEffect } from 'react';
import { Sliders, Shield, Database, Cpu, Check, Lock, Globe, RefreshCw, AlertTriangle, Key } from 'lucide-react';
import { fssApi, blockchainApi } from '../services/api';

export default function Settings() {
  const [graphicsMode, setGraphicsMode] = useState('high');
  const [rpcEndpoint, setRpcEndpoint] = useState('https://orchard.rpc.quai.network/cyprus1');
  const [enclaveId, setEnclaveId] = useState('SEC-ALPHA-8092');
  const [saved, setSaved] = useState(false);
  const [fssInfo, setFssInfo] = useState(null);
  const [fssActionLoading, setFssActionLoading] = useState(false);
  const [fssMessage, setFssMessage] = useState(null);

  const fetchFss = async () => {
    try {
      const data = await fssApi.getStatus();
      setFssInfo(data);
    } catch (err) {
      console.warn('Could not fetch FSS state in settings:', err.message);
    }
  };

  useEffect(() => {
    fetchFss();
  }, []);

  const handleEvolve = async () => {
    setFssActionLoading(true);
    setFssMessage(null);
    try {
      const res = await fssApi.evolveEpoch();
      setFssMessage({ type: 'success', text: `Evolved to FSS Epoch ${res.epoch} under same Master Public Key` });
      fetchFss();
    } catch (err) {
      setFssMessage({ type: 'error', text: err.message });
    } finally {
      setFssActionLoading(false);
    }
  };

  const handleEmergencyFreeze = async () => {
    if (!window.confirm('Trigger Emergency Signing Freeze? Active signing key will be shredded.')) {
      return;
    }
    setFssActionLoading(true);
    setFssMessage(null);
    try {
      const res = await fssApi.emergencyRevoke({ reason: 'Manual operator initiated freeze from command center' });
      setFssMessage({ type: 'warning', text: `Key shredded. Revocation notice published for epoch ${res.compromiseEpoch}` });
      fetchFss();
    } catch (err) {
      setFssMessage({ type: 'error', text: err.message });
    } finally {
      setFssActionLoading(false);
    }
  };

  const handleSave = (e) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="space-y-6 font-sans max-w-4xl">
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold font-mono text-white flex items-center space-x-2">
          <Sliders className="h-5 w-5 text-white" />
          <span>Enclave Configuration & Forward-Secure Parameters</span>
        </h1>
        <p className="text-xs text-platinum-400 mt-0.5">
          Configure adaptive forward-secure cryptography (MKT-FSS), Quai network consensus RPC, and visual rendering parameters.
        </p>
      </div>

      {/* FSS Cryptographic Lifecycle Management */}
      <div className="p-6 rounded-2xl glass-panel space-y-4 font-mono text-xs">
        <div className="flex items-center justify-between border-b border-white/5 pb-3">
          <div className="flex items-center space-x-2">
            <Key className="h-4 w-4 text-cyan-400" />
            <h2 className="text-xs font-bold text-white uppercase tracking-wider">
              Forward-Secure Cryptography (Ed25519-MKT-FSS)
            </h2>
          </div>
          <span className={`px-2 py-0.5 rounded text-[10px] ${
            fssInfo?.isRevoked
              ? 'bg-red-500/20 text-red-400 border border-red-500/30'
              : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
          }`}>
            {fssInfo?.isRevoked ? 'SIGNING FROZEN / REVOKED' : 'ACTIVE SIGNING STATE'}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-3 rounded-xl bg-obsidian-950 border border-white/10 space-y-1">
            <span className="text-[10px] text-platinum-500 uppercase block">Current FSS Epoch</span>
            <div className="text-white text-base font-bold">
              Epoch {fssInfo?.epoch ?? 0}
            </div>
            <span className="text-[10px] text-platinum-400 block">
              Policy: Normal Mode (8h) · Rollback Protected
            </span>
          </div>

          <div className="p-3 rounded-xl bg-obsidian-950 border border-white/10 space-y-1">
            <span className="text-[10px] text-platinum-500 uppercase block">Master Public Key (MPK)</span>
            <div className="text-cyan-300 text-[11px] break-all font-mono">
              {fssInfo?.mpk || '0'.repeat(64)}
            </div>
            <span className="text-[10px] text-platinum-400 block">Fixed root of trust across all epochs</span>
          </div>
        </div>

        {fssMessage && (
          <div className={`p-3 rounded-xl border text-[11px] ${
            fssMessage.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : fssMessage.type === 'warning'
              ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
              : 'bg-red-500/10 border-red-500/30 text-red-300'
          }`}>
            {fssMessage.text}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3 pt-2">
          <button
            type="button"
            onClick={handleEvolve}
            disabled={fssActionLoading || fssInfo?.isRevoked}
            className="px-4 py-2 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-bold transition flex items-center space-x-2 disabled:opacity-40"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${fssActionLoading ? 'animate-spin' : ''}`} />
            <span>Evolve to Next Epoch (t → t+1)</span>
          </button>

          <button
            type="button"
            onClick={handleEmergencyFreeze}
            disabled={fssActionLoading || fssInfo?.isRevoked}
            className="px-4 py-2 rounded-xl bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/40 text-xs font-bold transition flex items-center space-x-2 disabled:opacity-40"
          >
            <AlertTriangle className="h-3.5 w-3.5" />
            <span>Emergency Signing Freeze</span>
          </button>
        </div>
      </div>

      <form onSubmit={handleSave} className="space-y-6 font-mono text-xs">
        {/* 3D Graphics & Performance */}
        <div className="p-6 rounded-2xl glass-panel space-y-4">
          <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
            <Cpu className="h-4 w-4 text-white" />
            <span>3D Constellation Rendering Engine</span>
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {[
              { id: 'high', label: 'High Fidelity', desc: 'Full antialiasing, light pulses, metallic materials' },
              { id: 'balanced', label: 'Balanced', desc: 'Standard shadows and smooth orbiting' },
              { id: '2d', label: '2D Schematic', desc: 'Minimal battery drain / reduced motion' },
            ].map((mode) => (
              <button
                type="button"
                key={mode.id}
                onClick={() => setGraphicsMode(mode.id)}
                className={`p-4 rounded-xl border text-left transition ${
                  graphicsMode === mode.id
                    ? 'bg-white/15 border-white text-white shadow-glow-platinum'
                    : 'bg-graphite-900/60 border-white/5 hover:border-white/20 text-platinum-400'
                }`}
              >
                <div className="text-xs font-bold font-mono text-white mb-1">{mode.label}</div>
                <div className="text-[10px] text-platinum-400">{mode.desc}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Cryptographic Key Parameters */}
        <div className="p-6 rounded-2xl glass-panel space-y-4">
          <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
            <Lock className="h-4 w-4 text-white" />
            <span>Cryptographic Standards & Enclave ID</span>
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] text-platinum-400 mb-1">Enclave Node Identifier</label>
              <input
                type="text"
                value={enclaveId}
                onChange={(e) => setEnclaveId(e.target.value)}
                className="w-full p-2.5 rounded-xl bg-graphite-900 border border-white/10 text-white text-xs font-mono"
              />
            </div>

            <div>
              <label className="block text-[11px] text-platinum-400 mb-1">Authoritative Signing Scheme</label>
              <input
                type="text"
                disabled
                value="HHH-MKT-FSS-v1 (Ed25519-MKT-FSS)"
                className="w-full p-2.5 rounded-xl bg-obsidian-950 border border-white/5 text-platinum-400 text-xs font-mono"
              />
            </div>
          </div>
        </div>

        {/* Quai Blockchain Consensus RPC */}
        <div className="p-6 rounded-2xl glass-panel space-y-4">
          <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
            <Globe className="h-4 w-4 text-status-anchored" />
            <span>Quai Network Testnet Consensus RPC</span>
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] text-platinum-400 mb-1">Quai RPC Endpoint (Cyprus-1)</label>
              <input
                type="text"
                value={rpcEndpoint}
                onChange={(e) => setRpcEndpoint(e.target.value)}
                className="w-full p-2.5 rounded-xl bg-graphite-900 border border-white/10 text-white text-xs font-mono"
              />
            </div>
            <div>
              <label className="block text-[11px] text-platinum-400 mb-1">Network & Chain ID</label>
              <input
                type="text"
                disabled
                value="Orchard Testnet (Zone: cyprus1, Chain ID: 15000)"
                className="w-full p-2.5 rounded-xl bg-obsidian-950 border border-white/5 text-platinum-400 text-xs font-mono"
              />
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            type="submit"
            className="px-6 py-2.5 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs shadow-glow-platinum transition"
          >
            Save Enclave Parameters
          </button>

          {saved && (
            <span className="text-white text-xs font-mono flex items-center space-x-1 animate-fadeIn">
              <Check className="h-4 w-4 text-white" />
              <span>Parameters Synchronized</span>
            </span>
          )}
        </div>
      </form>
    </div>
  );
}
