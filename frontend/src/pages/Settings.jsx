import React, { useState } from 'react';
import { Sliders, Shield, Database, Cpu, Check, Lock, Globe } from 'lucide-react';

export default function Settings() {
  const [graphicsMode, setGraphicsMode] = useState('high');
  const [rpcEndpoint, setRpcEndpoint] = useState('https://sepolia.infura.io/v3/enclave-node-primary');
  const [enclaveId, setEnclaveId] = useState('SEC-ALPHA-8092');
  const [saved, setSaved] = useState(false);

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
          <span>Enclave Configuration & 3D Parameters</span>
        </h1>
        <p className="text-xs text-platinum-400 mt-0.5">
          Configure cryptographic HSM parameters, consensus RPC connections, and 3D graphics rendering.
        </p>
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
              <label className="block text-[11px] text-platinum-400 mb-1">Hardware Signing Key</label>
              <input
                type="text"
                disabled
                value="HSM-ED25519-FIPS-140-3"
                className="w-full p-2.5 rounded-xl bg-obsidian-950 border border-white/5 text-platinum-400 text-xs font-mono"
              />
            </div>
          </div>
        </div>

        {/* Blockchain Consensus RPC */}
        <div className="p-6 rounded-2xl glass-panel space-y-4">
          <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
            <Globe className="h-4 w-4 text-status-anchored" />
            <span>Blockchain Network RPC</span>
          </h2>

          <div>
            <label className="block text-[11px] text-platinum-400 mb-1">Ethereum Sepolia RPC Endpoint</label>
            <input
              type="text"
              value={rpcEndpoint}
              onChange={(e) => setRpcEndpoint(e.target.value)}
              className="w-full p-2.5 rounded-xl bg-graphite-900 border border-white/10 text-white text-xs font-mono"
            />
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
