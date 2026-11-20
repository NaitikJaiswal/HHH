import React, { useState } from 'react';
import { 
  Database, Globe, CheckCircle2, ExternalLink, Copy, Check, 
  ArrowUpRight, Shield, Layers, Box, Cpu 
} from 'lucide-react';

export default function BlockchainLedger({ nodes }) {
  const [selectedTx, setSelectedTx] = useState(null);
  const [copiedTx, setCopiedTx] = useState(null);

  const blockchainNodes = nodes.filter(n => n.category === 'BLOCKCHAIN');

  const transactions = [
    {
      id: 'TX-01',
      evidenceRef: 'EVD-9801 (memdump_srv01.raw)',
      txHash: '0x91f893e110cb84a9194e8234abcf90128475cdafe89104bce9013857102948ca',
      blockNumber: 7219402,
      timestamp: '2026-11-20T15:10:00Z',
      network: 'Ethereum Sepolia Testnet (EVM)',
      contract: '0x4f8287e07664B34eF2a3733A0B1c5f0f35492dE8',
      merkleRoot: '7e2c99b244670f5e714652434688d8b375b4aa23f81e33054e1abf192b0051e8',
      status: 'CONFIRMED',
      gasUsed: '42,108 Gwei',
      isActual: true,
    },
    {
      id: 'TX-02',
      evidenceRef: 'EVD-9802 (auth_audit.log)',
      txHash: '0x12b8901823094810293840192834019283401928340192834019283401928340',
      blockNumber: 44190,
      timestamp: '2026-11-20T14:45:00Z',
      network: 'Hyperledger Besu Consortium (Proof of Authority)',
      contract: '0x9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b',
      merkleRoot: '4b889fa1019348eabf091824908123049bcafe90184910283490182490182390',
      status: 'CONFIRMED',
      gasUsed: '21,000 Gas',
      isActual: false, // Simulated Consortium Ledger
    },
    {
      id: 'TX-03',
      evidenceRef: 'EVD-9803 (exfil_traffic.pcap)',
      txHash: '0x67a8910293840192834019283401928340192834019283401928340192834019',
      blockNumber: 7219398,
      timestamp: '2026-11-20T14:15:00Z',
      network: 'Ethereum Sepolia Testnet (EVM)',
      contract: '0x4f8287e07664B34eF2a3733A0B1c5f0f35492dE8',
      merkleRoot: 'd891b0c981273491823749182374918237491823749182374918237491823749',
      status: 'CONFIRMED',
      gasUsed: '38,920 Gwei',
      isActual: true,
    },
  ];

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedTx(id);
    setTimeout(() => setCopiedTx(null), 2000);
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold font-mono text-white flex items-center space-x-2">
          <Database className="h-5 w-5 text-status-anchored" />
          <span>Blockchain Ledger & On-Chain Proof Explorer</span>
        </h1>
        <p className="text-xs text-platinum-400 mt-0.5">
          Immutable cryptographic evidence anchoring with public verification on distributed ledgers.
        </p>
      </div>

      {/* Network Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
        <div className="p-4 rounded-xl glass-panel space-y-2">
          <div className="flex items-center justify-between text-platinum-400">
            <span className="text-[10px] uppercase">Primary Anchor Network</span>
            <Globe className="h-4 w-4 text-status-anchored" />
          </div>
          <div className="text-sm font-bold text-white">Ethereum Sepolia EVM</div>
          <div className="text-[10px] text-status-anchored flex items-center space-x-1">
            <span className="h-1.5 w-1.5 rounded-full bg-status-anchored shadow-glow-chrome" />
            <span>Block #7219402 [Synced]</span>
          </div>
        </div>

        <div className="p-4 rounded-xl glass-panel space-y-2">
          <div className="flex items-center justify-between text-platinum-400">
            <span className="text-[10px] uppercase">Consortium Ledger</span>
            <Layers className="h-4 w-4 text-white" />
          </div>
          <div className="text-sm font-bold text-white">Hyperledger Besu (PoA)</div>
          <div className="text-[10px] text-platinum-400">5 Validating Forensics Nodes</div>
        </div>

        <div className="p-4 rounded-xl glass-panel space-y-2">
          <div className="flex items-center justify-between text-platinum-400">
            <span className="text-[10px] uppercase">Smart Contract Registry</span>
            <Box className="h-4 w-4 text-platinum-300" />
          </div>
          <div className="text-sm font-bold text-white">ForensicRegistry.sol</div>
          <div className="text-[10px] text-platinum-400 truncate">0x4f8287e07664B34e...</div>
        </div>
      </div>

      {/* Transactions Table */}
      <div className="glass-panel rounded-2xl overflow-hidden font-mono text-xs">
        <div className="p-4 border-b border-white/5 flex items-center justify-between">
          <h2 className="text-xs font-bold text-white uppercase tracking-wider">
            Anchored Evidence Transactions
          </h2>
          <span className="text-[10px] text-platinum-500">
            Records labelled with [DEMO] are simulated consortium tests
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-graphite-900/80 border-b border-white/5 text-[10px] text-platinum-500 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Block #</th>
                <th className="py-3 px-4">Target Evidence</th>
                <th className="py-3 px-4">Transaction Hash</th>
                <th className="py-3 px-4">Ledger Network</th>
                <th className="py-3 px-4">Anchored Merkle Root</th>
                <th className="py-3 px-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-platinum-300">
              {transactions.map((tx) => (
                <tr
                  key={tx.id}
                  onClick={() => setSelectedTx(tx)}
                  className="hover:bg-white/5 transition cursor-pointer"
                >
                  <td className="py-3 px-4 font-bold text-status-anchored whitespace-nowrap">
                    #{tx.blockNumber}
                  </td>

                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className="text-white font-semibold">{tx.evidenceRef}</span>
                  </td>

                  <td className="py-3 px-4 font-mono text-[10px]">
                    <div className="flex items-center space-x-1.5">
                      <span className="truncate max-w-[130px]">{tx.txHash.slice(0, 16)}...</span>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleCopy(tx.txHash, tx.id);
                        }}
                        className="text-platinum-500 hover:text-white transition"
                        title="Copy Tx Hash"
                      >
                        {copiedTx === tx.id ? <Check className="h-3 w-3 text-white" /> : <Copy className="h-3 w-3" />}
                      </button>
                    </div>
                  </td>

                  <td className="py-3 px-4 whitespace-nowrap text-platinum-400">
                    <div>{tx.network}</div>
                    {!tx.isActual && (
                      <span className="text-[9px] text-amber-400/90 font-mono">[SIMULATED DEMO LEDGER]</span>
                    )}
                  </td>

                  <td className="py-3 px-4 font-mono text-[10px] text-platinum-400 truncate max-w-[120px]">
                    {tx.merkleRoot.slice(0, 14)}...
                  </td>

                  <td className="py-3 px-4 text-right whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-sky-500/15 text-sky-300 border border-sky-500/30">
                      CONFIRMED
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Transaction Detail Drawer */}
      {selectedTx && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="w-full max-w-xl glass-dropdown rounded-2xl p-6 border border-white/10 space-y-5 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white uppercase">Blockchain Anchor Docket</h3>
                <p className="text-[10px] text-platinum-400">Block #{selectedTx.blockNumber}</p>
              </div>
              <button
                onClick={() => setSelectedTx(null)}
                className="text-platinum-500 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3">
              <div className="p-3 rounded-xl bg-obsidian-950 border border-white/10 space-y-1">
                <span className="text-[10px] text-platinum-500 uppercase block">Transaction Hash</span>
                <div className="text-white break-all text-[11px] font-bold">{selectedTx.txHash}</div>
              </div>

              <div className="p-3 rounded-xl bg-obsidian-950 border border-white/10 space-y-1">
                <span className="text-[10px] text-platinum-500 uppercase block">Anchored Merkle Root</span>
                <div className="text-status-anchored break-all text-[11px] font-bold">{selectedTx.merkleRoot}</div>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-graphite-900 border border-white/5">
                  <span className="text-platinum-500 text-[10px] uppercase block">Smart Contract</span>
                  <span className="text-white font-semibold truncate block">{selectedTx.contract}</span>
                </div>
                <div className="p-3 rounded-xl bg-graphite-900 border border-white/5">
                  <span className="text-platinum-500 text-[10px] uppercase block">Gas Consumed</span>
                  <span className="text-white font-semibold">{selectedTx.gasUsed}</span>
                </div>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedTx(null)}
                className="px-4 py-2 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs"
              >
                Close Docket
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
