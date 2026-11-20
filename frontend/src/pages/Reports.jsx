import React, { useState } from 'react';
import { 
  FileSpreadsheet, Download, ShieldCheck, CheckCircle2, 
  FileText, Award, Printer, Check 
} from 'lucide-react';

export default function Reports({ nodes }) {
  const [downloading, setDownloading] = useState(null);

  const reportTemplates = [
    {
      id: 'REP-01',
      title: 'Cryptographic Evidence Integrity Attestation',
      type: 'Forensic Proof Package',
      description: 'Formal mathematical verification certificate documenting SHA-256 digests and Merkle proofs for all active evidence.',
      recordsCount: nodes.filter(n => n.category === 'EVIDENCE').length,
    },
    {
      id: 'REP-02',
      title: 'Chain-of-Custody Chronological Manifest',
      type: 'Audit Docket',
      description: 'Verifiable chronological ledger of all operator access, file transfers, and cryptographic sealing events.',
      recordsCount: 5,
    },
    {
      id: 'REP-03',
      title: 'Blockchain Anchoring & Public Proof Attestation',
      type: 'On-Chain Ledger Report',
      description: 'Smart contract transaction hashes, block numbers, gas receipts, and Merkle root state snapshots on Ethereum Sepolia.',
      recordsCount: 3,
    },
    {
      id: 'REP-04',
      title: 'Forensic Investigation Executive Summary',
      type: 'Case Docket (DarkVessel & CobaltBreeze)',
      description: 'Consolidated findings, IOC indicators, MITRE ATT&CK technique classifications, and lead analyst signatures.',
      recordsCount: 2,
    },
  ];

  const handleDownload = (rep) => {
    setDownloading(rep.id);

    setTimeout(() => {
      setDownloading(null);
      const content = {
        title: rep.title,
        documentId: `DOC-${Date.now()}`,
        generatedAt: new Date().toISOString(),
        enclave: 'SEC-ALPHA (HHH Forensic Enclave)',
        cryptographicStandard: 'NIST FIPS 180-4 (SHA-256) + Ed25519',
        blockchainLedger: 'Ethereum Sepolia EVM Block #7219402',
        summary: rep.description,
        evidenceRecords: nodes.filter(n => n.category === 'EVIDENCE').map(e => ({
          id: e.id,
          name: e.name,
          hash: e.hash,
          status: e.status,
          source: e.source,
        })),
      };

      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(content, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `${rep.id}_${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    }, 700);
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold font-mono text-white flex items-center space-x-2">
          <FileSpreadsheet className="h-5 w-5 text-white" />
          <span>Forensic Reports & Proof Attestations</span>
        </h1>
        <p className="text-xs text-platinum-400 mt-0.5">
          Generate tamper-evident, court-ready cryptographic proof packages and chain-of-custody dockets.
        </p>
      </div>

      {/* Reports Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
        {reportTemplates.map((rep) => (
          <div
            key={rep.id}
            className="p-6 rounded-2xl glass-panel border border-white/5 hover:border-white/20 transition space-y-4 flex flex-col justify-between"
          >
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-platinum-500">{rep.id}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-white/10 text-white border border-white/10">
                  {rep.type}
                </span>
              </div>
              <h2 className="text-sm font-bold text-white">{rep.title}</h2>
              <p className="text-platinum-400 text-xs leading-relaxed">
                {rep.description}
              </p>
            </div>

            <div className="pt-3 border-t border-white/5 flex items-center justify-between">
              <span className="text-[10px] text-platinum-500">
                Covers {rep.recordsCount} Sealed Artifacts
              </span>

              <button
                onClick={() => handleDownload(rep)}
                disabled={downloading === rep.id}
                className="px-3.5 py-1.5 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs shadow-glow-platinum transition flex items-center space-x-1.5 disabled:opacity-50"
              >
                <Download className="h-3.5 w-3.5" />
                <span>{downloading === rep.id ? 'Generating...' : 'Export JSON Package'}</span>
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
