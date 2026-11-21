import React, { useState, useEffect } from 'react';
import { 
  FileSpreadsheet, Download, ShieldCheck, CheckCircle2, 
  FileText, Award, Printer, Check, RefreshCw, AlertCircle
} from 'lucide-react';
import { forensicsApi } from '../services/api';

export default function Reports({ nodes }) {
  const [downloading, setDownloading] = useState(null);
  const [downloadingMd, setDownloadingMd] = useState(null);
  const [realReports, setRealReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState(null);

  useEffect(() => {
    loadReports();
  }, []);

  const loadReports = async () => {
    try {
      setLoading(true);
      const data = await forensicsApi.getReports();
      setRealReports(data || []);
    } catch (err) {
      console.warn('Using offline reports baseline:', err);
    } finally {
      setLoading(false);
    }
  };

  const reportTemplates = [
    {
      id: 'REP-01',
      title: 'Cryptographic Evidence Integrity Attestation',
      type: 'Forensic Proof Package',
      description: 'Formal mathematical verification certificate documenting SHA-256 digests, Merkle inclusion proofs, and FSS signatures for all active evidence.',
      recordsCount: nodes.filter(n => n.category === 'EVIDENCE').length || 15,
    },
    {
      id: 'REP-02',
      title: 'Chain-of-Custody Chronological Manifest',
      type: 'Audit Docket',
      description: 'Verifiable chronological ledger of all operator access, file transfers, and cryptographic sealing events under legal hold.',
      recordsCount: 8,
    },
    {
      id: 'REP-03',
      title: 'Quai Network Blockchain Anchoring Attestation',
      type: 'On-Chain Ledger Report',
      description: 'Smart contract transaction hashes, block numbers, gas receipts, and Merkle root state snapshots anchored on Quai Network Orchard Cyprus-1 Testnet (Chain ID 15000).',
      recordsCount: 5,
    },
    {
      id: 'REP-04',
      title: 'Forensic Investigation Executive Summary',
      type: 'Case Docket (Multi-Source Incident)',
      description: 'Consolidated findings, IOC indicators, MITRE ATT&CK classifications, FSS epoch evolution logs, and lead analyst signatures.',
      recordsCount: 12,
    },
  ];

  const handleDownload = async (rep, format = 'json') => {
    if (format === 'json') setDownloading(rep.id);
    else setDownloadingMd(rep.id);

    try {
      const res = await forensicsApi.generateReport({
        title: rep.title,
        format,
      });

      if (format === 'markdown') {
        const mdContent = typeof res === 'string' ? res : res.markdown;
        const blob = new Blob([mdContent], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${rep.id}_${Date.now()}.md`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      } else {
        const jsonContent = res.report || res;
        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(jsonContent, null, 2));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute('href', dataStr);
        downloadAnchor.setAttribute('download', `${rep.id}_${Date.now()}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
      }

      setStatusMessage({ type: 'success', text: `Exported ${rep.title} (${format.toUpperCase()})` });
      setTimeout(() => setStatusMessage(null), 3000);
    } catch (err) {
      console.warn('Falling back to local report export:', err);
      // Fallback local report
      const content = {
        title: rep.title,
        documentId: `DOC-${Date.now()}`,
        generatedAt: new Date().toISOString(),
        enclave: 'SEC-ALPHA (HHH Forensic Enclave)',
        cryptographicStandard: 'NIST FIPS 180-4 (SHA-256) + Ed25519-MKT-FSS',
        blockchainLedger: 'Quai Network Orchard Cyprus-1 Testnet (Chain ID 15000)',
        anchorContract: 'SecureLogAnchor',
        summary: rep.description,
        evidenceRecords: nodes.filter(n => n.category === 'EVIDENCE').map(e => ({
          id: e.id,
          name: e.name,
          hash: e.hash,
          status: e.status,
          source: e.source,
        })),
      };

      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(content, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', `${rep.id}_${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } finally {
      setDownloading(null);
      setDownloadingMd(null);
    }
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center space-x-2">
            <FileSpreadsheet className="h-5 w-5 text-white" />
            <span>Forensic Reports & Proof Attestations</span>
          </h1>
          <p className="text-xs text-platinum-400 mt-0.5">
            Generate tamper-evident, court-ready cryptographic proof packages and chain-of-custody dockets.
          </p>
        </div>

        <button
          onClick={loadReports}
          disabled={loading}
          className="px-3 py-1.5 rounded-xl glass-panel hover:bg-white/10 text-xs font-mono text-platinum-300 transition flex items-center space-x-2"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Reports</span>
        </button>
      </div>

      {statusMessage && (
        <div className="p-3 rounded-xl bg-white/10 border border-white/20 text-xs font-mono text-white flex items-center space-x-2">
          <CheckCircle2 className="h-4 w-4 text-white" />
          <span>{statusMessage.text}</span>
        </div>
      )}

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

            <div className="pt-3 border-t border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <span className="text-[10px] text-platinum-500">
                Covers {rep.recordsCount} Sealed Artifacts
              </span>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handleDownload(rep, 'markdown')}
                  disabled={downloadingMd === rep.id}
                  className="px-3 py-1.5 rounded-xl glass-panel hover:bg-white/10 text-platinum-200 font-bold text-[11px] transition flex items-center space-x-1.5 disabled:opacity-50"
                  title="Export GitHub-Flavored Markdown Dossier"
                >
                  <FileText className="h-3 w-3" />
                  <span>{downloadingMd === rep.id ? '...' : 'Markdown'}</span>
                </button>

                <button
                  onClick={() => handleDownload(rep, 'json')}
                  disabled={downloading === rep.id}
                  className="px-3.5 py-1.5 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs shadow-glow-platinum transition flex items-center space-x-1.5 disabled:opacity-50"
                >
                  <Download className="h-3.5 w-3.5" />
                  <span>{downloading === rep.id ? 'Generating...' : 'JSON Package'}</span>
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
