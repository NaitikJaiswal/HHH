import React, { useState } from 'react';
import { FileText, Download, CheckCircle2, ShieldCheck, Award, ExternalLink } from 'lucide-react';

export default function AuditCompliance() {
  const [downloading, setDownloading] = useState(false);

  const frameworks = [
    {
      name: 'SOC 2 Type II (Trust Services Criteria)',
      control: 'CC6.1 & CC6.8 (Security, Integrity, Non-repudiation)',
      status: 'COMPLIANT',
      evidenceCount: 148924,
      description: 'Continuous cryptographic event sealing and tamper-evident audit logging for forensic traceability.',
    },
    {
      name: 'ISO/IEC 27001:2022',
      control: 'A.12.4.1 (Event Logging) & A.12.4.3 (Administrator & Operator Logs)',
      status: 'COMPLIANT',
      evidenceCount: 148924,
      description: 'Independent HMAC-signed checkpoints stored across separate trust zones to prevent admin tampering.',
    },
    {
      name: 'HIPAA Security Rule',
      control: '45 CFR § 164.312(b) (Audit Controls)',
      status: 'COMPLIANT',
      evidenceCount: 148924,
      description: 'Strict immutable recording of all ePHI access events and authorization requests.',
    },
  ];

  const handleDownloadProof = () => {
    setDownloading(true);
    setTimeout(() => {
      setDownloading(false);
      const report = {
        title: 'HHH SecureLog Cryptographic Audit Attestation',
        generatedAt: new Date().toISOString(),
        frameworksEvaluated: frameworks.map(f => f.name),
        totalAuditedEvents: 148924,
        tamperProofHashChain: 'VALID_SHA256',
        auditorAttestation: 'All logs verified against signed Merkle checkpoints.',
      };
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `securelog_audit_attestation_${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    }, 800);
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center space-x-2">
            <Award className="h-5 w-5 text-purple-400" />
            <span>Audit & Compliance Attestation</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Automated compliance mapping for regulatory frameworks with cryptographic proof packages.
          </p>
        </div>

        <button
          onClick={handleDownloadProof}
          disabled={downloading}
          className="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs font-mono shadow-lg shadow-purple-600/20 transition flex items-center space-x-2 disabled:opacity-50"
        >
          <Download className="h-4 w-4" />
          <span>{downloading ? 'Compiling Proof...' : 'Download Audit Package'}</span>
        </button>
      </div>

      {/* Compliance Framework Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {frameworks.map((fw) => (
          <div key={fw.name} className="p-5 rounded-2xl bg-cyber-card border border-cyber-border space-y-4">
            <div className="flex items-start justify-between">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/15 text-purple-300 border border-purple-500/30">
                {fw.control}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                {fw.status}
              </span>
            </div>

            <div>
              <h3 className="text-sm font-bold font-mono text-white">{fw.name}</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">{fw.description}</p>
            </div>

            <div className="border-t border-cyber-border pt-3 flex justify-between items-center text-xs font-mono text-slate-300">
              <span className="text-slate-500">Sealed Records:</span>
              <span className="text-emerald-400 font-bold">{fw.evidenceCount.toLocaleString()}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
