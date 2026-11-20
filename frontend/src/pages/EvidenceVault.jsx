import React, { useState } from 'react';
import { 
  Archive, Upload, Search, Filter, ShieldCheck, AlertTriangle, 
  Download, Eye, Copy, Check, FileText, CheckCircle2, Plus, Clock 
} from 'lucide-react';
import { computeSHA256 } from '../services/cryptoUtils';

export default function EvidenceVault({ nodes, onAddEvidence, onSelectNode }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState('ALL');
  const [isUploading, setIsUploading] = useState(false);
  const [copiedHash, setCopiedHash] = useState(null);

  // New Evidence Modal Form State
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [uploadFile, setUploadFile] = useState(null);
  const [customName, setCustomName] = useState('');
  const [customType, setCustomType] = useState('Disk Image');
  const [customSource, setCustomSource] = useState('Workstation-Forensic-01');
  const [computedHash, setComputedHash] = useState('');
  const [isHashing, setIsHashing] = useState(false);

  // Filter evidence records
  const evidenceList = nodes.filter(n => n.category === 'EVIDENCE');

  const filteredEvidence = evidenceList.filter((item) => {
    const matchesSearch = 
      item.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.hash.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.source && item.source.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesType = filterType === 'ALL' || item.type === filterType;
    return matchesSearch && matchesType;
  });

  // Handle Real File Selection & Compute In-Browser SHA-256
  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setUploadFile(file);
    setCustomName(file.name);
    setIsHashing(true);

    try {
      const hash = await computeSHA256(file);
      setComputedHash(hash);
    } catch (err) {
      console.error('Hashing error:', err);
    } finally {
      setIsHashing(false);
    }
  };

  // Submit New Evidence to the Enclave
  const handleCommitEvidence = (e) => {
    e.preventDefault();
    if (!computedHash) return;

    const newEvidence = {
      id: `EVD-${Math.floor(1000 + Math.random() * 9000)}`,
      category: 'EVIDENCE',
      name: customName || (uploadFile ? uploadFile.name : 'artifact.raw'),
      label: customName,
      type: customType,
      size: uploadFile ? `${(uploadFile.size / (1024 * 1024)).toFixed(2)} MB` : '1.5 MB',
      source: customSource,
      timestamp: new Date().toISOString(),
      hash: computedHash,
      status: 'VERIFIED',
      caseId: 'CASE-2026-08',
      custody: ['Operator Ingest (Web Crypto Hash Sealed)', 'Evidence Enclave Vault'],
      x: (Math.random() - 0.5) * 60,
      y: (Math.random() - 0.5) * 40,
      z: (Math.random() - 0.5) * 40,
    };

    onAddEvidence(newEvidence);
    setShowUploadModal(false);
    setUploadFile(null);
    setComputedHash('');
  };

  const handleCopy = (hash, id) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center space-x-2">
            <Archive className="h-5 w-5 text-platinum-300" />
            <span>Evidence Vault & Chain-of-Custody</span>
          </h1>
          <p className="text-xs text-platinum-400 mt-0.5">
            Cryptographically sealed forensic repository with continuous SHA-256 fingerprinting and audit custody.
          </p>
        </div>

        <button
          onClick={() => setShowUploadModal(true)}
          className="px-4 py-2 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs shadow-glow-platinum transition flex items-center space-x-2"
        >
          <Upload className="h-4 w-4" />
          <span>Ingest New Evidence</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-2xl glass-panel space-y-3 font-mono text-xs">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="md:col-span-2 relative">
            <Search className="absolute left-3.5 top-2.5 h-3.5 w-3.5 text-platinum-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search evidence records by ID, file name, host, or SHA-256..."
              className="w-full pl-9 pr-3 py-2 rounded-xl bg-graphite-900/60 border border-white/5 text-platinum-200 placeholder-platinum-600 focus:outline-none focus:border-white/30 text-xs"
            />
          </div>

          <div>
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="w-full px-3 py-2 rounded-xl bg-graphite-900/60 border border-white/5 text-platinum-300 focus:outline-none focus:border-white/30 text-xs"
            >
              <option value="ALL">All Artifact Types</option>
              <option value="Memory Image">Memory Image</option>
              <option value="Audit Log">Audit Log</option>
              <option value="Packet Capture">Packet Capture</option>
              <option value="Configuration">Configuration</option>
              <option value="Disk Image">Disk Image</option>
            </select>
          </div>
        </div>

        <div className="flex items-center justify-between text-[10px] text-platinum-500 pt-1 border-t border-white/5">
          <span>{filteredEvidence.length} Evidence Records Registered</span>
          <span className="text-platinum-400">All artifacts sealed with WebCrypto SHA-256</span>
        </div>
      </div>

      {/* Evidence Table */}
      <div className="glass-panel rounded-2xl overflow-hidden font-mono text-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-graphite-900/80 border-b border-white/5 text-[10px] text-platinum-500 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Evidence ID</th>
                <th className="py-3 px-4">Artifact Name</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Source Host</th>
                <th className="py-3 px-4">SHA-256 Fingerprint</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-platinum-300">
              {filteredEvidence.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-platinum-500">
                    No evidence records match your criteria.
                  </td>
                </tr>
              ) : (
                filteredEvidence.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => onSelectNode(item)}
                    className="hover:bg-white/5 transition cursor-pointer"
                  >
                    <td className="py-3 px-4 font-bold text-white whitespace-nowrap">
                      {item.id}
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="text-white font-semibold">{item.name}</div>
                      <div className="text-[10px] text-platinum-500">{item.size}</div>
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-white/5 text-platinum-300 border border-white/5">
                        {item.type}
                      </span>
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap text-platinum-400">
                      {item.source}
                    </td>

                    <td className="py-3 px-4 font-mono text-[10px]">
                      <div className="flex items-center space-x-1.5">
                        <span className="truncate max-w-[130px]">{item.hash.slice(0, 18)}...</span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleCopy(item.hash, item.id);
                          }}
                          className="text-platinum-500 hover:text-white transition"
                          title="Copy Full SHA-256"
                        >
                          {copiedHash === item.id ? <Check className="h-3 w-3 text-white" /> : <Copy className="h-3 w-3" />}
                        </button>
                      </div>
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        item.status === 'VERIFIED' ? 'bg-white/10 text-white border border-white/20 shadow-glow-platinum' :
                        item.status === 'FAILED' ? 'bg-status-critical/15 text-status-critical border border-status-critical/30' :
                        'bg-status-warning/15 text-status-warning border border-status-warning/30'
                      }`}>
                        {item.status}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectNode(item);
                        }}
                        className="px-2.5 py-1 rounded-lg glass-panel-subtle hover:bg-white/10 text-[11px] text-white transition"
                      >
                        Details →
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Ingest Evidence Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="w-full max-w-lg glass-dropdown rounded-2xl p-6 border border-white/10 space-y-5 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div>
                <h2 className="text-base font-bold text-white uppercase">Secure Evidence Ingest</h2>
                <p className="text-[10px] text-platinum-400">Compute live browser SHA-256 and seal into Enclave</p>
              </div>
              <button
                onClick={() => setShowUploadModal(false)}
                className="text-platinum-500 hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCommitEvidence} className="space-y-4">
              {/* File Selector */}
              <div>
                <label className="block text-[11px] text-platinum-400 mb-1">Select File to Hash & Ingest</label>
                <input
                  type="file"
                  required
                  onChange={handleFileChange}
                  className="w-full text-xs text-platinum-300 file:mr-3 file:py-2 file:px-3 file:rounded-xl file:border-0 file:text-xs file:font-mono file:bg-white/10 file:text-white hover:file:bg-white/20 cursor-pointer"
                />
              </div>

              {/* In-Browser Computed Hash Display */}
              {isHashing ? (
                <div className="p-3 rounded-xl bg-graphite-900 text-platinum-400 flex items-center space-x-2">
                  <span className="animate-spin text-white">⚙</span>
                  <span>Computing SHA-256 digest with Web Crypto API...</span>
                </div>
              ) : computedHash ? (
                <div className="p-3 rounded-xl bg-obsidian-950 border border-white/10 space-y-1">
                  <span className="text-[10px] text-platinum-500 uppercase block">Computed SHA-256 Digest</span>
                  <div className="text-white break-all text-[11px] font-bold">{computedHash}</div>
                </div>
              ) : null}

              {/* Metadata Fields */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] text-platinum-400 mb-1">Artifact Type</label>
                  <select
                    value={customType}
                    onChange={(e) => setCustomType(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-graphite-900 border border-white/10 text-white"
                  >
                    <option value="Disk Image">Disk Image</option>
                    <option value="Memory Image">Memory Image</option>
                    <option value="Packet Capture">Packet Capture</option>
                    <option value="Audit Log">Audit Log</option>
                    <option value="Configuration">Configuration</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[11px] text-platinum-400 mb-1">Source Host</label>
                  <input
                    type="text"
                    value={customSource}
                    onChange={(e) => setCustomSource(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-graphite-900 border border-white/10 text-white"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={!computedHash || isHashing}
                className="w-full py-2.5 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs shadow-glow-platinum transition disabled:opacity-50"
              >
                Seal Evidence into Enclave
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
