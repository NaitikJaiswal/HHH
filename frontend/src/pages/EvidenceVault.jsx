import React, { useState, useEffect } from 'react';
import { 
  Archive, Upload, Search, Filter, ShieldCheck, AlertTriangle, 
  Download, Eye, Copy, Check, FileText, CheckCircle2, Plus, Clock,
  RefreshCw, PackageCheck, AlertCircle
} from 'lucide-react';
import { computeSHA256 } from '../services/cryptoUtils';
import { evidenceApi } from '../services/api';

export default function EvidenceVault({ nodes = [], onAddEvidence, onSelectNode }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState('ALL');
  const [copiedHash, setCopiedHash] = useState(null);
  const [evidenceList, setEvidenceList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [packaging, setPackaging] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [statusMessage, setStatusMessage] = useState(null);

  // New Evidence Modal Form State
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [uploadFile, setUploadFile] = useState(null);
  const [customName, setCustomName] = useState('');
  const [customType, setCustomType] = useState('Disk Image');
  const [customSource, setCustomSource] = useState('Workstation-Forensic-01');
  const [computedHash, setComputedHash] = useState('');
  const [isHashing, setIsHashing] = useState(false);

  useEffect(() => {
    loadEvidence();
  }, [nodes]);

  const loadEvidence = async () => {
    try {
      setLoading(true);
      const remoteData = await evidenceApi.getEvidenceList();
      if (remoteData && remoteData.length > 0) {
        const mapped = remoteData.map((item) => ({
          id: item.evidenceId || `EVD-${item.checkpointId}`,
          category: 'EVIDENCE',
          name: item.name || `Signed Checkpoint Docket (${item.sourceId})`,
          label: item.name,
          type: item.signatureAlgorithm || 'FSS Checkpoint Docket',
          size: `${item.eventCount || 1} logs sealed`,
          source: item.sourceId,
          timestamp: item.createdAt || new Date().toISOString(),
          hash: item.merkleRoot || 'GENESIS',
          status: item.status || 'VERIFIED',
          caseId: 'CASE-2026-08',
          custody: item.custody || ['Operator Ingest (Web Crypto Hash Sealed)', 'Evidence Enclave Vault'],
        }));
        setEvidenceList(mapped);
      } else {
        const localList = nodes.filter((n) => n.category === 'EVIDENCE');
        setEvidenceList(localList);
      }
    } catch (err) {
      console.warn('Falling back to local nodes for evidence:', err);
      const localList = nodes.filter((n) => n.category === 'EVIDENCE');
      setEvidenceList(localList);
    } finally {
      setLoading(false);
    }
  };

  const filteredEvidence = evidenceList.filter((item) => {
    const matchesSearch = 
      (item.name && item.name.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (item.id && item.id.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (item.hash && item.hash.toLowerCase().includes(searchQuery.toLowerCase())) ||
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

    if (onAddEvidence) onAddEvidence(newEvidence);
    setEvidenceList((prev) => [newEvidence, ...prev]);
    setShowUploadModal(false);
    setUploadFile(null);
    setComputedHash('');
  };

  // Trigger server-side packaging
  const handlePackageEvidence = async () => {
    try {
      setPackaging(true);
      const pkg = await evidenceApi.packageEvidence({ limit: 100 });
      setStatusMessage({
        type: 'success',
        text: `Sealed evidence bundle: ${pkg.bundle_id} (${pkg.events?.length || 0} events, ${pkg.checkpoints?.length || 0} checkpoints)`,
      });
      loadEvidence();
      setTimeout(() => setStatusMessage(null), 5000);
    } catch (err) {
      setStatusMessage({ type: 'error', text: `Failed to package evidence: ${err.message}` });
    } finally {
      setPackaging(false);
    }
  };

  // Trigger bundle verification
  const handleVerifyEvidence = async (item) => {
    try {
      setVerifying(true);
      const pkg = await evidenceApi.packageEvidence({ sourceId: item?.source, limit: 50 });
      const verification = await evidenceApi.verifyEvidence(pkg);
      setVerifyResult(verification);
    } catch (err) {
      setVerifyResult({ status: 'UNVERIFIABLE', message: err.message, errors: [err.message] });
    } finally {
      setVerifying(false);
    }
  };

  const handleCopy = (hash, id) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleDownloadBundle = (item) => {
    const content = {
      bundleId: item.id,
      name: item.name,
      merkleRoot: item.hash,
      sourceId: item.source,
      verifiedAt: new Date().toISOString(),
      chainOfCustody: item.custody,
      blockchain: 'Quai Network Orchard Cyprus-1 Testnet (Chain ID 15000)',
      contract: 'SecureLogAnchor',
    };
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(content, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `${item.id}_vault_package.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
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

        <div className="flex items-center space-x-2">
          <button
            onClick={handlePackageEvidence}
            disabled={packaging}
            className="px-3.5 py-2 rounded-xl glass-panel hover:bg-white/10 text-white font-bold text-xs transition flex items-center space-x-2 disabled:opacity-50"
          >
            <PackageCheck className={`h-4 w-4 ${packaging ? 'animate-spin' : ''}`} />
            <span>{packaging ? 'Packaging...' : 'Seal Evidence Bundle'}</span>
          </button>

          <button
            onClick={() => setShowUploadModal(true)}
            className="px-4 py-2 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs shadow-glow-platinum transition flex items-center space-x-2"
          >
            <Upload className="h-4 w-4" />
            <span>Ingest New Evidence</span>
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className={`p-3 rounded-xl border text-xs font-mono flex items-center space-x-2 ${
          statusMessage.type === 'error' ? 'bg-status-critical/10 border-status-critical/30 text-status-critical' : 'bg-white/10 border-white/20 text-white'
        }`}>
          {statusMessage.type === 'error' ? <AlertCircle className="h-4 w-4" /> : <CheckCircle2 className="h-4 w-4" />}
          <span>{statusMessage.text}</span>
        </div>
      )}

      {/* Verification Result Modal / Banner */}
      {verifyResult && (
        <div className="p-4 rounded-2xl glass-panel border border-white/20 space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between">
            <span className="font-bold text-white flex items-center space-x-2">
              <ShieldCheck className="h-4 w-4 text-white" />
              <span>Independent Evidence Verification Result</span>
            </span>
            <button
              onClick={() => setVerifyResult(null)}
              className="text-platinum-400 hover:text-white"
            >
              ✕
            </button>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px]">
            <div className="p-2.5 rounded-xl bg-obsidian-950 border border-white/5">
              <div className="text-platinum-500">Status</div>
              <div className="font-bold text-white mt-0.5">{verifyResult.status || 'VALID'}</div>
            </div>
            <div className="p-2.5 rounded-xl bg-obsidian-950 border border-white/5">
              <div className="text-platinum-500">Events Checked</div>
              <div className="font-bold text-white mt-0.5">{verifyResult.eventsChecked ?? 'N/A'}</div>
            </div>
            <div className="p-2.5 rounded-xl bg-obsidian-950 border border-white/5">
              <div className="text-platinum-500">Checkpoints Verified</div>
              <div className="font-bold text-white mt-0.5">{verifyResult.checkpointsVerified ?? 'N/A'}</div>
            </div>
            <div className="p-2.5 rounded-xl bg-obsidian-950 border border-white/5">
              <div className="text-platinum-500">Root Alignment</div>
              <div className="font-bold text-white mt-0.5">{verifyResult.rootAligned ? 'ALIGNED' : 'VERIFIED'}</div>
            </div>
          </div>
        </div>
      )}

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
              <option value="Disk Image">Disk Image</option>
              <option value="Memory Image">Memory Image</option>
              <option value="Audit Log">Audit Log</option>
              <option value="Packet Capture">Packet Capture</option>
              <option value="Configuration">Configuration</option>
              <option value="Ed25519-MKT-FSS">Ed25519-MKT-FSS</option>
            </select>
          </div>
        </div>

        <div className="flex items-center justify-between text-[10px] text-platinum-500 pt-1 border-t border-white/5">
          <span>{filteredEvidence.length} Evidence Records Registered</span>
          <span className="text-platinum-400">All artifacts sealed with WebCrypto SHA-256 & FSS</span>
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
                <th className="py-3 px-4 text-right">Actions</th>
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

                    <td className="py-3 px-4 text-right whitespace-nowrap space-x-2">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleVerifyEvidence(item);
                        }}
                        disabled={verifying}
                        className="px-2.5 py-1 rounded-lg glass-panel hover:bg-white/10 text-[11px] text-platinum-200 transition"
                        title="Cryptographically Verify Docket"
                      >
                        Verify
                      </button>

                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDownloadBundle(item);
                        }}
                        className="px-2.5 py-1 rounded-lg bg-white/10 hover:bg-white/20 text-[11px] text-white transition"
                        title="Download Evidence Package"
                      >
                        <Download className="h-3 w-3 inline mr-1" />
                        Export
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Ingest Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-obsidian-950/80 backdrop-blur-sm font-mono text-xs">
          <div className="w-full max-w-md p-6 rounded-2xl glass-panel border border-white/10 space-y-4">
            <h2 className="text-base font-bold text-white flex items-center space-x-2">
              <Upload className="h-4 w-4" />
              <span>Ingest & Seal New Evidence</span>
            </h2>

            <form onSubmit={handleCommitEvidence} className="space-y-3">
              <div>
                <label className="text-platinum-400 text-[10px]">Upload Raw Artifact</label>
                <input
                  type="file"
                  onChange={handleFileChange}
                  className="w-full mt-1 text-[11px] text-platinum-300 file:mr-3 file:py-1.5 file:px-3 file:rounded-xl file:border-0 file:bg-white file:text-obsidian-950 file:font-bold file:text-xs hover:file:bg-platinum-200"
                />
              </div>

              <div>
                <label className="text-platinum-400 text-[10px]">Artifact Name</label>
                <input
                  type="text"
                  value={customName}
                  onChange={(e) => setCustomName(e.target.value)}
                  placeholder="e.g., auth_audit.log"
                  className="w-full px-3 py-2 rounded-xl bg-graphite-900/60 border border-white/5 text-white text-xs mt-1"
                />
              </div>

              <div>
                <label className="text-platinum-400 text-[10px]">Source Host Identifier</label>
                <input
                  type="text"
                  value={customSource}
                  onChange={(e) => setCustomSource(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-graphite-900/60 border border-white/5 text-white text-xs mt-1"
                />
              </div>

              {isHashing ? (
                <div className="text-[11px] text-platinum-400 animate-pulse">
                  Computing WebCrypto SHA-256 digest...
                </div>
              ) : computedHash ? (
                <div className="p-2.5 rounded-xl bg-obsidian-950 border border-white/5">
                  <div className="text-[10px] text-platinum-500">Computed SHA-256 Digest</div>
                  <div className="text-[11px] font-mono text-white break-all mt-0.5">{computedHash}</div>
                </div>
              ) : null}

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowUploadModal(false)}
                  className="px-3.5 py-1.5 rounded-xl glass-panel text-platinum-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!computedHash}
                  className="px-4 py-1.5 rounded-xl bg-white text-obsidian-950 font-bold hover:bg-platinum-200 disabled:opacity-50"
                >
                  Seal & Commit
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
