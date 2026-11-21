import React, { useState } from 'react';
import { 
  Hash, Upload, ShieldCheck, AlertTriangle, CheckCircle2, 
  RefreshCw, Copy, Check, FileText, ArrowRight 
} from 'lucide-react';
import { computeSHA256, diffHashes } from '../services/cryptoUtils';

export default function HashVerification({ nodes }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [computedHash, setComputedHash] = useState('');
  const [recordedHash, setRecordedHash] = useState('');
  const [hashing, setHashing] = useState(false);
  const [verificationHistory, setVerificationHistory] = useState([
    {
      id: 1,
      target: 'memdump_srv01.raw',
      computed: 'a57e3f89d0c2e9b114d7a12b6f10c376189bb51e44a6ec588e390c9b60d703fc',
      recorded: 'a57e3f89d0c2e9b114d7a12b6f10c376189bb51e44a6ec588e390c9b60d703fc',
      match: true,
      timestamp: '2026-11-20T14:12:05Z',
    },
    {
      id: 2,
      target: 'security_headers.conf',
      computed: 'e45b91a700192837461524354657687980a9b8c7d6e5f4019283746574635241',
      recorded: '9183fa801bfe091c78e90dafcba871239401bfecda908123ef980123bca01923',
      match: false,
      timestamp: '2026-11-20T15:45:02Z',
    },
  ]);

  // Handle Local File Hashing
  const handleFileSelect = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setSelectedFile(file);
    setHashing(true);

    try {
      const hash = await computeSHA256(file);
      setComputedHash(hash);
    } catch (err) {
      console.error(err);
    } finally {
      setHashing(false);
    }
  };

  // Perform Verification Comparison
  const handleVerify = () => {
    if (!computedHash || !recordedHash) return;

    const isMatch = computedHash.trim().toLowerCase() === recordedHash.trim().toLowerCase();
    const newEntry = {
      id: Date.now(),
      target: selectedFile ? selectedFile.name : 'Manual String / Hash',
      computed: computedHash.trim().toLowerCase(),
      recorded: recordedHash.trim().toLowerCase(),
      match: isMatch,
      timestamp: new Date().toISOString(),
    };

    setVerificationHistory([newEntry, ...verificationHistory]);
  };

  const diffResult = diffHashes(recordedHash, computedHash);

  return (
    <div className="space-y-6 font-sans">
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold font-mono text-white flex items-center space-x-2">
          <Hash className="h-5 w-5 text-white" />
          <span>Cryptographic Hash Verification Studio</span>
        </h1>
        <p className="text-xs text-platinum-400 mt-0.5">
          Dedicated cryptographic workspace for real-time SHA-256 fingerprint generation and character-level tampering verification.
        </p>
      </div>

      {/* Main Verification Comparison Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Input & Compute */}
        <div className="p-6 rounded-2xl glass-panel space-y-4 font-mono text-xs">
          <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
            <span>[Step 1] Ingest & Generate SHA-256</span>
          </h2>

          <div>
            <label className="block text-[11px] text-platinum-400 mb-1.5">
              Select any local file to compute live SHA-256 digest:
            </label>
            <input
              type="file"
              onChange={handleFileSelect}
              className="w-full text-xs text-platinum-300 file:mr-3 file:py-2.5 file:px-3.5 file:rounded-xl file:border-0 file:text-xs file:font-mono file:bg-white/10 file:text-white hover:file:bg-white/20 cursor-pointer"
            />
          </div>

          <div>
            <label className="block text-[11px] text-platinum-400 mb-1.5">
              Or paste text/payload to hash:
            </label>
            <textarea
              rows={3}
              placeholder="Type or paste raw payload to hash directly..."
              onChange={async (e) => {
                if (e.target.value) {
                  const h = await computeSHA256(e.target.value);
                  setComputedHash(h);
                }
              }}
              className="w-full p-3 rounded-xl bg-graphite-900 border border-white/10 text-white placeholder-platinum-600 focus:outline-none focus:border-white/30 text-xs font-mono"
            />
          </div>

          <div className="space-y-1">
            <span className="text-[10px] text-platinum-500 uppercase block">Calculated SHA-256 Digest:</span>
            <div className="p-3 rounded-xl bg-obsidian-950 border border-white/10 break-all text-white font-bold min-h-[46px] flex items-center">
              {hashing ? (
                <span className="text-platinum-400 flex items-center space-x-2">
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  <span>Computing 256-bit hash in browser...</span>
                </span>
              ) : computedHash ? (
                computedHash
              ) : (
                <span className="text-platinum-600 font-normal">Awaiting payload or file...</span>
              )}
            </div>
          </div>
        </div>

        {/* Right: Compare Against Recorded Hash */}
        <div className="p-6 rounded-2xl glass-panel space-y-4 font-mono text-xs">
          <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
            <span>[Step 2] Compare Against Recorded Baseline</span>
          </h2>

          <div>
            <label className="block text-[11px] text-platinum-400 mb-1.5">
              Recorded Blockchain / Enclave Hash to Verify Against:
            </label>
            <input
              type="text"
              value={recordedHash}
              onChange={(e) => setRecordedHash(e.target.value)}
              placeholder="Paste 64-character SHA-256 hex string..."
              className="w-full p-2.5 rounded-xl bg-graphite-900 border border-white/10 text-white placeholder-platinum-600 focus:outline-none focus:border-white/30 text-xs font-mono"
            />
          </div>

          <button
            onClick={handleVerify}
            disabled={!computedHash || !recordedHash}
            className="w-full py-2.5 rounded-xl bg-white hover:bg-platinum-200 text-obsidian-950 font-bold text-xs shadow-glow-platinum transition disabled:opacity-50"
          >
            Execute Cryptographic Comparison
          </button>

          {/* Visual Diff Highlighting */}
          {recordedHash && computedHash && (
            <div className={`p-4 rounded-xl border space-y-2 animate-fadeIn ${
              diffResult.matches
                ? 'bg-white/5 border-white/30 text-white'
                : 'bg-status-critical/10 border-status-critical/40 text-status-critical'
            }`}>
              <div className="flex items-center space-x-2 text-xs font-bold">
                {diffResult.matches ? (
                  <>
                    <CheckCircle2 className="h-4 w-4 text-white" />
                    <span>CRYPTOGRAPHIC MATCH: INTEGRITY INTACT</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="h-4 w-4 text-status-critical" />
                    <span>INTEGRITY FAILURE: DIGEST MISMATCH</span>
                  </>
                )}
              </div>
              <p className="text-[11px] text-platinum-300">
                {diffResult.matches
                  ? 'All 64 hexadecimal characters correspond exactly to the baseline hash.'
                  : 'Computed hash differs from recorded reference. Evidence has been modified or corrupted.'}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Verification History Table */}
      <div className="p-6 rounded-2xl glass-panel space-y-4 font-mono text-xs">
        <h2 className="text-xs font-bold text-white uppercase tracking-wider">
          Verification History Log
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-graphite-900/80 border-b border-white/5 text-[10px] text-platinum-500 uppercase tracking-wider">
              <tr>
                <th className="py-2.5 px-3">Target / File</th>
                <th className="py-2.5 px-3">Computed Hash</th>
                <th className="py-2.5 px-3">Recorded Baseline</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3 text-right">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-platinum-300">
              {verificationHistory.map((item) => (
                <tr key={item.id} className="hover:bg-white/5">
                  <td className="py-2.5 px-3 font-semibold text-white">{item.target}</td>
                  <td className="py-2.5 px-3 font-mono text-[10px] text-platinum-400">
                    {item.computed.slice(0, 16)}...
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[10px] text-platinum-400">
                    {item.recorded.slice(0, 16)}...
                  </td>
                  <td className="py-2.5 px-3 text-[10px] text-platinum-500">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      item.match 
                        ? 'bg-white/10 text-white border border-white/20' 
                        : 'bg-status-critical/15 text-status-critical border border-status-critical/30'
                    }`}>
                      {item.match ? 'MATCH (VALID)' : 'TAMPERED (FAIL)'}
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
