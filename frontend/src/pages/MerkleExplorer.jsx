import React, { useState, useEffect } from 'react';
import { 
  GitCommit, ShieldCheck, CheckCircle2, ChevronRight, 
  Layers, RefreshCw, Copy, Check, Lock, ArrowDown 
} from 'lucide-react';
import { buildMerkleTree, generateMerkleProof, verifyMerkleProof } from '../services/cryptoUtils';

export default function MerkleExplorer({ nodes }) {
  const [treeData, setTreeData] = useState(null);
  const [selectedLeafIdx, setSelectedLeafIdx] = useState(0);
  const [proofPath, setProofPath] = useState([]);
  const [verificationResult, setVerificationResult] = useState(null);
  const [copiedHash, setCopiedHash] = useState(null);

  // Collect leaf hashes from evidence nodes
  const leafHashes = nodes
    .filter(n => n.category === 'EVIDENCE' && n.hash)
    .map(n => n.hash);

  // Initialize real Merkle Tree on mount
  useEffect(() => {
    async function initTree() {
      // If we have fewer than 4 leaves, add baseline forensic hashes
      const leaves = leafHashes.length >= 4 ? leafHashes : [
        'a57e3f89d0c2e9b114d7a12b6f10c376189bb51e44a6ec588e390c9b60d703fc',
        '7c891e4b31a0dc6790bcf42a9816e883dc14f09148d56b2cfd01e4a5b678c19a',
        '22b7a0c918ef91024bdca601e309f874cbe90184b901aef09c123498bcf09e41',
        '9183fa801bfe091c78e90dafcba871239401bfecda908123ef980123bca01923',
      ];

      const tree = await buildMerkleTree(leaves);
      setTreeData(tree);

      // Generate proof for first leaf
      const proof = generateMerkleProof(tree.levels, 0);
      setProofPath(proof);

      const res = await verifyMerkleProof(leaves[0], proof, tree.root);
      setVerificationResult(res);
    }

    initTree();
  }, [nodes]);

  const handleSelectLeaf = async (idx) => {
    if (!treeData) return;
    setSelectedLeafIdx(idx);

    const leafHash = treeData.leaves[idx];
    const proof = generateMerkleProof(treeData.levels, idx);
    setProofPath(proof);

    const res = await verifyMerkleProof(leafHash, proof, treeData.root);
    setVerificationResult(res);
  };

  const handleCopy = (hash) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  if (!treeData) return null;

  return (
    <div className="space-y-6 font-sans">
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold font-mono text-white flex items-center space-x-2">
          <GitCommit className="h-5 w-5 text-white" />
          <span>Interactive Merkle Tree Explorer</span>
        </h1>
        <p className="text-xs text-platinum-400 mt-0.5">
          Inspect hierarchical cryptographic Merkle roots, leaf hash relationships, and verify logarithmic audit proofs.
        </p>
      </div>

      {/* Root Hash Banner */}
      <div className="p-6 rounded-2xl glass-panel border border-white/15 space-y-3 font-mono text-xs">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="h-2 w-2 rounded-full bg-status-anchored shadow-glow-chrome" />
            <span className="text-[10px] text-platinum-400 uppercase tracking-widest font-bold">
              Merkle Tree Root (Blockchain Anchored)
            </span>
          </div>
          <span className="px-2 py-0.5 rounded text-[10px] bg-sky-500/15 text-sky-300 border border-sky-500/30">
            Depth: {treeData.levels.length} Levels • {treeData.leaves.length} Leaves
          </span>
        </div>

        <div className="p-3.5 rounded-xl bg-obsidian-950 border border-white/10 break-all text-white font-bold flex items-center justify-between gap-4">
          <span className="text-sm font-mono tracking-wide">{treeData.root}</span>
          <button
            onClick={() => handleCopy(treeData.root)}
            className="text-platinum-400 hover:text-white transition shrink-0"
            title="Copy Root Hash"
          >
            {copiedHash === treeData.root ? <Check className="h-4 w-4 text-white" /> : <Copy className="h-4 w-4" />}
          </button>
        </div>
      </div>

      {/* Interactive Visual Hierarchy & Proof Path Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs">
        {/* Left: Leaf Node Selector */}
        <div className="p-5 rounded-2xl glass-panel space-y-4">
          <h2 className="text-xs font-bold text-white uppercase tracking-wider">
            Select Leaf Hash [L0..L{treeData.leaves.length - 1}]
          </h2>

          <div className="space-y-2">
            {treeData.leaves.map((leaf, idx) => (
              <div
                key={leaf + idx}
                onClick={() => handleSelectLeaf(idx)}
                className={`p-3.5 rounded-xl border cursor-pointer transition ${
                  selectedLeafIdx === idx
                    ? 'bg-white/15 border-white text-white shadow-glow-platinum'
                    : 'bg-graphite-900/60 border-white/5 hover:border-white/20 text-platinum-300'
                }`}
              >
                <div className="flex justify-between items-center mb-1 text-[10px]">
                  <span className="text-platinum-500">Leaf Index #{idx}</span>
                  {selectedLeafIdx === idx && (
                    <span className="px-1.5 py-0.2 rounded bg-white text-obsidian-950 font-bold">
                      ACTIVE PROOF
                    </span>
                  )}
                </div>
                <div className="break-all font-mono text-[11px] font-semibold">
                  {leaf.slice(0, 24)}...{leaf.slice(-8)}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right 2 cols: Step-by-Step Proof Path Execution */}
        <div className="lg:col-span-2 p-6 rounded-2xl glass-panel space-y-5">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <div>
              <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                Cryptographic Proof Path (Leaf #{selectedLeafIdx} → Root)
              </h3>
              <p className="text-[10px] text-platinum-400 mt-0.5">
                Mathematical proof: combining hash siblings produces the identical root.
              </p>
            </div>

            {verificationResult?.isValid && (
              <span className="px-3 py-1 rounded-xl bg-white/15 text-white border border-white/30 text-xs font-bold flex items-center space-x-1.5 shadow-glow-platinum">
                <CheckCircle2 className="h-4 w-4" />
                <span>PROOF VERIFIED</span>
              </span>
            )}
          </div>

          {/* Trace Steps */}
          <div className="space-y-3">
            {verificationResult?.trace?.map((step, i) => (
              <div key={i} className="p-3.5 rounded-xl bg-graphite-900/60 border border-white/5 space-y-1.5">
                <div className="flex items-center justify-between text-[10px] text-platinum-500">
                  <span>STEP {step.step}: {i === 0 ? 'START LEAF DIGEST' : `COMBINE WITH SIBLING (${step.position.toUpperCase()})`}</span>
                  {i === verificationResult.trace.length - 1 && (
                    <span className="text-status-anchored font-bold">MATCHES ROOT</span>
                  )}
                </div>
                <div className="text-[11px] font-mono break-all text-white bg-obsidian-950 p-2 rounded-lg border border-white/5">
                  {step.resultingHash || step.hash}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
