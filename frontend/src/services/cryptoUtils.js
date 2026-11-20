/**
 * Cryptographic Forensics Engine for HHH (Hash. Hunt. Harden.)
 * Pure Web Crypto API implementation - zero external crypto dependencies needed.
 */

// Compute real SHA-256 hash of a File, Blob, ArrayBuffer, or UTF-8 String
export async function computeSHA256(input) {
  let buffer;
  if (typeof input === 'string') {
    buffer = new TextEncoder().encode(input);
  } else if (input instanceof File || input instanceof Blob) {
    buffer = await input.arrayBuffer();
  } else if (input instanceof ArrayBuffer) {
    buffer = input;
  } else {
    buffer = new TextEncoder().encode(JSON.stringify(input));
  }

  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Compute SHA-256 of two concatenated hex hashes (standard Merkle node concatenation)
export async function hashPair(leftHex, rightHex) {
  const combined = leftHex + (rightHex || leftHex);
  return await computeSHA256(combined);
}

// Build a verified Merkle Tree from an array of leaf hashes
export async function buildMerkleTree(leafHashes) {
  if (!leafHashes || leafHashes.length === 0) {
    const emptyRoot = await computeSHA256('EMPTY_TREE');
    return { root: emptyRoot, levels: [[emptyRoot]], leaves: [] };
  }

  const leaves = [...leafHashes];
  let currentLevel = [...leaves];
  const levels = [currentLevel];

  while (currentLevel.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left; // Duplicate odd leaf
      const parent = await hashPair(left, right);
      nextLevel.push(parent);
    }
    levels.push(nextLevel);
    currentLevel = nextLevel;
  }

  return {
    root: levels[levels.length - 1][0],
    levels,
    leaves,
  };
}

// Generate cryptographic Merkle Proof Path for a specific leaf index
export function generateMerkleProof(levels, leafIndex) {
  const proof = [];
  let index = leafIndex;

  for (let levelIdx = 0; levelIdx < levels.length - 1; levelIdx++) {
    const level = levels[levelIdx];
    const isRightNode = index % 2 === 1;
    const siblingIndex = isRightNode ? index - 1 : index + 1;

    if (siblingIndex < level.length) {
      proof.push({
        position: isRightNode ? 'left' : 'right',
        hash: level[siblingIndex],
      });
    } else {
      // Odd node duplicated itself
      proof.push({
        position: 'right',
        hash: level[index],
      });
    }

    index = Math.floor(index / 2);
  }

  return proof;
}

// Step-by-step cryptographic verification of a leaf against a Merkle Root using its proof path
export async function verifyMerkleProof(leafHash, proof, expectedRoot) {
  let currentHash = leafHash;
  const trace = [{ step: 0, hash: currentHash, matched: true }];

  for (let i = 0; i < proof.length; i++) {
    const item = proof[i];
    if (item.position === 'left') {
      currentHash = await hashPair(item.hash, currentHash);
    } else {
      currentHash = await hashPair(currentHash, item.hash);
    }
    trace.push({
      step: i + 1,
      combinedWith: item.hash,
      position: item.position,
      resultingHash: currentHash,
    });
  }

  const isValid = currentHash.toLowerCase() === expectedRoot.toLowerCase();
  return { isValid, finalHash: currentHash, trace };
}

// Compare two hashes character by character for UI diffing
export function diffHashes(recordedHash, computedHash) {
  const rec = (recordedHash || '').toLowerCase();
  const comp = (computedHash || '').toLowerCase();
  const maxLength = Math.max(rec.length, comp.length);
  const diff = [];

  for (let i = 0; i < maxLength; i++) {
    const charRec = rec[i] || '';
    const charComp = comp[i] || '';
    diff.push({
      index: i,
      recorded: charRec,
      computed: charComp,
      match: charRec === charComp,
    });
  }

  const matches = rec.length === 64 && comp.length === 64 && rec === comp;
  return { matches, diff, recLength: rec.length, compLength: comp.length };
}
